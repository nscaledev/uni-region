/*
Copyright 2024-2025 the Unikorn Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package openstack

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/roles"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/utils/openstack/clientconfig"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers/allocation/vlan"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	"github.com/unikorn-cloud/region/pkg/providers/util"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/uuid"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/yaml"
)

var (
	ErrConflict     = errors.New("resource conflict error")
	ErrKeyUndefined = errors.New("a required key was not defined")
)

type providerCredentials struct {
	endpoint  string
	domainID  string
	projectID string
	userID    string
	password  string
}

type Provider struct {
	// client is Kubernetes client.
	client client.Client

	// region is the current region configuration.
	region *unikornv1.Region

	// secret is the current region secret.
	secret *corev1.Secret

	// credentials hold cloud identity information.
	credentials *providerCredentials

	// vlan allocation table.
	// NOTE: this can only be used by a single client unless it's moved
	// into a Kubernetes resource of some variety to gain speculative locking
	// powers.
	vlanAllocator *vlan.Allocator

	// DO NOT USE DIRECTLY, CALL AN ACCESSOR.
	_identity *IdentityClient
	_compute  *ComputeClient
	_image    *ImageClient
	_network  *NetworkClient

	lock sync.Mutex
}

var _ types.Provider = &Provider{}

func New(ctx context.Context, cli client.Client, region *unikornv1.Region) (*Provider, error) {
	var vlanSpec *unikornv1.VLANSpec

	if region.Spec.Openstack != nil && region.Spec.Openstack.Network != nil && region.Spec.Openstack.Network.ProviderNetworks != nil {
		vlanSpec = region.Spec.Openstack.Network.ProviderNetworks.VLAN
	}

	p := &Provider{
		client:        cli,
		region:        region,
		vlanAllocator: vlan.New(cli, region.Namespace, "openstack-region-provider", vlanSpec),
	}

	if err := p.serviceClientRefresh(ctx); err != nil {
		return nil, err
	}

	return p, nil
}

// serviceClientRefresh updates clients if they need to e.g. in the event
// of a configuration update.
// NOTE: you MUST get the lock before calling this function.
//
//nolint:cyclop
func (p *Provider) serviceClientRefresh(ctx context.Context) error {
	refresh := false

	region := &unikornv1.Region{}

	if err := p.client.Get(ctx, client.ObjectKey{Namespace: p.region.Namespace, Name: p.region.Name}, region); err != nil {
		return err
	}

	// If anything changes with the configuration, referesh the clients as they may
	// do caching.
	if !reflect.DeepEqual(region.Spec.Openstack, p.region.Spec.Openstack) {
		refresh = true
	}

	secretkey := client.ObjectKey{
		Namespace: region.Spec.Openstack.ServiceAccountSecret.Namespace,
		Name:      region.Spec.Openstack.ServiceAccountSecret.Name,
	}

	secret := &corev1.Secret{}

	if err := p.client.Get(ctx, secretkey, secret); err != nil {
		return err
	}

	// If the secret hasn't beed read yet, or has changed e.g. credential rotation
	// then refresh the clients as they cache the API token.
	if p.secret == nil || !reflect.DeepEqual(secret.Data, p.secret.Data) {
		refresh = true
	}

	// Nothing to do, use what's there.
	if !refresh {
		return nil
	}

	// Create the core credential provider.
	domainID, ok := secret.Data["domain-id"]
	if !ok {
		return fmt.Errorf("%w: domain-id", ErrKeyUndefined)
	}

	userID, ok := secret.Data["user-id"]
	if !ok {
		return fmt.Errorf("%w: user-id", ErrKeyUndefined)
	}

	password, ok := secret.Data["password"]
	if !ok {
		return fmt.Errorf("%w: password", ErrKeyUndefined)
	}

	projectID, ok := secret.Data["project-id"]
	if !ok {
		return fmt.Errorf("%w: project-id", ErrKeyUndefined)
	}

	credentials := &providerCredentials{
		endpoint:  region.Spec.Openstack.Endpoint,
		domainID:  string(domainID),
		projectID: string(projectID),
		userID:    string(userID),
		password:  string(password),
	}

	// The identity client needs to have "manager" powers, so it create projects and
	// users within a domain without full admin.
	identity, err := NewIdentityClient(ctx, NewDomainScopedPasswordProvider(region.Spec.Openstack.Endpoint, string(userID), string(password), string(domainID)))
	if err != nil {
		return err
	}

	// Everything else gets a default view when bound to a project as a "member".
	// Sadly, domain scoped accesses do not work by default any longer.
	providerClient := NewPasswordProvider(region.Spec.Openstack.Endpoint, string(userID), string(password), string(projectID))

	compute, err := NewComputeClient(ctx, providerClient, region.Spec.Openstack.Compute)
	if err != nil {
		return err
	}

	image, err := NewImageClient(ctx, providerClient, region.Spec.Openstack.Image)
	if err != nil {
		return err
	}

	network, err := NewNetworkClient(ctx, providerClient, region.Spec.Openstack.Network)
	if err != nil {
		return err
	}

	// Save the current configuration for checking next time.
	p.region = region
	p.secret = secret
	p.credentials = credentials

	// Seve the clients
	p._identity = identity
	p._compute = compute
	p._image = image
	p._network = network

	return nil
}

func (p *Provider) identity(ctx context.Context) (*IdentityClient, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if err := p.serviceClientRefresh(ctx); err != nil {
		return nil, err
	}

	return p._identity, nil
}

func (p *Provider) compute(ctx context.Context) (*ComputeClient, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if err := p.serviceClientRefresh(ctx); err != nil {
		return nil, err
	}

	return p._compute, nil
}

func (p *Provider) image(ctx context.Context) (*ImageClient, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if err := p.serviceClientRefresh(ctx); err != nil {
		return nil, err
	}

	return p._image, nil
}

func (p *Provider) network(ctx context.Context) (*NetworkClient, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if err := p.serviceClientRefresh(ctx); err != nil {
		return nil, err
	}

	return p._network, nil
}

// Region returns the provider's region.
func (p *Provider) Region(ctx context.Context) (*unikornv1.Region, error) {
	// Get the newest version of the region.
	p.lock.Lock()
	defer p.lock.Unlock()

	if err := p.serviceClientRefresh(ctx); err != nil {
		return nil, err
	}

	return p.region, nil
}

// Flavors list all available flavors.
func (p *Provider) Flavors(ctx context.Context) (types.FlavorList, error) {
	computeService, err := p.compute(ctx)
	if err != nil {
		return nil, err
	}

	resources, err := computeService.Flavors(ctx)
	if err != nil {
		return nil, err
	}

	result := make(types.FlavorList, len(resources))

	for i := range resources {
		flavor := &resources[i]

		// API memory is in MiB, disk is in GB
		f := types.Flavor{
			ID:     flavor.ID,
			Name:   flavor.Name,
			CPUs:   flavor.VCPUs,
			Memory: resource.NewQuantity(int64(flavor.RAM)<<20, resource.BinarySI),
			Disk:   resource.NewScaledQuantity(int64(flavor.Disk), resource.Giga),
		}

		// Apply any extra metadata to the flavor.
		//
		//nolint:nestif
		if p.region.Spec.Openstack.Compute != nil && p.region.Spec.Openstack.Compute.Flavors != nil {
			i := slices.IndexFunc(p.region.Spec.Openstack.Compute.Flavors.Metadata, func(metadata unikornv1.FlavorMetadata) bool {
				return flavor.ID == metadata.ID
			})

			if i >= 0 {
				metadata := &p.region.Spec.Openstack.Compute.Flavors.Metadata[i]

				f.Baremetal = metadata.Baremetal

				if metadata.CPU != nil {
					f.CPUFamily = metadata.CPU.Family
				}

				if metadata.GPU != nil {
					f.GPU = &types.GPU{
						// TODO: while these align, you should really put a
						// proper conversion in here.
						Vendor:        types.GPUVendor(metadata.GPU.Vendor),
						Model:         metadata.GPU.Model,
						Memory:        metadata.GPU.Memory,
						PhysicalCount: metadata.GPU.PhysicalCount,
						LogicalCount:  metadata.GPU.LogicalCount,
					}
				}
			}
		}

		result[i] = f
	}

	return result, nil
}

// Images lists all available images.
func (p *Provider) Images(ctx context.Context) (types.ImageList, error) {
	imageService, err := p.image(ctx)
	if err != nil {
		return nil, err
	}

	resources, err := imageService.Images(ctx)
	if err != nil {
		return nil, err
	}

	result := make(types.ImageList, len(resources))

	for i := range resources {
		image := &resources[i]

		virtualization, _ := image.Properties["unikorn:virtualization"].(string)

		size := image.MinDiskGigabytes

		if size == 0 {
			// Round up to the nearest GiB.
			size = int((image.VirtualSize + (1 << 30) - 1) >> 30)
		}

		providerImage := types.Image{
			ID:             image.ID,
			Name:           image.Name,
			Created:        image.CreatedAt,
			Modified:       image.UpdatedAt,
			SizeGiB:        size,
			Virtualization: types.ImageVirtualization(virtualization),
			OS:             p.imageOS(image),
			Packages:       p.imagePackages(image),
		}

		if gpuVendor, ok := image.Properties["unikorn:gpu_vendor"].(string); ok {
			gpuDriver, ok := image.Properties["unikorn:gpu_driver_version"].(string)
			if !ok {
				// TODO: it's perhaps better to just skip this one, rather than
				// kill the entire service??
				return nil, fmt.Errorf("%w: GPU driver is not defined for image %s", ErrKeyUndefined, image.ID)
			}

			gpu := &types.ImageGPU{
				Vendor: types.GPUVendor(gpuVendor),
				Driver: gpuDriver,
			}

			if models, ok := image.Properties["unikorn:gpu_models"].(string); ok {
				gpu.Models = strings.Split(models, ",")
			}

			providerImage.GPU = gpu
		}

		result[i] = providerImage
	}

	return result, nil
}

// imageOS extracts the image OS from the image properties.
func (p *Provider) imageOS(image *images.Image) types.ImageOS {
	kernel, _ := image.Properties["unikorn:os:kernel"].(string)
	family, _ := image.Properties["unikorn:os:family"].(string)
	distro, _ := image.Properties["unikorn:os:distro"].(string)
	version, _ := image.Properties["unikorn:os:version"].(string)

	result := types.ImageOS{
		Kernel:  types.OsKernel(kernel),
		Family:  types.OsFamily(family),
		Distro:  types.OsDistro(distro),
		Version: version,
	}

	if variant, exists := image.Properties["unikorn:os:variant"].(string); exists {
		result.Variant = &variant
	}

	if codename, exists := image.Properties["unikorn:os:codename"].(string); exists {
		result.Codename = &codename
	}

	return result
}

// imagePackages extracts the image packages from the image properties.
func (p *Provider) imagePackages(image *images.Image) *types.ImagePackages {
	result := make(types.ImagePackages)

	for key, value := range image.Properties {
		// Check if the key starts with "unikorn:package"
		if strings.HasPrefix(key, "unikorn:package:") {
			packageName := key[len("unikorn:package:"):]

			if strValue, ok := value.(string); ok {
				result[packageName] = strValue
			}
		}
	}

	// https://github.com/unikorn-cloud/specifications/blob/main/specifications/providers/openstack/flavors_and_images.md
	// kubernetes_version was removed in v2.0.0 of the specification, but we still support it for backwards compatibility.
	if _, exists := result["kubernetes"]; !exists {
		if version, ok := image.Properties["unikorn:kubernetes_version"].(string); ok {
			result["kubernetes"] = version
		}
	}

	return &result
}

const (
	// Projects are randomly named to avoid clashes, so we need to add some tags
	// in order to be able to reason about who they really belong to.  It is also
	// useful to have these in place so we can spot orphaned resources and garbage
	// collect them.
	OrganizationTag = "organization"
	ProjectTag      = "project"
)

// projectTags defines how to tag projects.
func projectTags(identity *unikornv1.OpenstackIdentity) []string {
	tags := []string{
		OrganizationTag + "=" + identity.Labels[coreconstants.OrganizationLabel],
		ProjectTag + "=" + identity.Labels[coreconstants.ProjectLabel],
	}

	return tags
}

func identityResourceName(identity *unikornv1.OpenstackIdentity) string {
	return "unikorn-identity-" + identity.Name
}

// provisionUser creates a new user in the managed domain with a random password.
// There is a 1:1 mapping of user to project, and the project name is unique in the
// domain, so just reuse this, we can clean them up at the same time.
func (p *Provider) provisionUser(ctx context.Context, identityService *IdentityClient, identity *unikornv1.OpenstackIdentity) error {
	if identity.Spec.UserID != nil {
		return nil
	}

	name := identityResourceName(identity)
	password := string(uuid.NewUUID())

	user, err := identityService.CreateUser(ctx, p.credentials.domainID, name, password)
	if err != nil {
		return err
	}

	identity.Spec.UserID = &user.ID
	identity.Spec.Password = &password

	return nil
}

// provisionProject creates a project per-cluster.  Cluster API provider Openstack is
// somewhat broken in that networks can alias and cause all kinds of disasters, so it's
// safest to have one cluster in one project so it has its own namespace.
func (p *Provider) provisionProject(ctx context.Context, identityService *IdentityClient, identity *unikornv1.OpenstackIdentity) error {
	if identity.Spec.ProjectID != nil {
		return nil
	}

	name := identityResourceName(identity)

	project, err := identityService.CreateProject(ctx, p.credentials.domainID, name, projectTags(identity))
	if err != nil {
		return err
	}

	identity.Spec.ProjectID = &project.ID

	return nil
}

// roleNameToID maps from something human readable to something Openstack will operate with
// because who doesn't like extra, slow, API calls...
func roleNameToID(roles []roles.Role, name string) (string, error) {
	for _, role := range roles {
		if role.Name == name {
			return role.ID, nil
		}
	}

	return "", fmt.Errorf("%w: role %s", ErrResourceNotFound, name)
}

// getRequiredProjectManagerRoles returns the roles required for a manager to create, manage
// and delete things like provider networks to support baremetal.
func (p *Provider) getRequiredProjectManagerRoles() []string {
	defaultRoles := []string{
		"manager",
	}

	return defaultRoles
}

// getRequiredProjectUserRoles returns the roles required for a user to create, manage and delete
// a cluster.
func (p *Provider) getRequiredProjectUserRoles() []string {
	if p.region.Spec.Openstack.Identity != nil && len(p.region.Spec.Openstack.Identity.ClusterRoles) > 0 {
		return p.region.Spec.Openstack.Identity.ClusterRoles
	}

	defaultRoles := []string{
		"member",
		"load-balancer_member",
	}

	return defaultRoles
}

// provisionProjectRoles creates a binding between our service account and the project
// with the required roles to provision an application credential that will allow cluster
// creation, deletion and life-cycle management.
func (p *Provider) provisionProjectRoles(ctx context.Context, identityService *IdentityClient, identity *unikornv1.OpenstackIdentity, userID string, rolesGetter func() []string) error {
	allRoles, err := identityService.ListRoles(ctx)
	if err != nil {
		return err
	}

	for _, name := range rolesGetter() {
		roleID, err := roleNameToID(allRoles, name)
		if err != nil {
			return err
		}

		if err := identityService.CreateRoleAssignment(ctx, userID, *identity.Spec.ProjectID, roleID); err != nil {
			return err
		}
	}

	return nil
}

func (p *Provider) provisionApplicationCredential(ctx context.Context, identity *unikornv1.OpenstackIdentity) error {
	if identity.Spec.ApplicationCredentialID != nil {
		return nil
	}

	// Rescope to the user/project...
	providerClient := NewPasswordProvider(p.region.Spec.Openstack.Endpoint, *identity.Spec.UserID, *identity.Spec.Password, *identity.Spec.ProjectID)

	identityService, err := NewIdentityClient(ctx, providerClient)
	if err != nil {
		return err
	}

	name := identityResourceName(identity)

	appcred, err := identityService.CreateApplicationCredential(ctx, *identity.Spec.UserID, name, "IaaS lifecycle management", p.getRequiredProjectUserRoles())
	if err != nil {
		return err
	}

	identity.Spec.ApplicationCredentialID = &appcred.ID
	identity.Spec.ApplicationCredentialSecret = &appcred.Secret

	return nil
}

func (p *Provider) provisionQuotas(ctx context.Context, identity *unikornv1.OpenstackIdentity) error {
	providerClient := NewPasswordProvider(p.region.Spec.Openstack.Endpoint, p.credentials.userID, p.credentials.password, *identity.Spec.ProjectID)

	compute, err := NewComputeClient(ctx, providerClient, p.region.Spec.Openstack.Compute)
	if err != nil {
		return err
	}

	blockstorage, err := NewBlockStorageClient(ctx, providerClient)
	if err != nil {
		return err
	}

	if err := compute.UpdateQuotas(ctx, *identity.Spec.ProjectID); err != nil {
		return err
	}

	if err := blockstorage.UpdateQuotas(ctx, *identity.Spec.ProjectID); err != nil {
		return err
	}

	return nil
}

func (p *Provider) createClientConfig(identity *unikornv1.OpenstackIdentity) error {
	if identity.Spec.Cloud != nil {
		return nil
	}

	cloud := "cloud"

	clientConfig := &clientconfig.Clouds{
		Clouds: map[string]clientconfig.Cloud{
			cloud: {
				AuthType: clientconfig.AuthV3ApplicationCredential,
				AuthInfo: &clientconfig.AuthInfo{
					AuthURL:                     p.region.Spec.Openstack.Endpoint,
					ApplicationCredentialID:     *identity.Spec.ApplicationCredentialID,
					ApplicationCredentialSecret: *identity.Spec.ApplicationCredentialSecret,
				},
			},
		},
	}

	clientConfigYAML, err := yaml.Marshal(clientConfig)
	if err != nil {
		return err
	}

	identity.Spec.Cloud = &cloud
	identity.Spec.CloudConfig = clientConfigYAML

	return nil
}

// keyPairName is a fixed name for our per-identity keypair.
const keyPairName = "unikorn-openstack-provider"

func (p *Provider) createIdentityComputeResources(ctx context.Context, identity *unikornv1.OpenstackIdentity) error {
	if identity.Spec.ServerGroupID != nil {
		return nil
	}

	// Rescope to the user/project...
	providerClient := NewPasswordProvider(p.region.Spec.Openstack.Endpoint, *identity.Spec.UserID, *identity.Spec.Password, *identity.Spec.ProjectID)

	computeService, err := NewComputeClient(ctx, providerClient, p.region.Spec.Openstack.Compute)
	if err != nil {
		return err
	}

	name := identityResourceName(identity)

	// Create a server group, that can be used by clients for soft anti-affinity.
	result, err := computeService.CreateServerGroup(ctx, name)
	if err != nil {
		return err
	}

	identity.Spec.ServerGroupID = &result.ID

	// Create an SSH key pair that can be used to gain access to servers.
	// This is primarily a debugging aid, and you need to opt in at the client service
	// to actually inject it into anything.  Besides, you have the uesrname and password
	// available anyway, so you can do a server recovery and steal all the data that way.
	publicKey, privateKey, err := util.GenerateSSHKeyPair()
	if err != nil {
		return err
	}

	if err := computeService.CreateKeypair(ctx, keyPairName, string(publicKey)); err != nil {
		return err
	}

	t := keyPairName
	identity.Spec.SSHKeyName = &t
	identity.Spec.SSHPrivateKey = privateKey

	return nil
}

func (p *Provider) GetOpenstackIdentity(ctx context.Context, identity *unikornv1.Identity) (*unikornv1.OpenstackIdentity, error) {
	var result unikornv1.OpenstackIdentity

	if err := p.client.Get(ctx, client.ObjectKey{Namespace: identity.Namespace, Name: identity.Name}, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (p *Provider) GetOrCreateOpenstackIdentity(ctx context.Context, identity *unikornv1.Identity) (*unikornv1.OpenstackIdentity, bool, error) {
	create := false

	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return nil, false, err
		}

		openstackIdentity = &unikornv1.OpenstackIdentity{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: identity.Namespace,
				Name:      identity.Name,
				Labels: map[string]string{
					constants.IdentityLabel: identity.Name,
				},
				Annotations: identity.Annotations,
			},
		}

		for k, v := range identity.Labels {
			openstackIdentity.Labels[k] = v
		}

		create = true
	}

	return openstackIdentity, create, nil
}

// CreateIdentity creates a new identity for cloud infrastructure.
//
//nolint:cyclop
func (p *Provider) CreateIdentity(ctx context.Context, identity *unikornv1.Identity) error {
	identityService, err := p.identity(ctx)
	if err != nil {
		return err
	}

	openstackIdentity, create, err := p.GetOrCreateOpenstackIdentity(ctx, identity)
	if err != nil {
		return err
	}

	// Always attempt to record where we are up to for idempotency.
	record := func() {
		log := log.FromContext(ctx)

		if create {
			if err := p.client.Create(ctx, openstackIdentity); err != nil {
				log.Error(err, "failed to create openstack identity")
			}

			return
		}

		if err := p.client.Update(ctx, openstackIdentity); err != nil {
			log.Error(err, "failed to update openstack identity")
		}
	}

	defer record()

	// Every cluster has its own project to mitigate "nuances" in CAPO i.e. it's
	// totally broken when it comes to network aliasing.
	if err := p.provisionProject(ctx, identityService, openstackIdentity); err != nil {
		return err
	}

	// Grant the "manager" role on the project for unikorn's user.  Sadly when provisioning
	// resources, most services can only infer the project ID from the token, and not any
	// of the hierarchy, so we cannot define policy rules for a domain manager in the same
	// way as can be done for the identity service.
	if err := p.provisionProjectRoles(ctx, identityService, openstackIdentity, p.credentials.userID, p.getRequiredProjectManagerRoles); err != nil {
		return err
	}

	// Try set quotas...
	if err := p.provisionQuotas(ctx, openstackIdentity); err != nil {
		return err
	}

	// You MUST provision a new user, if we rotate a password, any application credentials
	// hanging off it will stop working, i.e. doing that to the unikorn management user
	// will be pretty catastrophic for all clusters in the region.
	if err := p.provisionUser(ctx, identityService, openstackIdentity); err != nil {
		return err
	}

	// Give the user only what permissions they need to provision a cluster and
	// manage it during its lifetime.
	if err := p.provisionProjectRoles(ctx, identityService, openstackIdentity, *openstackIdentity.Spec.UserID, p.getRequiredProjectUserRoles); err != nil {
		return err
	}

	// Always use application credentials, they are scoped to a single project and
	// cannot be used to break from that jail.
	if err := p.provisionApplicationCredential(ctx, openstackIdentity); err != nil {
		return err
	}

	if err := p.createClientConfig(openstackIdentity); err != nil {
		return err
	}

	// Add in any optional configuration.
	if err := p.createIdentityComputeResources(ctx, openstackIdentity); err != nil {
		return err
	}

	return nil
}

// DeleteIdentity cleans up an identity for cloud infrastructure.
//
//nolint:cyclop
func (p *Provider) DeleteIdentity(ctx context.Context, identity *unikornv1.Identity) error {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return err
		}

		return nil
	}

	complete := false

	// Always attempt to record where we are up to for idempotency.
	record := func() {
		if complete {
			return
		}

		log := log.FromContext(ctx)

		if err := p.client.Update(ctx, openstackIdentity); err != nil {
			log.Error(err, "failed to update openstack identity")
		}
	}

	defer record()

	// User never even created, so nothing else will have been.
	if openstackIdentity.Spec.UserID == nil {
		return nil
	}

	// Rescope to the user/project...
	providerClient := NewPasswordProvider(p.region.Spec.Openstack.Endpoint, *openstackIdentity.Spec.UserID, *openstackIdentity.Spec.Password, *openstackIdentity.Spec.ProjectID)

	computeService, err := NewComputeClient(ctx, providerClient, p.region.Spec.Openstack.Compute)
	if err != nil {
		return err
	}

	if openstackIdentity.Spec.SSHKeyName != nil {
		if err := computeService.DeleteKeypair(ctx, keyPairName); err != nil {
			return err
		}

		openstackIdentity.Spec.SSHKeyName = nil
		openstackIdentity.Spec.SSHPrivateKey = nil
	}

	if openstackIdentity.Spec.ServerGroupID != nil {
		if err := computeService.DeleteServerGroup(ctx, *openstackIdentity.Spec.ServerGroupID); err != nil {
			return err
		}

		openstackIdentity.Spec.ServerGroupID = nil
	}

	identityService, err := p.identity(ctx)
	if err != nil {
		return err
	}

	if openstackIdentity.Spec.UserID != nil {
		if err := identityService.DeleteUser(ctx, *openstackIdentity.Spec.UserID); err != nil {
			return err
		}

		openstackIdentity.Spec.UserID = nil
	}

	if openstackIdentity.Spec.ProjectID != nil {
		if err := identityService.DeleteProject(ctx, *openstackIdentity.Spec.ProjectID); err != nil {
			return err
		}

		openstackIdentity.Spec.ProjectID = nil
	}

	if err := p.client.Delete(ctx, openstackIdentity); err != nil {
		return err
	}

	complete = true

	return nil
}

func (p *Provider) GetOpenstackNetwork(ctx context.Context, network *unikornv1.Network) (*unikornv1.OpenstackNetwork, error) {
	var result unikornv1.OpenstackNetwork

	if err := p.client.Get(ctx, client.ObjectKey{Namespace: network.Namespace, Name: network.Name}, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (p *Provider) GetOrCreateOpenstackNetwork(ctx context.Context, identity *unikornv1.Identity, network *unikornv1.Network) (*unikornv1.OpenstackNetwork, bool, error) {
	create := false

	openstackNetwork, err := p.GetOpenstackNetwork(ctx, network)
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return nil, false, err
		}

		openstackNetwork = &unikornv1.OpenstackNetwork{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: network.Namespace,
				Name:      network.Name,
				Labels: map[string]string{
					constants.IdentityLabel: identity.Name,
					constants.NetworkLabel:  network.Name,
				},
				Annotations: network.Annotations,
			},
		}

		for k, v := range network.Labels {
			openstackNetwork.Labels[k] = v
		}

		create = true
	}

	return openstackNetwork, create, nil
}

func (p *Provider) allocateVLAN(ctx context.Context, network *unikornv1.OpenstackNetwork) error {
	if !p.region.Spec.Openstack.Network.UseProviderNetworks() {
		return nil
	}

	if network.Spec.VlanID != nil {
		return nil
	}

	vlanID, err := p.vlanAllocator.Allocate(ctx, network.Name)
	if err != nil {
		return err
	}

	network.Spec.VlanID = &vlanID

	return nil
}

func (p *Provider) createNetwork(ctx context.Context, networkService *NetworkClient, network *unikornv1.OpenstackNetwork) error {
	if network.Spec.NetworkID != nil {
		return nil
	}

	vlanID := -1

	if network.Spec.VlanID != nil {
		vlanID = *network.Spec.VlanID
	}

	openstackNetwork, err := networkService.CreateNetwork(ctx, "unikorn-openstack-region-network", vlanID)
	if err != nil {
		return err
	}

	network.Spec.NetworkID = &openstackNetwork.ID

	return nil
}

func (p *Provider) createSubnet(ctx context.Context, networkService *NetworkClient, network *unikornv1.Network, openstackNetwork *unikornv1.OpenstackNetwork) error {
	if openstackNetwork.Spec.SubnetID != nil {
		return nil
	}

	dnsNameservers := make([]string, len(network.Spec.DNSNameservers))

	for i, ip := range network.Spec.DNSNameservers {
		dnsNameservers[i] = ip.String()
	}

	subnet, err := networkService.CreateSubnet(ctx, "unikorn-openstack-region-provider-subnet", *openstackNetwork.Spec.NetworkID, network.Spec.Prefix.String(), dnsNameservers)
	if err != nil {
		return err
	}

	openstackNetwork.Spec.SubnetID = &subnet.ID

	return nil
}

func (p *Provider) createRouter(ctx context.Context, networkService *NetworkClient, openstackNetwork *unikornv1.OpenstackNetwork) error {
	if openstackNetwork.Spec.RouterID != nil {
		return nil
	}

	router, err := networkService.CreateRouter(ctx, "unikorn-openstack-region-provider-router")
	if err != nil {
		return err
	}

	openstackNetwork.Spec.RouterID = &router.ID

	return nil
}

func (p *Provider) addRouterSubnetInterface(ctx context.Context, networkService *NetworkClient, openstackNetwork *unikornv1.OpenstackNetwork) error {
	if openstackNetwork.Spec.RouterSubnetInterfaceAdded {
		return nil
	}

	if err := networkService.AddRouterInterface(ctx, *openstackNetwork.Spec.RouterID, *openstackNetwork.Spec.SubnetID); err != nil {
		return err
	}

	openstackNetwork.Spec.RouterSubnetInterfaceAdded = true

	return nil
}

// CreateNetwork creates a physical network for an identity.
//
//nolint:cyclop
func (p *Provider) CreateNetwork(ctx context.Context, identity *unikornv1.Identity, network *unikornv1.Network) error {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return err
	}

	openstackNetwork, create, err := p.GetOrCreateOpenstackNetwork(ctx, identity, network)
	if err != nil {
		return err
	}

	// Always attempt to record where we are up to for idempotency.
	record := func() {
		log := log.FromContext(ctx)

		if create {
			if err := p.client.Create(ctx, openstackNetwork); err != nil {
				log.Error(err, "failed to create openstack physical network")
			}

			return
		}

		if err := p.client.Update(ctx, openstackNetwork); err != nil {
			log.Error(err, "failed to update openstack physical network")
		}
	}

	defer record()

	if err := p.allocateVLAN(ctx, openstackNetwork); err != nil {
		return err
	}

	// Rescope to the project...
	providerClient := NewPasswordProvider(p.region.Spec.Openstack.Endpoint, p.credentials.userID, p.credentials.password, *openstackIdentity.Spec.ProjectID)

	networkService, err := NewNetworkClient(ctx, providerClient, p.region.Spec.Openstack.Network)
	if err != nil {
		return err
	}

	if err := p.createNetwork(ctx, networkService, openstackNetwork); err != nil {
		return err
	}

	if err := p.createSubnet(ctx, networkService, network, openstackNetwork); err != nil {
		return err
	}

	if err := p.createRouter(ctx, networkService, openstackNetwork); err != nil {
		return err
	}

	if err := p.addRouterSubnetInterface(ctx, networkService, openstackNetwork); err != nil {
		return err
	}

	return nil
}

// DeleteNetwork deletes a physical network.
//
//nolint:cyclop
func (p *Provider) DeleteNetwork(ctx context.Context, identity *unikornv1.Identity, network *unikornv1.Network) error {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return err
	}

	openstackNetwork, err := p.GetOpenstackNetwork(ctx, network)
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return err
		}

		return nil
	}

	complete := false

	// Always attempt to record where we are up to for idempotency.
	record := func() {
		if complete {
			return
		}

		log := log.FromContext(ctx)

		if err := p.client.Update(ctx, openstackNetwork); err != nil {
			log.Error(err, "failed to update openstack physical network")
		}
	}

	defer record()

	// Rescope to the project...
	providerClient := NewPasswordProvider(p.region.Spec.Openstack.Endpoint, p.credentials.userID, p.credentials.password, *openstackIdentity.Spec.ProjectID)

	networkService, err := NewNetworkClient(ctx, providerClient, p.region.Spec.Openstack.Network)
	if err != nil {
		return err
	}

	if openstackNetwork.Spec.RouterSubnetInterfaceAdded {
		if err := networkService.RemoveRouterInterface(ctx, *openstackNetwork.Spec.RouterID, *openstackNetwork.Spec.SubnetID); err != nil {
			return err
		}

		openstackNetwork.Spec.RouterSubnetInterfaceAdded = false
	}

	if openstackNetwork.Spec.RouterID != nil {
		if err := networkService.DeleteRouter(ctx, *openstackNetwork.Spec.RouterID); err != nil {
			return err
		}

		openstackNetwork.Spec.RouterID = nil
	}

	if openstackNetwork.Spec.SubnetID != nil {
		if err := networkService.DeleteSubnet(ctx, *openstackNetwork.Spec.SubnetID); err != nil {
			return err
		}

		openstackNetwork.Spec.SubnetID = nil
	}

	if openstackNetwork.Spec.NetworkID != nil {
		if err := networkService.DeleteNetwork(ctx, *openstackNetwork.Spec.NetworkID); err != nil {
			return err
		}

		openstackNetwork.Spec.NetworkID = nil
	}

	if openstackNetwork.Spec.VlanID != nil {
		if err := p.vlanAllocator.Free(ctx, *openstackNetwork.Spec.VlanID); err != nil {
			return err
		}

		openstackNetwork.Spec.VlanID = nil
	}

	if err := p.client.Delete(ctx, openstackNetwork); err != nil {
		return err
	}

	complete = true

	return nil
}

// ListExternalNetworks returns a list of external networks if the platform
// supports such a concept.
func (p *Provider) ListExternalNetworks(ctx context.Context) (types.ExternalNetworks, error) {
	networkService, err := p.network(ctx)
	if err != nil {
		return nil, err
	}

	result, err := networkService.ExternalNetworks(ctx)
	if err != nil {
		return nil, err
	}

	out := make(types.ExternalNetworks, len(result))

	for i, in := range result {
		out[i] = types.ExternalNetwork{
			ID:   in.ID,
			Name: in.Name,
		}
	}

	return out, nil
}

func (p *Provider) GetOpenstackSecurityGroup(ctx context.Context, securityGroup *unikornv1.SecurityGroup) (*unikornv1.OpenstackSecurityGroup, error) {
	var result unikornv1.OpenstackSecurityGroup

	if err := p.client.Get(ctx, client.ObjectKey{Namespace: securityGroup.Namespace, Name: securityGroup.Name}, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (p *Provider) GetOrCreateOpenstackSecurityGroup(ctx context.Context, identity *unikornv1.Identity, securityGroup *unikornv1.SecurityGroup) (*unikornv1.OpenstackSecurityGroup, bool, error) {
	create := false

	openstackSecurityGroup, err := p.GetOpenstackSecurityGroup(ctx, securityGroup)
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return nil, false, err
		}

		openstackSecurityGroup = &unikornv1.OpenstackSecurityGroup{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: securityGroup.Namespace,
				Name:      securityGroup.Name,
				Labels: map[string]string{
					constants.IdentityLabel:      identity.Name,
					constants.SecurityGroupLabel: securityGroup.Name,
				},
				Annotations: securityGroup.Annotations,
			},
		}

		for k, v := range securityGroup.Labels {
			openstackSecurityGroup.Labels[k] = v
		}

		create = true
	}

	return openstackSecurityGroup, create, nil
}

func (p *Provider) createSecurityGroup(ctx context.Context, networkService *NetworkClient, securityGroup *unikornv1.OpenstackSecurityGroup) error {
	if securityGroup.Spec.SecurityGroupID != nil {
		return nil
	}

	providerSecurityGroup, err := networkService.CreateSecurityGroup(ctx, securityGroup.Name)
	if err != nil {
		return err
	}

	securityGroup.Spec.SecurityGroupID = &providerSecurityGroup.ID

	return nil
}

// CreateSecurityGroup creates a new security group.
func (p *Provider) CreateSecurityGroup(ctx context.Context, identity *unikornv1.Identity, securityGroup *unikornv1.SecurityGroup) error {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return err
	}

	openstackSecurityGroup, create, err := p.GetOrCreateOpenstackSecurityGroup(ctx, identity, securityGroup)
	if err != nil {
		return err
	}

	// Always attempt to record where we are up to for idempotency.
	record := func() {
		log := log.FromContext(ctx)

		if create {
			if err := p.client.Create(ctx, openstackSecurityGroup); err != nil {
				log.Error(err, "failed to create openstack security group")
			}

			return
		}

		if err := p.client.Update(ctx, openstackSecurityGroup); err != nil {
			log.Error(err, "failed to update openstack security group")
		}
	}

	defer record()

	// Rescope to the project...
	providerClient := NewPasswordProvider(p.region.Spec.Openstack.Endpoint, p.credentials.userID, p.credentials.password, *openstackIdentity.Spec.ProjectID)

	networkService, err := NewNetworkClient(ctx, providerClient, p.region.Spec.Openstack.Network)
	if err != nil {
		return err
	}

	if err := p.createSecurityGroup(ctx, networkService, openstackSecurityGroup); err != nil {
		return err
	}

	return nil
}

// DeleteSecurityGroup deletes a security group.
func (p *Provider) DeleteSecurityGroup(ctx context.Context, identity *unikornv1.Identity, securityGroup *unikornv1.SecurityGroup) error {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return err
	}

	openstackSecurityGroup, err := p.GetOpenstackSecurityGroup(ctx, securityGroup)
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return err
		}

		return nil
	}

	complete := false

	// Always attempt to record where we are up to for idempotency.
	record := func() {
		if complete {
			return
		}

		log := log.FromContext(ctx)

		if err := p.client.Update(ctx, openstackSecurityGroup); err != nil {
			log.Error(err, "failed to update openstack security group")
		}
	}

	defer record()

	// Rescope to the project...
	providerClient := NewPasswordProvider(p.region.Spec.Openstack.Endpoint, p.credentials.userID, p.credentials.password, *openstackIdentity.Spec.ProjectID)

	networkService, err := NewNetworkClient(ctx, providerClient, p.region.Spec.Openstack.Network)
	if err != nil {
		return err
	}

	if openstackSecurityGroup.Spec.SecurityGroupID != nil {
		if err := networkService.DeleteSecurityGroup(ctx, *openstackSecurityGroup.Spec.SecurityGroupID); err != nil {
			return err
		}

		openstackSecurityGroup.Spec.SecurityGroupID = nil
	}

	if err := p.client.Delete(ctx, openstackSecurityGroup); err != nil {
		return err
	}

	complete = true

	return nil
}

func (p *Provider) GetOpenstackSecurityGroupRule(ctx context.Context, securityGroupRule *unikornv1.SecurityGroupRule) (*unikornv1.OpenstackSecurityGroupRule, error) {
	var result unikornv1.OpenstackSecurityGroupRule

	if err := p.client.Get(ctx, client.ObjectKey{Namespace: securityGroupRule.Namespace, Name: securityGroupRule.Name}, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (p *Provider) GetOrCreateOpenstackSecurityGroupRule(ctx context.Context, identity *unikornv1.Identity, securityGroup *unikornv1.SecurityGroup, rule *unikornv1.SecurityGroupRule) (*unikornv1.OpenstackSecurityGroupRule, bool, error) {
	create := false

	openstackSecurityGroupRule, err := p.GetOpenstackSecurityGroupRule(ctx, rule)
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return nil, false, err
		}

		openstackSecurityGroupRule = &unikornv1.OpenstackSecurityGroupRule{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: rule.Namespace,
				Name:      rule.Name,
				Labels: map[string]string{
					constants.IdentityLabel:      identity.Name,
					constants.SecurityGroupLabel: securityGroup.Name,
				},
				Annotations: rule.Annotations,
			},
		}

		for k, v := range rule.Labels {
			openstackSecurityGroupRule.Labels[k] = v
		}

		create = true
	}

	return openstackSecurityGroupRule, create, nil
}

func (p *Provider) createSecurityGroupRule(ctx context.Context, networkService *NetworkClient, rule *unikornv1.SecurityGroupRule, openstackRule *unikornv1.OpenstackSecurityGroupRule, openstackSecurityGroup *unikornv1.OpenstackSecurityGroup) error {
	if openstackRule.Spec.SecurityGroupRuleID != nil {
		return nil
	}

	// Helper function to map port range
	mapPortRange := func() (int, int, error) {
		if rule.Spec.Port.Number != nil {
			return *rule.Spec.Port.Number, *rule.Spec.Port.Number, nil
		}

		if rule.Spec.Port.Range != nil {
			return rule.Spec.Port.Range.Start, rule.Spec.Port.Range.End, nil
		}

		return 0, 0, fmt.Errorf("%w: at least one of number or range must be defined for security rule %s", ErrKeyUndefined, rule.Name)
	}

	direction := rules.RuleDirection(*rule.Spec.Direction)
	protocol := rules.RuleProtocol(*rule.Spec.Protocol)
	securityGroupID := *openstackSecurityGroup.Spec.SecurityGroupID

	portStart, portEnd, err := mapPortRange()
	if err != nil {
		return err
	}

	providerRule, err := networkService.CreateSecurityGroupRule(ctx, securityGroupID, direction, protocol, portStart, portEnd, rule.Spec.CIDR)
	if err != nil {
		return err
	}

	openstackRule.Spec.SecurityGroupRuleID = &providerRule.ID

	return nil
}

// CreateSecurityGroupRule creates a new security group rule.
func (p *Provider) CreateSecurityGroupRule(ctx context.Context, identity *unikornv1.Identity, securityGroup *unikornv1.SecurityGroup, rule *unikornv1.SecurityGroupRule) error {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return err
	}

	openstackSecurityGroupRule, create, err := p.GetOrCreateOpenstackSecurityGroupRule(ctx, identity, securityGroup, rule)
	if err != nil {
		return err
	}

	// Always attempt to record where we are up to for idempotency.
	record := func() {
		log := log.FromContext(ctx)

		if create {
			if err := p.client.Create(ctx, openstackSecurityGroupRule); err != nil {
				log.Error(err, "failed to create openstack security group rule")
			}

			return
		}

		if err := p.client.Update(ctx, openstackSecurityGroupRule); err != nil {
			log.Error(err, "failed to update openstack security group rule")
		}
	}

	defer record()

	// Rescope to the project...
	providerClient := NewPasswordProvider(p.region.Spec.Openstack.Endpoint, p.credentials.userID, p.credentials.password, *openstackIdentity.Spec.ProjectID)

	networkService, err := NewNetworkClient(ctx, providerClient, p.region.Spec.Openstack.Network)
	if err != nil {
		return err
	}

	openstackSecurityGroup, err := p.GetOpenstackSecurityGroup(ctx, securityGroup)
	if err != nil {
		return err
	}

	if err := p.createSecurityGroupRule(ctx, networkService, rule, openstackSecurityGroupRule, openstackSecurityGroup); err != nil {
		return err
	}

	return nil
}

// DeleteSecurityGroupRule deletes a security group rule.
//
//nolint:cyclop
func (p *Provider) DeleteSecurityGroupRule(ctx context.Context, identity *unikornv1.Identity, securityGroup *unikornv1.SecurityGroup, rule *unikornv1.SecurityGroupRule) error {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return err
	}

	openstackSecurityGroup, err := p.GetOpenstackSecurityGroup(ctx, securityGroup)
	if err != nil {
		return err
	}

	openstackSecurityGroupRule, err := p.GetOpenstackSecurityGroupRule(ctx, rule)
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return err
		}

		return nil
	}

	complete := false

	// Always attempt to record where we are up to for idempotency.
	record := func() {
		if complete {
			return
		}

		log := log.FromContext(ctx)

		if err := p.client.Update(ctx, openstackSecurityGroupRule); err != nil {
			log.Error(err, "failed to update openstack security group rule")
		}
	}

	defer record()

	// Rescope to the project...
	providerClient := NewPasswordProvider(p.region.Spec.Openstack.Endpoint, p.credentials.userID, p.credentials.password, *openstackIdentity.Spec.ProjectID)

	networkService, err := NewNetworkClient(ctx, providerClient, p.region.Spec.Openstack.Network)
	if err != nil {
		return err
	}

	if openstackSecurityGroupRule.Spec.SecurityGroupRuleID != nil {
		if err := networkService.DeleteSecurityGroupRule(ctx, *openstackSecurityGroup.Spec.SecurityGroupID, *openstackSecurityGroupRule.Spec.SecurityGroupRuleID); err != nil {
			return err
		}

		openstackSecurityGroupRule.Spec.SecurityGroupRuleID = nil
	}

	if err := p.client.Delete(ctx, openstackSecurityGroupRule); err != nil {
		return err
	}

	complete = true

	return nil
}

func (p *Provider) GetOpenstackServer(ctx context.Context, server *unikornv1.Server) (*unikornv1.OpenstackServer, error) {
	var result unikornv1.OpenstackServer

	if err := p.client.Get(ctx, client.ObjectKey{Namespace: server.Namespace, Name: server.Name}, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (p *Provider) GetOrCreateOpenstackServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) (*unikornv1.OpenstackServer, bool, error) {
	create := false

	openstackServer, err := p.GetOpenstackServer(ctx, server)
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return nil, false, err
		}

		openstackServer = &unikornv1.OpenstackServer{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: server.Namespace,
				Name:      server.Name,
				Labels: map[string]string{
					constants.IdentityLabel: identity.Name,
					constants.ServerLabel:   server.Name,
				},
				Annotations: server.Annotations,
			},
		}

		for k, v := range server.Labels {
			openstackServer.Labels[k] = v
		}

		create = true
	}

	return openstackServer, create, nil
}

// openstackNetworkID returns the openstack ID of the giving unikorn network.
func (p *Provider) openstackNetworkID(ctx context.Context, identity *unikornv1.OpenstackIdentity, id string) (string, error) {
	options := &client.ListOptions{
		Namespace: identity.Namespace,
		LabelSelector: labels.SelectorFromSet(map[string]string{
			constants.IdentityLabel: identity.Name,
		}),
	}

	resources := &unikornv1.OpenstackNetworkList{}
	if err := p.client.List(ctx, resources, options); err != nil {
		return "", err
	}

	index := slices.IndexFunc(resources.Items, func(net unikornv1.OpenstackNetwork) bool {
		return net.Name == id
	})

	if index < 0 {
		return "", fmt.Errorf("%w: network %s", ErrResourceNotFound, id)
	}

	if resources.Items[index].Spec.NetworkID == nil {
		return "", fmt.Errorf("%w: network %s not provisioned", ErrResouceDependency, id)
	}

	return *resources.Items[index].Spec.NetworkID, nil
}

// convertServerHealthStatus translates from an OpenStack server status into a Kubernetes one.
// See the following for all possible states (currently).
// https://docs.openstack.org/api-guide/compute/server_concepts.html
func convertServerHealthStatus(server *servers.Server) (corev1.ConditionStatus, unikornv1core.ConditionReason, string) {
	if server == nil {
		return corev1.ConditionUnknown, unikornv1core.ConditionReasonUnknown, "unable to determine server status"
	}

	switch server.Status {
	case "ACTIVE":
		return corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "server is healthy"
	case "ERROR":
		return corev1.ConditionFalse, unikornv1core.ConditionReasonErrored, "server is in an error state"
	case "UNKNOWN":
		return corev1.ConditionUnknown, unikornv1core.ConditionReasonUnknown, "unable to determine server status"
	default:
		return corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "server is in state " + server.Status
	}
}

// SetServerHealthStatus attaches the healt status condition to a server.
func setServerHealthStatus(server *unikornv1.Server, openstackserver *servers.Server) {
	status, reason, message := convertServerHealthStatus(openstackserver)

	server.StatusConditionWrite(unikornv1core.ConditionHealthy, status, reason, message)
}

// https://docs.openstack.org/api-guide/compute/server_concepts.html
func setServerPhase(ctx context.Context, server *unikornv1.Server, openstackserver *servers.Server) {
	// Default to `Pending` if the phase is not already set. This should only happen to old servers created before we had phases.
	if server.Status.Phase == "" {
		server.Status.Phase = unikornv1.InstanceLifecyclePhasePending
	}

	if openstackserver == nil {
		return
	}

	switch openstackserver.PowerState {
	case servers.NOSTATE:
		// No state information available. We will keep the phase as it is.
	case servers.RUNNING:
		server.Status.Phase = unikornv1.InstanceLifecyclePhaseRunning
	case servers.SHUTDOWN:
		server.Status.Phase = unikornv1.InstanceLifecyclePhaseStopped
	case servers.CRASHED:
		// REVIEW_ME: What should we do when the server crashes?
	case servers.PAUSED, servers.SUSPENDED:
		log.FromContext(ctx).Info("caught unsupported server power state", "powerState", openstackserver.PowerState.String())
	}
}

// CreateServer creates or updates a server.
//
//nolint:cyclop
func (p *Provider) CreateServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return err
	}

	openstackServer, create, err := p.GetOrCreateOpenstackServer(ctx, identity, server)
	if err != nil {
		return err
	}

	// Always attempt to record where we are up to for idempotency.
	record := func() {
		log := log.FromContext(ctx)

		if create {
			if err := p.client.Create(ctx, openstackServer); err != nil {
				log.Error(err, "failed to create openstack server")
			}

			return
		}

		if err := p.client.Update(ctx, openstackServer); err != nil {
			log.Error(err, "failed to update openstack server")
		}
	}

	defer record()

	// Rescope to the project...
	providerClient := NewPasswordProvider(p.region.Spec.Openstack.Endpoint, *openstackIdentity.Spec.UserID, *openstackIdentity.Spec.Password, *openstackIdentity.Spec.ProjectID)

	networkService, err := NewNetworkClient(ctx, providerClient, p.region.Spec.Openstack.Network)
	if err != nil {
		return err
	}

	if err := p.createServerPorts(ctx, networkService, openstackIdentity, server, openstackServer); err != nil {
		return err
	}

	computeService, err := NewComputeClient(ctx, providerClient, p.region.Spec.Openstack.Compute)
	if err != nil {
		return err
	}

	if err := p.createServer(ctx, computeService, openstackIdentity, server, openstackServer); err != nil {
		return err
	}

	providerServer, err := computeService.GetServer(ctx, *openstackServer.Spec.ServerID)
	if err != nil {
		return err
	}

	setServerHealthStatus(server, providerServer)
	setServerPhase(ctx, server, providerServer)

	// REVIEW_ME: Do we need to wait for `server.status.phase` to be `Running`?
	// wait for server to be active
	if providerServer.Status != "ACTIVE" {
		return fmt.Errorf("%w: expected ACTIVE status for server %s, got %s", provisioners.ErrYield, server.Name, providerServer.Status)
	}

	addr, err := p.getServerFixedIP(providerServer)
	if err != nil {
		return err
	}

	server.Status.PrivateIP = addr

	if err := p.allocateServerFloatingIP(ctx, networkService, server, openstackServer); err != nil {
		return err
	}

	return nil
}

func (p *Provider) createServer(ctx context.Context, computeService *ComputeClient, identity *unikornv1.OpenstackIdentity, server *unikornv1.Server, openstackServer *unikornv1.OpenstackServer) error {
	if openstackServer.Spec.ServerID != nil {
		return nil
	}

	// NOTE: exactly 1 is enforced at the API schema level.
	openstackNetworkID, err := p.openstackNetworkID(ctx, identity, server.Spec.Networks[0].ID)
	if err != nil {
		return err
	}

	networks := []NetworkOptions{
		{
			NetworkID: openstackNetworkID,
			PortID:    openstackServer.Spec.PortIDs[0],
		},
	}

	// These are defined to make cross referencing between unikorn
	// and openstack logging easier.
	metadata := map[string]string{
		"serverID":       server.Name,
		"organizationID": server.Labels[coreconstants.OrganizationLabel],
		"projectID":      server.Labels[coreconstants.ProjectLabel],
		"regionID":       server.Labels[constants.RegionLabel],
		"identityID":     identity.Name,
	}

	providerServer, err := computeService.CreateServer(ctx, server.Labels[coreconstants.NameLabel], server.Spec.Image.ID, server.Spec.FlavorID, *identity.Spec.SSHKeyName, networks, identity.Spec.ServerGroupID, metadata, server.Spec.UserData)
	if err != nil {
		return err
	}

	openstackServer.Spec.ServerID = &providerServer.ID

	if err := p.createServerCredentialsSecret(ctx, server, providerServer.AdminPass); err != nil {
		return err
	}

	return provisioners.ErrYield
}

func (p *Provider) createServerPorts(ctx context.Context, networkService *NetworkClient, identity *unikornv1.OpenstackIdentity, server *unikornv1.Server, openstackServer *unikornv1.OpenstackServer) error {
	// NOTE: exactly 1 is enforced at the API schema level.
	network := server.Spec.Networks[0]

	openstackNetworkID, err := p.openstackNetworkID(ctx, identity, server.Spec.Networks[0].ID)
	if err != nil {
		return err
	}

	securityGroupIDs, err := p.openstackSecurityGroupIDs(ctx, identity, server.Spec.SecurityGroups)
	if err != nil {
		return err
	}

	addressPairs := make([]ports.AddressPair, len(network.AllowedAddressPairs))

	for i, pair := range network.AllowedAddressPairs {
		addressPairs[i] = ports.AddressPair{
			IPAddress:  pair.CIDR.String(),
			MACAddress: pair.MACAddress,
		}
	}

	// Create a new port.
	if len(openstackServer.Spec.PortIDs) == 0 {
		providerPort, err := networkService.CreatePort(ctx, openstackNetworkID, securityGroupIDs, addressPairs)
		if err != nil {
			return err
		}

		openstackServer.Spec.PortIDs = append(openstackServer.Spec.PortIDs, providerPort.ID)

		return nil
	}

	// Update an existing port.
	if _, err := networkService.UpdatePort(ctx, openstackServer.Spec.PortIDs[0], securityGroupIDs, addressPairs); err != nil {
		return err
	}

	return nil
}

// openstackSecurityGroupIDs returns the openstack IDs for giving security group list.
func (p *Provider) openstackSecurityGroupIDs(ctx context.Context, identity *unikornv1.OpenstackIdentity, securityGroups []unikornv1.ServerSecurityGroupSpec) ([]string, error) {
	options := &client.ListOptions{
		Namespace: identity.Namespace,
		LabelSelector: labels.SelectorFromSet(map[string]string{
			constants.IdentityLabel: identity.Name,
		}),
	}

	resources := &unikornv1.OpenstackSecurityGroupList{}

	if err := p.client.List(ctx, resources, options); err != nil {
		return nil, err
	}

	sgMap := make(map[string]*unikornv1.OpenstackSecurityGroup)

	for _, net := range resources.Items {
		sgMap[net.Name] = &net
	}

	sgIDs := make([]string, 0, len(securityGroups))

	for _, sg := range securityGroups {
		// As we may be waiting for a separate controller to reconcile the
		// security group, yield rather than raise an error which is bad for
		// UX.
		s, ok := sgMap[sg.ID]
		if !ok {
			return nil, provisioners.ErrYield
		}

		if s.Spec.SecurityGroupID == nil {
			return nil, provisioners.ErrYield
		}

		sgIDs = append(sgIDs, *s.Spec.SecurityGroupID)
	}

	return sgIDs, nil
}

func (p *Provider) createServerCredentialsSecret(ctx context.Context, server *unikornv1.Server, password string) error {
	resource := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: server.Namespace,
			Name:      server.Name,
		},
		StringData: map[string]string{
			"password": password,
		},
	}

	// Ensure the secret is owned by the openstackserver so it is automatically cleaned
	// up on openstackserver deletion.
	if err := controllerutil.SetOwnerReference(server, resource, p.client.Scheme()); err != nil {
		return err
	}

	if err := p.client.Create(ctx, resource); err != nil {
		return err
	}

	return nil
}

func (p *Provider) deleteServerCredentialSecret(ctx context.Context, openstackServer *unikornv1.OpenstackServer) error {
	resource := &corev1.Secret{}
	if err := p.client.Get(ctx, client.ObjectKey{Namespace: openstackServer.Namespace, Name: openstackServer.Name}, resource); err != nil {
		if kerrors.IsNotFound(err) {
			// nothing to do here
			return nil
		}

		return err
	}

	if err := p.client.Delete(ctx, resource); err != nil {
		return err
	}

	return nil
}

func (p *Provider) allocateServerFloatingIP(ctx context.Context, networkService *NetworkClient, server *unikornv1.Server, openstackServer *unikornv1.OpenstackServer) error {
	hasFloatingIP := openstackServer.Spec.PublicIPAllocationID != nil
	needsFloatingIP := server.Spec.PublicIPAllocation != nil && server.Spec.PublicIPAllocation.Enabled

	// In the right state, nothing to do.
	if hasFloatingIP == needsFloatingIP {
		return nil
	}

	// Create a floating IP.
	if needsFloatingIP {
		if len(openstackServer.Spec.PortIDs) == 0 {
			return fmt.Errorf("%w: no ports found for server %s", ErrResourceNotFound, *openstackServer.Spec.ServerID)
		}

		// NOTE: exactly 1 is enforced at the API level as only 1 network is supported.
		portID := openstackServer.Spec.PortIDs[0]

		floatingIP, err := networkService.CreateFloatingIP(ctx, portID)
		if err != nil {
			return err
		}

		server.Status.PublicIP = &floatingIP.FloatingIP
		openstackServer.Spec.PublicIPAllocationID = &floatingIP.ID

		return nil
	}

	// Delete a floating IP.
	if err := networkService.DeleteFloatingIP(ctx, *openstackServer.Spec.PublicIPAllocationID); err != nil {
		return err
	}

	server.Status.PublicIP = nil
	openstackServer.Spec.PublicIPAllocationID = nil

	return nil
}

func (p *Provider) getServerFixedIP(server *servers.Server) (*string, error) {
	// Iterate through the server's addresses and extract the fixed IP.
	for _, network := range server.Addresses {
		addresses, ok := network.([]any)
		if !ok {
			continue
		}

		for _, addr := range addresses {
			properties, ok := addr.(map[string]any)
			if !ok {
				continue
			}

			iptype, ok := properties["OS-EXT-IPS:type"].(string)
			if !ok || iptype != "fixed" {
				continue
			}

			ipaddr, ok := properties["addr"].(string)
			if !ok {
				continue
			}

			return &ipaddr, nil
		}
	}

	return nil, fmt.Errorf("%w: no ip address found for server %s", ErrResourceNotFound, server.ID)
}

func (p *Provider) RebootServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, hard bool) error {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return err
	}

	openstackServer, err := p.GetOpenstackServer(ctx, server)
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return err
		}

		return nil
	}

	providerClient := NewPasswordProvider(p.region.Spec.Openstack.Endpoint, p.credentials.userID, p.credentials.password, *openstackIdentity.Spec.ProjectID)

	computeService, err := NewComputeClient(ctx, providerClient, p.region.Spec.Openstack.Compute)
	if err != nil {
		return err
	}

	if openstackServer.Spec.ServerID != nil {
		if err := computeService.RebootServer(ctx, *openstackServer.Spec.ServerID, hard); err != nil {
			// ignore not found errors
			if !gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
				return err
			}
		}
	}

	return nil
}

//nolint:dupl
func (p *Provider) StartServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return err
	}

	openstackServer, err := p.GetOpenstackServer(ctx, server)
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return err
		}

		return nil
	}

	providerClient := NewPasswordProvider(p.region.Spec.Openstack.Endpoint, p.credentials.userID, p.credentials.password, *openstackIdentity.Spec.ProjectID)

	computeService, err := NewComputeClient(ctx, providerClient, p.region.Spec.Openstack.Compute)
	if err != nil {
		return err
	}

	if openstackServer.Spec.ServerID != nil {
		if err := computeService.StartServer(ctx, *openstackServer.Spec.ServerID); err != nil {
			// ignore not found errors
			if !gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
				return err
			}
		}
	}

	return nil
}

//nolint:dupl
func (p *Provider) StopServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return err
	}

	openstackServer, err := p.GetOpenstackServer(ctx, server)
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return err
		}

		return nil
	}

	providerClient := NewPasswordProvider(p.region.Spec.Openstack.Endpoint, p.credentials.userID, p.credentials.password, *openstackIdentity.Spec.ProjectID)

	computeService, err := NewComputeClient(ctx, providerClient, p.region.Spec.Openstack.Compute)
	if err != nil {
		return err
	}

	if openstackServer.Spec.ServerID != nil {
		if err := computeService.StopServer(ctx, *openstackServer.Spec.ServerID); err != nil {
			// ignore not found errors
			if !gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
				return err
			}
		}
	}

	return nil
}

// DeleteServer deletes a server.
//
//nolint:gocognit,cyclop
func (p *Provider) DeleteServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return err
	}

	openstackServer, err := p.GetOpenstackServer(ctx, server)
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return err
		}

		return nil
	}

	complete := false

	// Always attempt to record where we are up to for idempotency.
	record := func() {
		if complete {
			return
		}

		log := log.FromContext(ctx)

		if err := p.client.Update(ctx, openstackServer); err != nil {
			log.Error(err, "failed to update openstack server")
		}
	}

	defer record()

	// Rescope to the project...
	providerClient := NewPasswordProvider(p.region.Spec.Openstack.Endpoint, p.credentials.userID, p.credentials.password, *openstackIdentity.Spec.ProjectID)

	networkService, err := NewNetworkClient(ctx, providerClient, p.region.Spec.Openstack.Network)
	if err != nil {
		return err
	}

	if openstackServer.Spec.PublicIPAllocationID != nil {
		if err := networkService.DeleteFloatingIP(ctx, *openstackServer.Spec.PublicIPAllocationID); err != nil {
			// ignore not found errors
			if !gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
				return err
			}
		}

		openstackServer.Spec.PublicIPAllocationID = nil
	}

	computeService, err := NewComputeClient(ctx, providerClient, p.region.Spec.Openstack.Compute)
	if err != nil {
		return err
	}

	if openstackServer.Spec.ServerID != nil {
		if err := computeService.DeleteServer(ctx, *openstackServer.Spec.ServerID); err != nil {
			// ignore not found errors
			if !gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
				return err
			}
		}

		openstackServer.Spec.ServerID = nil
	}

	if len(openstackServer.Spec.PortIDs) > 0 {
		for _, portID := range openstackServer.Spec.PortIDs {
			if err := networkService.DeletePort(ctx, portID); err != nil {
				// ignore not found errors
				if !gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
					return err
				}
			}
		}

		openstackServer.Spec.PortIDs = nil
	}

	if err := p.deleteServerCredentialSecret(ctx, openstackServer); err != nil {
		return err
	}

	if err := p.client.Delete(ctx, openstackServer); err != nil {
		return err
	}

	complete = true

	return nil
}

// UpdateServerState checks a server's state and modifies the resource in place.
func (p *Provider) UpdateServerState(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return err
	}

	openstackServer, err := p.GetOpenstackServer(ctx, server)
	if err != nil {
		return err
	}

	// Rescope to the project...
	providerClient := NewPasswordProvider(p.region.Spec.Openstack.Endpoint, *openstackIdentity.Spec.UserID, *openstackIdentity.Spec.Password, *openstackIdentity.Spec.ProjectID)

	computeService, err := NewComputeClient(ctx, providerClient, p.region.Spec.Openstack.Compute)
	if err != nil {
		return err
	}

	var providerServer *servers.Server

	if openstackServer.Spec.ServerID != nil {
		temp, err := computeService.GetServer(ctx, *openstackServer.Spec.ServerID)
		if err != nil {
			return err
		}

		providerServer = temp
	}

	setServerHealthStatus(server, providerServer)
	setServerPhase(ctx, server, providerServer)

	return nil
}
