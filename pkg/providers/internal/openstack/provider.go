/*
Copyright 2024-2025 the Unikorn Authors.
Copyright 2026 Nscale.

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
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/baremetal/v1/nodes"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/roles"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/loadbalancers"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/monitors"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/pools"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"
	"github.com/gophercloud/utils/openstack/clientconfig"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	"github.com/unikorn-cloud/core/pkg/util/cache"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers/allocation/vlan"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	"github.com/unikorn-cloud/region/pkg/providers/util"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/yaml"
)

const (
	osKernelLabel   = "unikorn:os:kernel"
	osFamilyLabel   = "unikorn:os:family"
	osDistroLabel   = "unikorn:os:distro"
	osVersionLabel  = "unikorn:os:version"
	osVariantLabel  = "unikorn:os:variant"
	osCodenameLabel = "unikorn:os:codename"

	virtualizationLabel   = "unikorn:virtualization"
	gpuModelsLabel        = "unikorn:gpu_models"
	gpuVendorLabel        = "unikorn:gpu_vendor"
	gpuDriverVersionLabel = "unikorn:gpu_driver_version"

	packageLabelPrefix = "unikorn:package:"

	kubernetesVersionLabel = "unikorn:kubernetes_version"

	organizationIDLabel = "unikorn:organization:id"
	tagLabelPrefix      = "unikorn:tag:"
	identityIDLabel     = "unikorn:identity_id"

	containerFormatBare = "bare" // there's no const in gophercloud for this, so we have our own.

	// These ones are well defined openstack image properties.
	imageArchitectureProperty = "architecture"
)

var tagKeyRegex = regexp.MustCompile(
	`^([a-z0-9][a-z0-9-]*)\.[^/]+/([a-z0-9][a-z0-9-]*)$`,
)

// metadataKey converts a namespaced tag key of the form
// "<service>.unikorn-cloud.org/<local-name>" into the OpenStack metadata key
// "<service>:<local_name>", returning false if the key does not match the schema.
func metadataKey(key string) (string, bool) {
	m := tagKeyRegex.FindStringSubmatch(key)
	if m == nil {
		return "", false
	}

	return m[1] + ":" + strings.ReplaceAll(m[2], "-", "_"), true
}

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

	openstack *openStackClients

	// vlan allocation table.
	// NOTE: this can only be used by a single client unless it's moved
	// into a Kubernetes resource of some variety to gain speculative locking
	// powers.
	vlanAllocator *vlan.Allocator

	// imageCache is used to downsample the OpenStack image API, because responses can
	// take seconds. This reduces the effect of that latency on all callers.
	imageCache *cache.RefreshAheadCache[types.Image, *types.Image]
}

var _ types.Provider = &Provider{}

type Options struct {
	// WarmImageCache enables startup-time image cache initialization.
	WarmImageCache bool
}

// New constructs an OpenStack provider.
//
// Provider construction has two phases:
// 1. Bootstrap service-client state with initClient before any controller cache exists.
// 2. Return a provider that retains runtimeClient for all subsequent Kubernetes reads.
//
// This makes the bootstrap/runtime boundary explicit: direct reads are used only while
// building the initial OpenStack client state, and normal provider operation switches
// back to the runtime client immediately afterwards.
func New(ctx context.Context, initClient client.Client, runtimeClient client.Client, region *unikornv1.Region, opts Options) (*Provider, error) {
	bootstrapState, err := bootstrapServiceClientState(ctx, initClient, region)
	if err != nil {
		return nil, err
	}

	p := &Provider{
		client: runtimeClient,
		openstack: &openStackClients{
			client:  runtimeClient,
			_region: region,
		},
		vlanAllocator: vlan.New(runtimeClient, region),
	}

	// Install the bootstrapped OpenStack client state onto the long-lived runtime wrapper.
	// After this point, Kubernetes reads flow through runtimeClient and no bootstrap-only
	// client is retained by the provider.
	p.openstack.install(bootstrapState)

	if opts.WarmImageCache {
		imageCacheOptions := &cache.RefreshAheadCacheOptions{
			RefreshPeriod: time.Minute,
		}

		imageCache := cache.NewRefreshAheadCache[types.Image](p.imageRefresh, imageCacheOptions)
		if err := imageCache.Run(ctx); err != nil {
			return nil, err
		}

		p.imageCache = imageCache
	}

	return p, nil
}

// getProviderFromServicePrincipalData creates a generic provider client from ephemeral
// per-service principal credentials.
func (p *Provider) getProviderFromServicePrincipalData(identity *unikornv1.OpenstackIdentity) (CredentialProvider, error) {
	if identity.Spec.UserID == nil {
		return nil, fmt.Errorf("%w: service principal user ID not set", coreerrors.ErrConsistency)
	}

	if identity.Spec.Password == nil {
		return nil, fmt.Errorf("%w: service principal password not set", coreerrors.ErrConsistency)
	}

	if identity.Spec.ProjectID == nil {
		return nil, fmt.Errorf("%w: service principal project not set", coreerrors.ErrConsistency)
	}

	region, _ := p.openstack.regionSnapshot()

	return NewPasswordProvider(region.Spec.Openstack.Endpoint, *identity.Spec.UserID, *identity.Spec.Password, *identity.Spec.ProjectID), nil
}

// computeFromServicePrincipalData gets a compute client scoped to the service principal data.
func (p *Provider) computeFromServicePrincipalData(ctx context.Context, identity *unikornv1.OpenstackIdentity) (ComputeInterface, error) {
	provider, err := p.getProviderFromServicePrincipalData(identity)
	if err != nil {
		return nil, err
	}

	region, _ := p.openstack.regionSnapshot()

	client, err := NewComputeClient(ctx, provider, region.Spec.Openstack.Compute)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// getProviderFromServicePrincipal takes a service principal and returns a generic
// provider client for it.
func (p *Provider) getProviderFromServicePrincipal(ctx context.Context, identity *unikornv1.Identity) (CredentialProvider, error) {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return nil, err
	}

	return p.getProviderFromServicePrincipalData(openstackIdentity)
}

// getPrivilegedProviderFromServicePrincipal binds itself to the service principal's project
// but uses the provider's top level admin credentials.
func (p *Provider) getPrivilegedProviderFromServicePrincipal(ctx context.Context, identity *unikornv1.Identity) (CredentialProvider, error) {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return nil, err
	}

	if openstackIdentity.Spec.ProjectID == nil {
		return nil, fmt.Errorf("%w: service principal project not set", coreerrors.ErrConsistency)
	}

	region, credentials := p.openstack.regionSnapshot()

	return NewPasswordProvider(region.Spec.Openstack.Endpoint, credentials.userID, credentials.password, *openstackIdentity.Spec.ProjectID), nil
}

// computeFromServicePrincipal gets a compute client scoped to the service principal.
func (p *Provider) computeFromServicePrincipal(ctx context.Context, identity *unikornv1.Identity) (ComputeInterface, error) {
	provider, err := p.getProviderFromServicePrincipal(ctx, identity)
	if err != nil {
		return nil, err
	}

	region, _ := p.openstack.regionSnapshot()

	client, err := NewComputeClient(ctx, provider, region.Spec.Openstack.Compute)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// providerForServerCreate gets the credential provider to use for creating a server.
func (p *Provider) providerForServerCreate(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) (CredentialProvider, error) {
	if server.Spec.InfrastructureRef != nil {
		return p.getPrivilegedProviderFromServicePrincipal(ctx, identity)
	}

	return p.getProviderFromServicePrincipal(ctx, identity)
}

// baremetalPhaseProvider returns the credential provider used for Ironic
// node lookups that feed Server Phase derivation. Node-to-instance mapping
// is provider infrastructure state, so use the top-level Region credentials
// scoped to the service principal's project rather than the tenant
// service-principal credentials.
func (p *Provider) baremetalPhaseProvider(ctx context.Context, identity *unikornv1.Identity) (CredentialProvider, error) {
	return p.getPrivilegedProviderFromServicePrincipal(ctx, identity)
}

func (p *Provider) baremetalForPhase(ctx context.Context, identity *unikornv1.Identity) (BaremetalInterface, error) {
	provider, err := p.baremetalPhaseProvider(ctx, identity)
	if err != nil {
		return nil, err
	}

	client, err := NewBaremetalClient(ctx, provider)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// computeForServerCreate gets a compute client for creating a server.
func (p *Provider) computeForServerCreate(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) (ComputeInterface, error) {
	provider, err := p.providerForServerCreate(ctx, identity, server)
	if err != nil {
		return nil, err
	}

	region, _ := p.openstack.regionSnapshot()

	client, err := NewComputeClient(ctx, provider, region.Spec.Openstack.Compute)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// imageFromServicePrincipal gets a compute client scoped to the service principal data.
func (p *Provider) imageFromServicePrincipal(ctx context.Context, identity *unikornv1.Identity) (*ImageClient, error) {
	provider, err := p.getProviderFromServicePrincipal(ctx, identity)
	if err != nil {
		return nil, err
	}

	region, _ := p.openstack.regionSnapshot()

	client, err := NewImageClient(ctx, provider, region.Spec.Openstack.Image)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// privilegedImageFromServicePrincipal gets a compute client scoped to the service principal data
// but with "manager" credentials.
func (p *Provider) privilegedImageFromServicePrincipal(ctx context.Context, identity *unikornv1.Identity) (*ImageClient, error) {
	provider, err := p.getPrivilegedProviderFromServicePrincipal(ctx, identity)
	if err != nil {
		return nil, err
	}

	region, _ := p.openstack.regionSnapshot()

	client, err := NewImageClient(ctx, provider, region.Spec.Openstack.Image)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// networkFromServicePrincipal gets a network client scoped to the service principal.
func (p *Provider) networkFromServicePrincipal(ctx context.Context, identity *unikornv1.Identity) (NetworkingInterface, error) {
	provider, err := p.getProviderFromServicePrincipal(ctx, identity)
	if err != nil {
		return nil, err
	}

	region, _ := p.openstack.regionSnapshot()

	client, err := NewNetworkClient(ctx, provider, region.Spec.Openstack.Network)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// privilegedNetworkFromServicePrincipal gets a network client scoped to the service principal's
// project but with "manager" credentials.
func (p *Provider) privilegedNetworkFromServicePrincipal(ctx context.Context, identity *unikornv1.Identity) (NetworkingInterface, error) {
	provider, err := p.getPrivilegedProviderFromServicePrincipal(ctx, identity)
	if err != nil {
		return nil, err
	}

	region, _ := p.openstack.regionSnapshot()

	client, err := NewNetworkClient(ctx, provider, region.Spec.Openstack.Network)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// loadBalancerFromServicePrincipal gets a load balancer client scoped to the service principal.
func (p *Provider) loadBalancerFromServicePrincipal(ctx context.Context, identity *unikornv1.Identity) (LoadBalancingInterface, error) {
	provider, err := p.getProviderFromServicePrincipal(ctx, identity)
	if err != nil {
		return nil, err
	}

	client, err := NewLoadBalancerClient(ctx, provider)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// Region returns the provider's region.
func (p *Provider) Region(ctx context.Context) (*unikornv1.Region, error) {
	region, _, err := p.openstack.regionRefresh(ctx)

	return region, err
}

// Flavors list all available flavors.
func (p *Provider) Flavors(ctx context.Context) (types.FlavorList, error) {
	compute, err := p.openstack.compute(ctx)
	if err != nil {
		return nil, err
	}

	resources, err := compute.GetFlavors(ctx)
	if err != nil {
		return nil, err
	}

	region, _ := p.openstack.regionSnapshot()
	result := make(types.FlavorList, len(resources))

	for i := range resources {
		flavor := &resources[i]

		// API memory is in MiB, disk is in GB
		f := types.Flavor{
			ID:           flavor.ID,
			Name:         flavor.Name,
			Architecture: types.X86_64,
			CPUs:         flavor.VCPUs,
			Memory:       resource.NewQuantity(int64(flavor.RAM)<<20, resource.BinarySI),
			Disk:         resource.NewScaledQuantity(int64(flavor.Disk), resource.Giga),
		}

		// Apply any extra metadata to the flavor.
		//
		//nolint:nestif
		if region.Spec.Openstack.Compute != nil && region.Spec.Openstack.Compute.Flavors != nil {
			i := slices.IndexFunc(region.Spec.Openstack.Compute.Flavors.Metadata, func(metadata unikornv1.FlavorMetadata) bool {
				return flavor.ID == metadata.ID
			})

			if i >= 0 {
				metadata := &region.Spec.Openstack.Compute.Flavors.Metadata[i]

				f.Baremetal = metadata.Baremetal
				f.PinnedOnly = metadata.PinnedOnly

				if metadata.CPU != nil {
					if metadata.CPU.Architecture != nil {
						f.Architecture = types.Architecture(*metadata.CPU.Architecture)
					}

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

// imageOS extracts the image OS from the image properties.
func imageOS(image *images.Image) types.ImageOS {
	kernel, _ := image.Properties[osKernelLabel].(string)
	family, _ := image.Properties[osFamilyLabel].(string)
	distro, _ := image.Properties[osDistroLabel].(string)
	version, _ := image.Properties[osVersionLabel].(string)

	result := types.ImageOS{
		Kernel:  types.OsKernel(kernel),
		Family:  family,
		Distro:  distro,
		Version: version,
	}

	if variant, exists := image.Properties[osVariantLabel].(string); exists {
		result.Variant = &variant
	}

	if codename, exists := image.Properties[osCodenameLabel].(string); exists {
		result.Codename = &codename
	}

	return result
}

// imagePackages extracts the image packages from the image properties.
func imagePackages(image *images.Image) *types.ImagePackages {
	result := make(types.ImagePackages)

	for key, value := range image.Properties {
		// Check if the key starts with "unikorn:package:"
		if strings.HasPrefix(key, packageLabelPrefix) {
			packageName := key[len(packageLabelPrefix):]

			if strValue, ok := value.(string); ok {
				result[packageName] = strValue
			}
		}
	}

	// https://github.com/unikorn-cloud/specifications/blob/main/specifications/providers/openstack/flavors_and_images.md
	// kubernetes_version was removed in v2.0.0 of the specification, but we still support it for backwards compatibility.
	if _, exists := result["kubernetes"]; !exists {
		if version, ok := image.Properties[kubernetesVersionLabel].(string); ok {
			result["kubernetes"] = version
		}
	}

	return &result
}

func isPublicOrOrganizationOwnedImage(image *types.Image, organizationIDs []string) bool {
	return image.OrganizationID == nil || slices.Contains(organizationIDs, *image.OrganizationID)
}

func isOrganizationOwnedImage(image *types.Image, organizationIDs []string) bool {
	return image.OrganizationID != nil && slices.Contains(organizationIDs, *image.OrganizationID)
}

func imageStatus(image *images.Image) types.ImageStatus {
	var status types.ImageStatus

	switch image.Status {
	case images.ImageStatusQueued:
		status = types.ImageStatusPending
	case images.ImageStatusSaving, images.ImageStatusImporting, images.ImageStatusUploading:
		status = types.ImageStatusCreating
	case images.ImageStatusActive:
		status = types.ImageStatusReady
	case images.ImageStatusKilled:
		status = types.ImageStatusFailed
	case images.ImageStatusDeleted, images.ImageStatusPendingDelete, images.ImageStatusDeactivated:
		// These statuses are not directly mappable, mark them as failed.
		status = types.ImageStatusFailed
	}

	return status
}

func imageArchitecture(image *images.Image) types.Architecture {
	if v, ok := image.Properties[imageArchitectureProperty].(string); ok && v != "" {
		return types.Architecture(v)
	}

	return types.X86_64
}

func imageTags(image *images.Image) map[string]string {
	tags := make(map[string]string)

	for k, v := range image.Properties {
		if strings.HasPrefix(k, tagLabelPrefix) {
			value, ok := v.(string) // empty string if this type assertion fails
			if ok {
				tags[k[len(tagLabelPrefix):]] = value
			}
		}
	}

	if len(tags) == 0 {
		return nil
	}

	return tags
}

func convertImage(image *images.Image) (*types.Image, error) {
	var organizationID *string
	if temp, _ := image.Properties[organizationIDLabel].(string); temp != "" {
		organizationID = &temp
	}

	size := image.MinDiskGigabytes

	if size == 0 {
		// Round up to the nearest GiB.
		size = int((image.VirtualSize + (1 << 30) - 1) >> 30)
	}

	virtualization, _ := image.Properties[virtualizationLabel].(string)

	identityID, _ := image.Properties[identityIDLabel].(string)

	tags := imageTags(image)

	providerImage := types.Image{
		ID:             image.ID,
		Name:           image.Name,
		Tags:           tags,
		OrganizationID: organizationID,
		Created:        image.CreatedAt,
		Modified:       image.UpdatedAt,
		Architecture:   imageArchitecture(image),
		SizeGiB:        size,
		Virtualization: types.ImageVirtualization(virtualization),
		OS:             imageOS(image),
		Packages:       imagePackages(image),
		Status:         imageStatus(image),
		IdentityID:     identityID,
	}

	if gpuVendor, ok := image.Properties[gpuVendorLabel].(string); ok {
		gpuDriver, ok := image.Properties[gpuDriverVersionLabel].(string)
		if !ok {
			// TODO: it's perhaps better to just skip this one, rather than kill the entire service??
			return nil, fmt.Errorf("%w: GPU driver is not defined for image %s", coreerrors.ErrKey, image.ID)
		}

		gpu := &types.ImageGPU{
			Vendor: types.GPUVendor(gpuVendor),
			Driver: gpuDriver,
		}

		if models, ok := image.Properties[gpuModelsLabel].(string); ok {
			gpu.Models = strings.Split(models, ",")
		}

		providerImage.GPU = gpu
	}

	return &providerImage, nil
}

type imageFilter func(*types.Image) bool

// TODO: this operates on generic types now, so shouldn't live here.
// However it relies on some RBAC functions defined internally that
// are still needed by part of this package.
type imageQuery struct {
	listFunc func() (*cache.ListSnapshot[types.Image], error)
	filters  []imageFilter
}

func (q *imageQuery) AvailableToOrganization(organizationIDs ...string) types.ImageQuery {
	q.filters = append(q.filters, func(im *types.Image) bool {
		return !isPublicOrOrganizationOwnedImage(im, organizationIDs)
	})

	return q
}

func (q *imageQuery) OwnedByOrganization(organizationIDs ...string) types.ImageQuery {
	q.filters = append(q.filters, func(im *types.Image) bool {
		return !isOrganizationOwnedImage(im, organizationIDs)
	})

	return q
}

func (q *imageQuery) StatusIn(statuses ...types.ImageStatus) types.ImageQuery {
	q.filters = append(q.filters, func(im *types.Image) bool {
		return !slices.Contains(statuses, im.Status)
	})

	return q
}

func (q *imageQuery) filter(im *types.Image) bool {
	for _, f := range q.filters {
		if f(im) {
			return true
		}
	}

	return false
}

func (q *imageQuery) List(_ context.Context) (types.ImageList, error) {
	images, err := q.listFunc()
	if err != nil {
		return nil, err
	}

	images.Items = slices.DeleteFunc(images.Items, func(i *types.Image) bool {
		return q.filter(i)
	})

	return images, nil
}

// imageRefresh happens in the background periodically and on invalidation.
// Do as much work here as is possible to hide the cost from API calls.
func (p *Provider) imageRefresh(ctx context.Context) ([]*types.Image, error) {
	imageService, err := p.openstack.image(ctx)
	if err != nil {
		return nil, err
	}

	resources, err := imageService.ListImages(ctx)
	if err != nil {
		return nil, err
	}

	items := make([]*types.Image, len(resources))

	for i := range resources {
		item, err := convertImage(&resources[i])
		if err != nil {
			return nil, err
		}

		items[i] = item
	}

	return items, nil
}

func (p *Provider) QueryImages() (types.ImageQuery, error) {
	if p.imageCache == nil {
		return nil, fmt.Errorf("%w: image caching is disabled", coreerrors.ErrResourceNotFound)
	}

	return &imageQuery{listFunc: p.imageCache.List}, nil
}

// GetImage retrieves a specific image by its ID.
func (p *Provider) GetImage(ctx context.Context, organizationID, imageID string) (*types.Image, error) {
	if p.imageCache == nil {
		return nil, fmt.Errorf("%w: image caching is disabled", coreerrors.ErrResourceNotFound)
	}

	image, err := p.imageCache.Get(imageID)
	if err != nil {
		if errors.Is(err, cache.ErrNotFound) {
			return nil, fmt.Errorf("%w: image %s", coreerrors.ErrResourceNotFound, imageID)
		}

		return nil, err
	}

	if !isPublicOrOrganizationOwnedImage(image.Item, []string{organizationID}) {
		return nil, fmt.Errorf(
			"%w: image %s is not accessible to organization %s",
			coreerrors.ErrResourceNotFound,
			imageID,
			organizationID,
		)
	}

	return image.Item, nil
}

func setIfNotNil[T ~string](metadata map[string]string, key string, value *T) {
	if value != nil {
		metadata[key] = string(*value)
	}
}

func createImageMetadata(image *types.Image) (map[string]string, error) {
	metadata := make(map[string]string)

	metadata[osKernelLabel] = string(image.OS.Kernel)
	metadata[osFamilyLabel] = image.OS.Family
	metadata[osDistroLabel] = image.OS.Distro
	metadata[osVersionLabel] = image.OS.Version
	setIfNotNil(metadata, osVariantLabel, image.OS.Variant)
	setIfNotNil(metadata, osCodenameLabel, image.OS.Codename)

	for k, v := range image.Tags {
		metadata[tagLabelPrefix+k] = v
	}

	if image.Packages != nil {
		for name, version := range *image.Packages {
			key := fmt.Sprintf("%s%s", packageLabelPrefix, name)
			metadata[key] = version
		}
	}

	if image.GPU != nil {
		if image.GPU.Vendor == "" {
			return nil, fmt.Errorf("%w: GPU vendor must be defined when GPU information is provided", coreerrors.ErrKey)
		}

		if len(image.GPU.Models) == 0 {
			return nil, fmt.Errorf("%w: GPU models must be defined when GPU information is provided", coreerrors.ErrKey)
		}

		if image.GPU.Driver == "" {
			return nil, fmt.Errorf("%w: GPU driver must be defined when GPU information is provided", coreerrors.ErrKey)
		}

		gpuModels := strings.Join(image.GPU.Models, ",")

		metadata[gpuVendorLabel] = string(image.GPU.Vendor)
		metadata[gpuModelsLabel] = gpuModels
		metadata[gpuDriverVersionLabel] = image.GPU.Driver
	}

	metadata[imageArchitectureProperty] = string(image.Architecture)
	metadata[virtualizationLabel] = string(image.Virtualization)
	setIfNotNil(metadata, organizationIDLabel, image.OrganizationID)

	metadata["hw_disk_bus"] = "scsi"
	metadata["hw_firmware_type"] = "uefi"
	metadata["hw_scsi_model"] = "virtio-scsi"

	// See: https://docs.openstack.org/nova/latest/admin/hw-machine-type.html
	switch image.Architecture {
	case types.X86_64:
		metadata["hw_machine_type"] = "q35"
	case types.Aarch64:
		metadata["hw_machine_type"] = "virt"
	}

	return metadata, nil
}

// CreateImage creates a new image.
func (p *Provider) CreateImage(ctx context.Context, image *types.Image, uri string) (*types.Image, error) {
	if p.imageCache == nil {
		return nil, fmt.Errorf("%w: image caching is disabled", coreerrors.ErrResourceNotFound)
	}

	imageService, err := p.openstack.image(ctx)
	if err != nil {
		return nil, err
	}

	properties, err := createImageMetadata(image)
	if err != nil {
		return nil, err
	}

	opts := &images.CreateOpts{
		Name:            image.Name,
		Visibility:      ptr.To(images.ImageVisibilityPublic),
		ContainerFormat: containerFormatBare,
		DiskFormat:      "raw",
		Properties:      properties,
	}

	resource, err := imageService.CreateImage(ctx, opts)
	if err != nil {
		return nil, err
	}

	if err := imageService.Import(ctx, resource.ID, uri); err != nil {
		return nil, err
	}

	// Bridge successful writes into the cache immediately so the handler does not need
	// to force a synchronous Glance relist back onto the request path.
	//
	// This seeds the cache from the pre-import Glance response, so callers may observe
	// an intermediate queued/importing status until the next background refresh
	// converges on the fully updated image state.
	syntheticImage, err := convertImage(resource)
	if err != nil {
		return nil, err
	}

	if err := p.imageCache.InsertIfAbsent(syntheticImage); err != nil {
		return nil, err
	}

	return syntheticImage, nil
}

func (p *Provider) DeleteImage(ctx context.Context, imageID string) error {
	if p.imageCache == nil {
		return fmt.Errorf("%w: image caching is disabled", coreerrors.ErrResourceNotFound)
	}

	image, err := p.imageCache.Get(imageID)
	if err != nil {
		return err
	}

	// If we've set the identity ID, then that means it's a snapshot and
	// currently lives in the service principal's project, so rescope to
	// that.
	if identityID := image.Item.IdentityID; identityID != "" {
		identity := &unikornv1.Identity{}

		region, _ := p.openstack.regionSnapshot()

		if err := p.client.Get(ctx, client.ObjectKey{Namespace: region.Namespace, Name: identityID}, identity); err != nil {
			return err
		}

		imageService, err := p.imageFromServicePrincipal(ctx, identity)
		if err != nil {
			return err
		}

		return p.deleteImage(ctx, imageService, image.Item, imageID)
	}

	// Otherwise it exists in our project...
	imageService, err := p.openstack.image(ctx)
	if err != nil {
		return err
	}

	return p.deleteImage(ctx, imageService, image.Item, imageID)
}

func (p *Provider) deleteImage(ctx context.Context, imageService *ImageClient, image *types.Image, imageID string) error {
	if p.imageCache == nil {
		return fmt.Errorf("%w: image caching is disabled", coreerrors.ErrResourceNotFound)
	}

	if err := imageService.DeleteImage(ctx, imageID); err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return fmt.Errorf("image %w", coreerrors.ErrResourceNotFound)
		}

		if gophercloud.ResponseCodeIs(err, http.StatusConflict) {
			return types.ErrImageStillInUse
		}

		return err
	}

	// Bridge delete visibility through the cache immediately without forcing a blocking
	// relist. The public provider model does not have a delete-tombstone image status,
	// so we mark the cached entry failed until a later refresh removes it.
	//
	// Cache reads are intentionally zero-copy for performance, so image may alias the
	// currently published cache object. Clone before mutating the status we upsert back
	// into the cache.
	//
	// The current cache API no longer supports a custom retire-on-absence policy for
	// Upsert overlays, so this tombstone remains visible only until the next
	// authoritative refresh that starts after this write.
	deleting := image.DeepCopy()
	deleting.Status = types.ImageStatusFailed

	// Image cache warmup is part of API readiness, so Upsert is expected to be available
	// for all normal request paths by the time delete can be called.
	if err := p.imageCache.Upsert(deleting); err != nil {
		return err
	}

	return nil
}

// ListExternalNetworks returns a list of external networks if the platform
// supports such a concept.
func (p *Provider) ListExternalNetworks(ctx context.Context) (types.ExternalNetworks, error) {
	networking, err := p.openstack.network(ctx)
	if err != nil {
		return nil, err
	}

	result, err := networking.ExternalNetworks(ctx)
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
	_, credentials := p.openstack.regionSnapshot()

	user, err := identityService.CreateUser(ctx, credentials.domainID, name, password)
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
	_, credentials := p.openstack.regionSnapshot()

	project, err := identityService.CreateProject(ctx, credentials.domainID, name, projectTags(identity))
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

	return "", fmt.Errorf("%w: role %s", coreerrors.ErrResourceNotFound, name)
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
	region, _ := p.openstack.regionSnapshot()

	if region.Spec.Openstack.Identity != nil && len(region.Spec.Openstack.Identity.ClusterRoles) > 0 {
		return region.Spec.Openstack.Identity.ClusterRoles
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

	region, _ := p.openstack.regionSnapshot()
	// Rescope to the user/project...
	providerClient := NewPasswordProvider(region.Spec.Openstack.Endpoint, *identity.Spec.UserID, *identity.Spec.Password, *identity.Spec.ProjectID)

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
	region, credentials := p.openstack.regionSnapshot()

	providerClient := NewPasswordProvider(region.Spec.Openstack.Endpoint, credentials.userID, credentials.password, *identity.Spec.ProjectID)

	compute, err := NewComputeClient(ctx, providerClient, region.Spec.Openstack.Compute)
	if err != nil {
		return err
	}

	network, err := NewNetworkClient(ctx, providerClient, region.Spec.Openstack.Network)
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

	if err := network.UpdateQuotas(ctx, *identity.Spec.ProjectID); err != nil {
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

	region, _ := p.openstack.regionSnapshot()

	clientConfig := &clientconfig.Clouds{
		Clouds: map[string]clientconfig.Cloud{
			cloud: {
				AuthType: clientconfig.AuthV3ApplicationCredential,
				AuthInfo: &clientconfig.AuthInfo{
					AuthURL:                     region.Spec.Openstack.Endpoint,
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

	compute, err := p.computeFromServicePrincipalData(ctx, identity)
	if err != nil {
		return err
	}

	name := identityResourceName(identity)

	// Create a server group, that can be used by clients for soft anti-affinity.
	result, err := compute.CreateServerGroup(ctx, name)
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

	if err := compute.CreateKeypair(ctx, keyPairName, string(publicKey)); err != nil {
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
	identityService, err := p.openstack.identity(ctx)
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

	_, credentials := p.openstack.regionSnapshot()

	// Grant the "manager" role on the project for unikorn's user.  Sadly when provisioning
	// resources, most services can only infer the project ID from the token, and not any
	// of the hierarchy, so we cannot define policy rules for a domain manager in the same
	// way as can be done for the identity service.
	if err := p.provisionProjectRoles(ctx, identityService, openstackIdentity, credentials.userID, p.getRequiredProjectManagerRoles); err != nil {
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
//nolint:cyclop,gocognit
func (p *Provider) DeleteIdentity(ctx context.Context, identity *unikornv1.Identity) error {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return err
		}

		return nil
	}

	// User never even created, so nothing else will have been.
	if openstackIdentity.Spec.UserID == nil {
		return nil
	}

	// Rescope to the user/project...
	compute, err := p.computeFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	if openstackIdentity.Spec.SSHKeyName != nil {
		if err := compute.DeleteKeypair(ctx, keyPairName); err != nil {
			if !gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
				return err
			}
		}
	}

	if openstackIdentity.Spec.ServerGroupID != nil {
		if err := compute.DeleteServerGroup(ctx, *openstackIdentity.Spec.ServerGroupID); err != nil {
			if !gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
				return err
			}
		}
	}

	identityService, err := p.openstack.identity(ctx)
	if err != nil {
		return err
	}

	if openstackIdentity.Spec.UserID != nil {
		if err := identityService.DeleteUser(ctx, *openstackIdentity.Spec.UserID); err != nil {
			if !gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
				return err
			}
		}
	}

	if openstackIdentity.Spec.ProjectID != nil {
		if err := identityService.DeleteProject(ctx, *openstackIdentity.Spec.ProjectID); err != nil {
			if !gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
				return err
			}
		}
	}

	if err := p.client.Delete(ctx, openstackIdentity); err != nil {
		return err
	}

	return nil
}

// gatewayIP selects .1 from our prefix.
func gatewayIP(prefix net.IPNet) string {
	ba := big.NewInt(0).SetBytes(prefix.IP)

	ip := net.IP(big.NewInt(0).Add(ba, big.NewInt(1)).Bytes())

	return ip.String()
}

// dhcpRange returns a range from the prefix starting after the reservation.
func dhcpRange(prefix net.IPNet, reservations *unikornv1.NetworkReservations) (string, string) {
	ba := big.NewInt(0).SetBytes(prefix.IP)

	// Start.
	startOffset := int64(1 << (32 - reservations.PrefixLength))

	bs := big.NewInt(0).Add(ba, big.NewInt(startOffset))

	// End.
	ones, bits := prefix.Mask.Size()
	size := 1 << (bits - ones)

	be := big.NewInt(0).Add(ba, big.NewInt(int64(size-2)))

	start := net.IP(bs.Bytes())
	end := net.IP(be.Bytes())

	return start.String(), end.String()
}

// storageRange returns a range from the prefix that comes from the requested
// reservation less any requested infrastructure-reserved space.
func storageRange(prefix net.IPNet, reservations *unikornv1.NetworkReservations) *unikornv1.AttachmentIPRange {
	dotStart := 2

	if reservations.ProviderReservedPrefixLength != nil {
		// Users can explicitly opt out of storage.
		if *reservations.ProviderReservedPrefixLength == reservations.PrefixLength {
			return nil
		}

		dotStart = 1 << (32 - *reservations.ProviderReservedPrefixLength)
	}

	ba := big.NewInt(0).SetBytes(prefix.IP)

	// Start.
	bs := big.NewInt(0).Add(ba, big.NewInt(int64(dotStart)))

	// End.
	dotEnd := 1 << (32 - reservations.PrefixLength)

	be := big.NewInt(0).Add(ba, big.NewInt(int64(dotEnd-1)))

	start := net.IP(bs.Bytes())
	end := net.IP(be.Bytes())

	return &unikornv1.AttachmentIPRange{
		Start: unikornv1core.IPv4Address{IP: start},
		End:   unikornv1core.IPv4Address{IP: end},
	}
}

func (p *Provider) reconcileNetwork(ctx context.Context, client NetworkInterface, network *unikornv1.Network) (*NetworkExt, error) {
	log := log.FromContext(ctx)

	result, err := client.GetNetwork(ctx, network)
	if err == nil {
		log.V(1).Info("L2 network already exists")

		network.Status.Openstack.NetworkID = ptr.To(result.ID)

		if result.NetworkType == "vlan" {
			vlanID, err := strconv.Atoi(result.SegmentationID)
			if err != nil {
				log.Error(err, "failed to parse SegmentationID string into VLAN ID", "id", result.SegmentationID)
			} else {
				network.Status.Openstack.VlanID = &vlanID
			}
		}

		return result, nil
	}

	if !errors.Is(err, coreerrors.ErrResourceNotFound) {
		return nil, err
	}

	log.V(1).Info("creating L2 network")

	var vlanID *int

	region, _ := p.openstack.regionSnapshot()

	if region.Spec.Openstack.Network.UseProviderNetworks() {
		v, err := p.vlanAllocator.Allocate(ctx, network.Name)
		if err != nil {
			log.Error(err, "failed to allocate VLAN", "networkID", network.Name, "allocation", region.StaticName())

			return nil, err
		}

		log.V(1).Info("allocated VLAN", "id", v)

		vlanID = &v
	}

	result, err = client.CreateNetwork(ctx, network, vlanID)
	if err != nil {
		log.Error(err, "failed to create OpenStack network", "networkID", network.Name, "vlanID", vlanID)
		// Keep any allocated VLAN assigned to this Network until delete. Returning
		// it to the pool on create failure can hand the same problematic VLAN to
		// another Network and spread the failure.

		return nil, err
	}

	network.Status.Openstack.NetworkID = ptr.To(result.ID)
	network.Status.Openstack.VlanID = vlanID

	return result, nil
}

func (p *Provider) reconcileSubnet(ctx context.Context, client SubnetInterface, network *unikornv1.Network, openstackNetwork *NetworkExt) (*subnets.Subnet, error) {
	log := log.FromContext(ctx)
	effectiveReservations := network.EffectiveReservations()

	var dnsNameservers []string

	if len(network.Spec.DNSNameservers) > 0 {
		dnsNameservers = make([]string, len(network.Spec.DNSNameservers))

		for i, ip := range network.Spec.DNSNameservers {
			dnsNameservers[i] = ip.String()
		}
	}

	routes := make([]subnets.HostRoute, len(network.Spec.Routes))

	for i, route := range network.Spec.Routes {
		routes[i].DestinationCIDR = route.Prefix.String()
		routes[i].NextHop = route.NextHop.String()
	}

	start, end := dhcpRange(network.Spec.Prefix.IPNet, effectiveReservations)

	allocationPools := []subnets.AllocationPool{
		{
			Start: start,
			End:   end,
		},
	}

	result, err := client.GetSubnet(ctx, network)
	if err != nil {
		if !errors.Is(err, coreerrors.ErrResourceNotFound) {
			return nil, err
		}

		log.V(1).Info("creating L3 subnet")

		result, err = client.CreateSubnet(ctx, network, openstackNetwork.ID, network.Spec.Prefix.String(), gatewayIP(network.Spec.Prefix.IPNet), dnsNameservers, routes, allocationPools)
		if err != nil {
			return nil, err
		}

		network.Status.Openstack.SubnetID = ptr.To(result.ID)
		network.Status.Openstack.StorageRange = storageRange(network.Spec.Prefix.IPNet, effectiveReservations)

		return result, nil
	}

	log.V(1).Info("Updating subnet")

	if _, err = client.UpdateSubnet(ctx, result.ID, dnsNameservers, routes); err != nil {
		return nil, err
	}

	network.Status.Openstack.SubnetID = ptr.To(result.ID)
	network.Status.Openstack.StorageRange = storageRange(network.Spec.Prefix.IPNet, effectiveReservations)

	return result, nil
}

func (p *Provider) reconcileRouter(ctx context.Context, client RouterInterface, network *unikornv1.Network) (*routers.Router, error) {
	log := log.FromContext(ctx)

	result, err := client.GetRouter(ctx, network)
	if err == nil {
		log.V(1).Info("router already exists")

		return result, nil
	}

	if !errors.Is(err, coreerrors.ErrResourceNotFound) {
		return nil, err
	}

	log.V(1).Info("creating router")

	result, err = client.CreateRouter(ctx, network)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func subnetInPorts(ports []ports.Port, subnetID string) bool {
	for _, port := range ports {
		for _, ip := range port.FixedIPs {
			if ip.SubnetID == subnetID {
				return true
			}
		}
	}

	return false
}

func (p *Provider) reconcileRouterInterface(ctx context.Context, client NetworkingInterface, router *routers.Router, subnet *subnets.Subnet) error {
	log := log.FromContext(ctx)

	ports, err := client.ListRouterPorts(ctx, router.ID)
	if err != nil {
		return err
	}

	if subnetInPorts(ports, subnet.ID) {
		log.V(1).Info("router has existing port on subnet")

		return nil
	}

	log.V(1).Info("adding subnet to router")

	if err := client.AddRouterInterface(ctx, router.ID, subnet.ID); err != nil {
		return err
	}

	return nil
}

// CreateNetwork creates a physical network for an identity.
func (p *Provider) CreateNetwork(ctx context.Context, identity *unikornv1.Identity, network *unikornv1.Network) error {
	network.Status.Openstack = &unikornv1.NetworkStatusOpenstack{}

	// NOTE: this is a privileged network client as it needs permissions
	// from the manager policy in order to create provider networks.
	networking, err := p.privilegedNetworkFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	openstackNetwork, err := p.reconcileNetwork(ctx, networking, network)
	if err != nil {
		return err
	}

	subnet, err := p.reconcileSubnet(ctx, networking, network, openstackNetwork)
	if err != nil {
		return err
	}

	router, err := p.reconcileRouter(ctx, networking, network)
	if err != nil {
		return err
	}

	if err := p.reconcileRouterInterface(ctx, networking, router, subnet); err != nil {
		return err
	}

	return nil
}

// openstackIdentityProvisioned reports whether the service principal has been
// realized far enough to build a project-scoped client. Finalizer ordering
// keeps the identity alive until its consumers are gone, so on delete paths a
// not-yet-provisioned identity (absent, or no project allocated) means nothing
// provider-side was ever created and the delete is a no-op. Never use this to
// gate create paths: there the missing project must surface as an error so the
// manager requeues.
//
// The project is the deliberate watermark: it is allocated before any provider
// resource (a VLAN, Neutron or Octavia object) can be created, so its absence
// is sufficient to prove nothing exists to delete. Later identity fields (user,
// password) gate specific clients and still surface their own errors past this
// point, which is correct: those deletes are idempotent and the manager
// requeues.
func (p *Provider) openstackIdentityProvisioned(ctx context.Context, identity *unikornv1.Identity) (bool, error) {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return false, nil
		}

		return false, err
	}

	return openstackIdentity.Spec.ProjectID != nil, nil
}

// DeleteNetwork deletes a physical network.
func (p *Provider) DeleteNetwork(ctx context.Context, identity *unikornv1.Identity, network *unikornv1.Network) error {
	provisioned, err := p.openstackIdentityProvisioned(ctx, identity)
	if err != nil {
		return err
	}

	if !provisioned {
		return nil
	}

	// NOTE: this is a privileged network client as it needs permissions
	// from the manager policy in order to see provider networks for VLAN
	// deallocation.
	networking, err := p.privilegedNetworkFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	return p.deleteNetwork(ctx, networking, network)
}

//nolint:cyclop
func (p *Provider) deleteNetwork(ctx context.Context, networking NetworkingInterface, network *unikornv1.Network) error {
	log := log.FromContext(ctx)

	openstackNetwork, err := networking.GetNetwork(ctx, network)
	if err != nil && !errors.Is(err, coreerrors.ErrResourceNotFound) {
		return err
	}

	subnet, err := networking.GetSubnet(ctx, network)
	if err != nil && !errors.Is(err, coreerrors.ErrResourceNotFound) {
		return err
	}

	router, err := networking.GetRouter(ctx, network)
	if err != nil && !errors.Is(err, coreerrors.ErrResourceNotFound) {
		return err
	}

	//nolint:nestif
	if router != nil {
		ports, err := networking.ListRouterPorts(ctx, router.ID)
		if err != nil {
			return err
		}

		if subnetInPorts(ports, subnet.ID) {
			log.V(1).Info("removing subnet from router")

			if err := networking.RemoveRouterInterface(ctx, router.ID, subnet.ID); err != nil {
				return err
			}
		}

		log.V(1).Info("deleting router")

		if err := networking.DeleteRouter(ctx, router.ID); err != nil {
			return err
		}
	}

	if subnet != nil {
		log.V(1).Info("deleting subnet")

		if err := networking.DeleteSubnet(ctx, subnet.ID); err != nil {
			return err
		}
	}

	if openstackNetwork != nil {
		log.V(1).Info("deleting network")

		if err := networking.DeleteNetwork(ctx, openstackNetwork.ID); err != nil {
			return err
		}
	}

	region, _ := p.openstack.regionSnapshot()
	if region.Spec.Openstack != nil && region.Spec.Openstack.Network.UseProviderNetworks() {
		// NetworkID is the allocator source of truth; status and OpenStack
		// resources can both be missing during delete.
		// NOTE: VLAN is freed after the Neutron network is confirmed deleted so
		// that a failed DeleteNetwork cannot leave the allocator out of sync with
		// OpenStack (which would cause VlanIdInUse on the next allocation).
		log.V(1).Info("freeing vlan", "networkID", network.Name)

		if err := p.vlanAllocator.FreeByNetworkID(ctx, network.Name); err != nil {
			return fmt.Errorf("%w: failed to free vlan", err)
		}
	}

	return nil
}

// securityGroupRulePortRange expands a security group port into a start-end range as
// required by Neutron.
// TODO: surely we can do this checking in validating admission policies...
func securityGroupRulePortRange(port *unikornv1.SecurityGroupRulePort) (int, int, error) {
	if port == nil {
		return 0, 0, nil
	}

	if port.Number != nil {
		return *port.Number, *port.Number, nil
	}

	if port.Range != nil {
		return port.Range.Start, port.Range.End, nil
	}

	return 0, 0, fmt.Errorf("%w: security group rule contains no port number or range", coreerrors.ErrConsistency)
}

// generateDirection takes our API and converts it to OpenStack's.
func generateDirection(in unikornv1.SecurityGroupRuleDirection) rules.RuleDirection {
	return rules.RuleDirection(in)
}

// convertDirection takes OpenStack's API and converts it into ours.
// NOTE: the gophercloud results API isn't type safe for some reason.
func convertDirection(in string) unikornv1.SecurityGroupRuleDirection {
	return unikornv1.SecurityGroupRuleDirection(in)
}

// generateProtocol takes our API and converts it to OpenStack's.
func generateProtocol(in unikornv1.SecurityGroupRuleProtocol) rules.RuleProtocol {
	if in == unikornv1.Any {
		return rules.ProtocolAny
	}

	return rules.RuleProtocol(in)
}

// convertProtocol takes OpenStack's API and converts it into ours.
// NOTE: the gophercloud results API isn't type safe for some reason.
func convertProtocol(in string) unikornv1.SecurityGroupRuleProtocol {
	if in == string(rules.ProtocolAny) {
		return unikornv1.Any
	}

	return unikornv1.SecurityGroupRuleProtocol(in)
}

// securityGroupRuleID generates a deterministic, but unique, ID for a security group rule.
func securityGroupRuleID(direction unikornv1.SecurityGroupRuleDirection, protocol unikornv1.SecurityGroupRuleProtocol, startPort, endPort int, prefix string) string {
	// Prefix may be empty, but for debug purposes give it a name so it's not confusing
	// when debugging this.
	if prefix == "" {
		prefix = "0.0.0.0/0"
	}

	return fmt.Sprintf("%s,%s,%d-%d,%s", direction, protocol, startPort, endPort, prefix)
}

// securityGroupRuleIDFromSecurityGroupRule generates a deterministic, but unique, ID for a security group rule.
func securityGroupRuleIDFromSecurityGroupRule(rule *unikornv1.SecurityGroupRule) (string, error) {
	// The data is a tuple of direction, protocol, port and prefix.
	start, end, err := securityGroupRulePortRange(rule.Port)
	if err != nil {
		return "", err
	}

	var prefix string

	if rule.CIDR != nil {
		prefix = rule.CIDR.String()
	}

	return securityGroupRuleID(rule.Direction, rule.Protocol, start, end, prefix), nil
}

// securityGroupRuleIDFromOpenstackSecurityGroupRule generates a deterministic, but unique, ID for a security group rule.
func securityGroupRuleIDFromOpenstackSecurityGroupRule(rule *rules.SecGroupRule) string {
	direction := convertDirection(rule.Direction)
	protocol := convertProtocol(rule.Protocol)

	return securityGroupRuleID(direction, protocol, rule.PortRangeMin, rule.PortRangeMax, rule.RemoteIPPrefix)
}

func listOpenstackSecurityGroupRules(ctx context.Context, client SecurityGroupInterface, securityGroupID string) (map[string]*rules.SecGroupRule, error) {
	resources, err := client.ListSecurityGroupRules(ctx, securityGroupID)
	if err != nil {
		return nil, err
	}

	out := map[string]*rules.SecGroupRule{}

	for i := range resources {
		rule := &resources[i]

		out[securityGroupRuleIDFromOpenstackSecurityGroupRule(rule)] = rule
	}

	return out, nil
}

// generateSecurityGroupRules maps all rules to a unique ID.
func generateSecurityGroupRules(securityGroup *unikornv1.SecurityGroup) (map[string]*unikornv1.SecurityGroupRule, error) {
	out := map[string]*unikornv1.SecurityGroupRule{
		// Secret hidden rule that comes by default, don't delete it by accident!
		securityGroupRuleID(unikornv1.Egress, unikornv1.Any, 0, 0, ""): nil,
	}

	for i := range securityGroup.Spec.Rules {
		rule := &securityGroup.Spec.Rules[i]

		id, err := securityGroupRuleIDFromSecurityGroupRule(rule)
		if err != nil {
			return nil, err
		}

		out[id] = rule
	}

	return out, nil
}

// reconcileSecurityGroupRules generates two sets of IDs from existing and requested security group
// rules, does a boolean difference, and uses that to either create or delete rules from the security
// group.
//
//nolint:cyclop
func (p *Provider) reconcileSecurityGroupRules(ctx context.Context, client SecurityGroupInterface, securityGroup *unikornv1.SecurityGroup, openstackSecurityGroup *groups.SecGroup) error {
	log := log.FromContext(ctx)

	existing, err := listOpenstackSecurityGroupRules(ctx, client, openstackSecurityGroup.ID)
	if err != nil {
		return err
	}

	requested, err := generateSecurityGroupRules(securityGroup)
	if err != nil {
		return err
	}

	// Anything that exists but has not been requested needs deleting.
	for id := range existing {
		if _, ok := requested[id]; ok {
			log.V(1).Info("security group rule already exists", "rule", id, "securitygroupid", openstackSecurityGroup.ID, "securitygroupruleid", existing[id].ID)
			continue
		}

		log.V(1).Info("deleting security group rule", "rule", id, "securitygroupid", openstackSecurityGroup.ID, "securitygroupruleid", existing[id].ID)

		if err := client.DeleteSecurityGroupRule(ctx, openstackSecurityGroup.ID, existing[id].ID); err != nil {
			return err
		}
	}

	// Anything that doesn't exist but has been rquested needs creating.
	for id := range requested {
		if _, ok := existing[id]; ok {
			continue
		}

		log.V(1).Info("creating security group rule", "rule", id, "securitygroupid", openstackSecurityGroup.ID)

		rule := requested[id]

		direction := generateDirection(rule.Direction)
		protocol := generateProtocol(rule.Protocol)

		portStart, portEnd, err := securityGroupRulePortRange(rule.Port)
		if err != nil {
			return err
		}

		var prefix string

		if rule.CIDR != nil {
			prefix = rule.CIDR.String()
		}

		if _, err := client.CreateSecurityGroupRule(ctx, openstackSecurityGroup.ID, direction, protocol, portStart, portEnd, prefix); err != nil {
			return err
		}
	}

	return nil
}

func (p *Provider) reconcileSecurityGroup(ctx context.Context, client SecurityGroupInterface, securityGroup *unikornv1.SecurityGroup) (*groups.SecGroup, error) {
	log := log.FromContext(ctx)

	result, err := client.GetSecurityGroup(ctx, securityGroup)
	if err == nil {
		log.V(1).Info("security group already exists")

		return result, nil
	}

	if !errors.Is(err, coreerrors.ErrResourceNotFound) {
		return nil, err
	}

	log.V(1).Info("creating security group")

	result, err = client.CreateSecurityGroup(ctx, securityGroup)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// CreateSecurityGroup creates a new security group.
func (p *Provider) CreateSecurityGroup(ctx context.Context, identity *unikornv1.Identity, securityGroup *unikornv1.SecurityGroup) error {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return err
	}

	region, credentials := p.openstack.regionSnapshot()

	providerClient := NewPasswordProvider(region.Spec.Openstack.Endpoint, credentials.userID, credentials.password, *openstackIdentity.Spec.ProjectID)

	networking, err := NewNetworkClient(ctx, providerClient, region.Spec.Openstack.Network)
	if err != nil {
		return err
	}

	openstackSecurityGroup, err := p.reconcileSecurityGroup(ctx, networking, securityGroup)
	if err != nil {
		return err
	}

	if err := p.reconcileSecurityGroupRules(ctx, networking, securityGroup, openstackSecurityGroup); err != nil {
		return err
	}

	return nil
}

// DeleteSecurityGroup deletes a security group.
func (p *Provider) DeleteSecurityGroup(ctx context.Context, identity *unikornv1.Identity, securityGroup *unikornv1.SecurityGroup) error {
	log := log.FromContext(ctx)

	provisioned, err := p.openstackIdentityProvisioned(ctx, identity)
	if err != nil {
		return err
	}

	if !provisioned {
		return nil
	}

	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return err
	}

	region, credentials := p.openstack.regionSnapshot()

	providerClient := NewPasswordProvider(region.Spec.Openstack.Endpoint, credentials.userID, credentials.password, *openstackIdentity.Spec.ProjectID)

	networking, err := NewNetworkClient(ctx, providerClient, region.Spec.Openstack.Network)
	if err != nil {
		return err
	}

	openstackSecurityGroup, err := networking.GetSecurityGroup(ctx, securityGroup)
	if err != nil && !errors.Is(err, coreerrors.ErrResourceNotFound) {
		return err
	}

	if openstackSecurityGroup != nil {
		log.V(1).Info("deleting security group")

		if err := networking.DeleteSecurityGroup(ctx, openstackSecurityGroup.ID); err != nil {
			return err
		}
	}

	return nil
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
		// Nova records the failure cause (e.g. a scheduler "No valid host was
		// found") on the server fault, visible to the owner; surface it so the
		// condition explains the error without cloud-side log access.
		message := "server is in an error state"
		if server.Fault.Message != "" {
			message += ": " + server.Fault.Message
		}

		return corev1.ConditionFalse, unikornv1core.ConditionReasonErrored, message
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

// novaServerAddress is a single entry in a Nova server's `addresses` map. It
// exists only because gophercloud's servers.Address type omits the port MAC
// that Nova reports under OS-EXT-IPS-MAC:mac_addr, so we decode the addresses
// into this to read the MAC with a real type rather than untyped assertions.
type novaServerAddress struct {
	//nolint:tagliatelle // Nova API field name, fixed by the OpenStack compute API.
	MACAddress string `json:"OS-EXT-IPS-MAC:mac_addr"`
}

// serverMACAddress extracts the primary interface MAC from a Nova server
// response. gophercloud decodes `addresses` into an untyped map keyed by
// OpenStack network name, so we round-trip it through JSON into typed entries
// and read the MAC from the server's primary network (Spec.Networks[0]) rather
// than an arbitrary map entry. "" means Nova has not (yet) reported a MAC for
// that network.
func serverMACAddress(server *unikornv1.Server, openstackserver *servers.Server) (string, error) {
	if len(server.Spec.Networks) == 0 {
		return "", nil
	}

	raw, err := json.Marshal(openstackserver.Addresses)
	if err != nil {
		return "", err
	}

	addresses := map[string][]novaServerAddress{}
	if err := json.Unmarshal(raw, &addresses); err != nil {
		return "", err
	}

	for _, entry := range addresses[networkNameForID(server.Spec.Networks[0].ID)] {
		if entry.MACAddress != "" {
			return entry.MACAddress, nil
		}
	}

	return "", nil
}

// setServerMACAddress records the server's MAC address from a Nova response.
//
// The monitor is the sole owner of Status.MACAddress: the reconciler goes to
// sleep once the server is provisioned, and for baremetal Ironic rebinds the
// port to the real NIC MAC asynchronously, so only a live poll can observe the
// final value. Nova guarantees the port MAC is bound by ACTIVE for VMs and
// baremetal alike, giving one code path for both.
//
// A MAC is only ever written, never cleared: gating on ACTIVE and skipping an
// empty read means a transient port-read miss can never unset a value we hold,
// while an unconditional write of a valid MAC self-heals any drift (the
// monitor's optimistic status PATCH makes a same-value write a harmless no-op).
func setServerMACAddress(ctx context.Context, server *unikornv1.Server, openstackserver *servers.Server) {
	if openstackserver == nil || openstackserver.Status != "ACTIVE" {
		return
	}

	mac, err := serverMACAddress(server, openstackserver)
	if err != nil {
		log.FromContext(ctx).Error(err, "failed to decode server addresses for MAC", "server", server.Name)

		return
	}

	if mac == "" {
		return
	}

	server.Status.MACAddress = &mac
}

// buildPhase picks the right Phase for a server Nova reports as BUILD. VMs
// and baremetal lookups that failed fall back to Building (the honest "we
// don't know more than Nova does" answer); a successful Ironic lookup
// further distinguishes Queued (pre-deploy) from Building (deploy underway).
func buildPhase(ironicNode *nodes.Node) unikornv1.InstanceLifecyclePhase {
	if ironicNode == nil {
		return unikornv1.InstanceLifecyclePhaseBuilding
	}

	return baremetalBuildPhase(ironicNode)
}

// https://docs.openstack.org/api-guide/compute/server_concepts.html
// ironicNode is the Ironic node lookup result for a baremetal server in Nova
// BUILD. It is nil for VMs, non-BUILD states, non-baremetal flavors, or when
// the Ironic lookup failed (graceful degradation).
//
// BUILD-window branch. Breaking it up further would scatter Phase derivation.
//
//nolint:cyclop // Fan-out matches OpenStack's PowerState enum surface plus the BUILD branch that consults Ironic via buildPhase; collapsing it would scatter Phase derivation across helpers.
func setServerPhase(ctx context.Context, server *unikornv1.Server, openstackserver *servers.Server, ironicNode *nodes.Node) {
	// Default to `Pending` if the phase is not already set. This should only happen to old servers created before we had phases.
	if server.Status.Phase == "" {
		server.Status.Phase = unikornv1.InstanceLifecyclePhasePending
	}

	if openstackserver == nil {
		return
	}

	// Both timestamps are set unconditionally (not gated on power state): Nova
	// populates created and launched_at on every server response once set, and
	// neither value changes after the server's first boot.
	if !openstackserver.Created.IsZero() {
		t := metav1.NewTime(openstackserver.Created)
		server.Status.ScheduledAt = &t
	}

	if !openstackserver.LaunchedAt.IsZero() {
		t := metav1.NewTime(openstackserver.LaunchedAt)
		server.Status.LaunchedAt = &t

		// ProvisionedAt is a write-once latch recording that the server has booted
		// at least once. It mirrors the same Nova launched_at signal as LaunchedAt
		// (set here, ahead of the BUILD early-return and independent of power
		// state, so it fires for VMs and baremetal alike) but, unlike LaunchedAt,
		// it is never cleared: not by the provider-create retry reset, nor by a
		// re-reconcile against a flaky provider. The bounded delete-and-retry guard
		// keys off it so a server that has booted is never rebuilt, which would
		// destroy data.
		if server.Status.ProvisionedAt == nil {
			server.Status.ProvisionedAt = &t
		}
	}

	// Nova BUILD is the window where the live monitor refines the lifecycle
	// view beyond what PowerState alone can express. PowerState is NOSTATE
	// throughout BUILD, so we look at server.Status + the optional Ironic
	// state to pick Queued vs Building.
	if openstackserver.Status == "BUILD" {
		server.Status.Phase = buildPhase(ironicNode)

		return
	}

	switch openstackserver.PowerState {
	case servers.NOSTATE:
		// No state information available. We will keep the phase as it is.
	case servers.RUNNING:
		server.Status.Phase = unikornv1.InstanceLifecyclePhaseRunning
	case servers.SHUTDOWN:
		// TODO: Stopping is only ever written by the handler in response to a
		// user-initiated stop. If a monitor poll lands while OpenStack is
		// already reporting SHUTOFF/SHUTDOWN (e.g. the user stopped via the
		// OpenStack dashboard rather than the platform API, or the platform
		// missed the transient Stopping window), this flips Stopping → Stopped
		// without ever observing the in-flight state on Phase. Pre-existing
		// behaviour, follow-up work in a later PR; leaving the mapping as-is
		// here to keep the INST-921 stack scoped.
		server.Status.Phase = unikornv1.InstanceLifecyclePhaseStopped
	case servers.CRASHED:
		// REVIEW_ME: What should we do when the server crashes?
	case servers.PAUSED, servers.SUSPENDED:
		log.FromContext(ctx).Info("caught unsupported server power state", "powerState", openstackserver.PowerState.String())
	}
}

func (p *Provider) lookupNetwork(ctx context.Context, networks NetworkInterface, namespace, id string) (*NetworkExt, error) {
	network := &unikornv1.Network{}

	if err := p.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: id}, network); err != nil {
		return nil, err
	}

	openstackNetwork, err := networks.GetNetwork(ctx, network)
	if err != nil {
		return nil, err
	}

	return openstackNetwork, nil
}

func (p *Provider) lookupSecurityGroup(ctx context.Context, securityGroups SecurityGroupInterface, namespace, id string) (*groups.SecGroup, error) {
	securityGroup := &unikornv1.SecurityGroup{}

	if err := p.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: id}, securityGroup); err != nil {
		return nil, err
	}

	openstackSecurityGroup, err := securityGroups.GetSecurityGroup(ctx, securityGroup)
	if err != nil {
		return nil, err
	}

	return openstackSecurityGroup, nil
}

func (p *Provider) reconcileServerPort(ctx context.Context, client NetworkingInterface, server *unikornv1.Server) (*ports.Port, error) {
	log := log.FromContext(ctx)

	network, err := p.lookupNetwork(ctx, client, server.Namespace, server.Spec.Networks[0].ID)
	if err != nil {
		return nil, err
	}

	securityGroupIDs := make([]string, len(server.Spec.SecurityGroups))

	for i, s := range server.Spec.SecurityGroups {
		securityGroup, err := p.lookupSecurityGroup(ctx, client, server.Namespace, s.ID)
		if err != nil {
			return nil, err
		}

		securityGroupIDs[i] = securityGroup.ID
	}

	addressPairs := make([]ports.AddressPair, len(server.Spec.Networks[0].AllowedAddressPairs))

	for i, pair := range server.Spec.Networks[0].AllowedAddressPairs {
		addressPairs[i] = ports.AddressPair{
			IPAddress:  pair.CIDR.String(),
			MACAddress: pair.MACAddress,
		}
	}

	port, err := client.GetServerPort(ctx, server)
	if err != nil {
		if !errors.Is(err, coreerrors.ErrResourceNotFound) {
			return nil, err
		}

		log.V(1).Info("creating port")

		port, err = client.CreateServerPort(ctx, server, network.ID, securityGroupIDs, addressPairs)
		if err != nil {
			return nil, err
		}

		server.Status.PrivateIP = ptr.To(port.FixedIPs[0].IPAddress)

		return port, nil
	}

	// TODO: we should only do this when the security groups or address pairs differ.
	log.V(1).Info("updating port")

	port, err = client.UpdatePort(ctx, port.ID, securityGroupIDs, addressPairs)
	if err != nil {
		return nil, err
	}

	server.Status.PrivateIP = ptr.To(port.FixedIPs[0].IPAddress)

	return port, nil
}

func (p *Provider) reconcileFloatingIP(ctx context.Context, client FloatingIPInterface, server *unikornv1.Server, port *ports.Port) error {
	log := log.FromContext(ctx)

	enabled := server.Spec.PublicIPAllocation != nil && server.Spec.PublicIPAllocation.Enabled

	server.Status.PublicIP = nil

	floatingip, err := client.GetFloatingIP(ctx, port.ID)
	if err == nil {
		if enabled {
			log.V(1).Info("floating ip already exists")

			server.Status.PublicIP = ptr.To(floatingip.FloatingIP)

			return nil
		}

		log.V(1).Info("deleting floating ip")

		if err := client.DeleteFloatingIP(ctx, floatingip.ID); err != nil {
			return err
		}

		return nil
	}

	if !errors.Is(err, coreerrors.ErrResourceNotFound) {
		return err
	}

	if !enabled {
		return nil
	}

	log.V(1).Info("creating floating ip")

	floatingip, err = client.CreateFloatingIP(ctx, port.ID)
	if err != nil {
		return err
	}

	server.Status.PublicIP = ptr.To(floatingip.FloatingIP)

	return nil
}

// reconcileLoadBalancerFloatingIP converges the floating IP attached to the
// Octavia VIP port to match loadBalancer.Spec.PublicIP. The VIP port is
// owned by Octavia, not a Neutron port we created ourselves.
func (p *Provider) reconcileLoadBalancerFloatingIP(ctx context.Context, client FloatingIPInterface, loadBalancer *unikornv1.LoadBalancer, vipPortID string) error {
	log := log.FromContext(ctx)

	enabled := loadBalancer.Spec.PublicIP

	loadBalancer.Status.PublicIP = nil

	floatingip, err := client.GetFloatingIP(ctx, vipPortID)
	if err == nil {
		if enabled {
			log.V(1).Info("floating ip already exists")

			addr, err := parseIPv4Address(floatingip.FloatingIP)
			if err != nil {
				return fmt.Errorf("load balancer %s public IP: %w", loadBalancer.Name, err)
			}

			loadBalancer.Status.PublicIP = addr

			return nil
		}

		log.V(1).Info("deleting floating ip")

		if err := client.DeleteFloatingIP(ctx, floatingip.ID); err != nil {
			return err
		}

		return nil
	}

	if !errors.Is(err, coreerrors.ErrResourceNotFound) {
		return err
	}

	if !enabled {
		return nil
	}

	log.V(1).Info("creating floating ip")

	floatingip, err = client.CreateFloatingIP(ctx, vipPortID)
	if err != nil {
		return err
	}

	addr, err := parseIPv4Address(floatingip.FloatingIP)
	if err != nil {
		return fmt.Errorf("load balancer %s public IP: %w", loadBalancer.Name, err)
	}

	loadBalancer.Status.PublicIP = addr

	return nil
}

func (p *Provider) reconcileServer(ctx context.Context, client ServerInterface, server *unikornv1.Server, port *ports.Port, keyName string, preflight serverCreatePreflight) (*servers.Server, error) {
	log := log.FromContext(ctx)

	openstackServer, err := client.GetServer(ctx, server)
	if err == nil {
		log.V(1).Info("server already exists")

		return openstackServer, nil
	}

	networks := []servers.Network{
		{
			Port: port.ID,
			UUID: port.NetworkID,
		},
	}

	// Legacy camelCase keys — frozen for backwards compat.
	systemMetadata := map[string]string{
		"serverID":       server.Name,
		"organizationID": server.Labels[coreconstants.OrganizationLabel],
		"projectID":      server.Labels[coreconstants.ProjectLabel],
		"regionID":       server.Labels[constants.RegionLabel],
	}
	// New namespaced duplicates — upgrade path for new consumers.
	namespacedSystemMetadata := map[string]string{
		"region:server_id":         server.Name,
		"identity:organization_id": server.Labels[coreconstants.OrganizationLabel],
		"identity:project_id":      server.Labels[coreconstants.ProjectLabel],
		"region:region_id":         server.Labels[constants.RegionLabel],
	}

	metadata := make(map[string]string, len(server.Spec.Tags)+len(systemMetadata)+len(namespacedSystemMetadata))

	for _, tag := range server.Spec.Tags {
		if k, ok := metadataKey(tag.Name); ok {
			metadata[k] = tag.Value
		}
	}

	// System keys written last — unconditionally overwrite any colliding user tag.
	for k, v := range namespacedSystemMetadata {
		metadata[k] = v
	}

	for k, v := range systemMetadata {
		metadata[k] = v
	}

	if preflight != nil {
		if err := preflight(ctx, server); err != nil {
			return nil, err
		}
	}

	log.V(1).Info("creating server")

	openstackServer, err = client.CreateServer(ctx, server, keyName, networks, nil, metadata)
	if err != nil {
		return nil, err
	}

	setServerHealthStatus(server, openstackServer)
	// No Ironic lookup at create time — the live monitor's UpdateServerState
	// refines Phase from observed Ironic state on each poll.
	setServerPhase(ctx, server, openstackServer, nil)

	return openstackServer, nil
}

// CreateServer creates or updates a server.
func serverForCreate(server *unikornv1.Server, options *types.ServerCreateOptions) *unikornv1.Server {
	if options == nil || options.UserData == nil {
		return server
	}

	serverForCreate := server.DeepCopy()
	serverForCreate.Spec.UserData = options.UserData

	return serverForCreate
}

func (p *Provider) CreateServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, options *types.ServerCreateOptions) error {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return err
	}

	serverForCreate := serverForCreate(server, options)

	networking, err := p.networkFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	port, err := p.reconcileServerPort(ctx, networking, server)
	if err != nil {
		return err
	}

	if err := p.reconcileFloatingIP(ctx, networking, server, port); err != nil {
		return err
	}

	compute, err := p.computeForServerCreate(ctx, identity, server)
	if err != nil {
		return err
	}

	if _, err := p.reconcileServer(ctx, compute, serverForCreate, port, resolveServerKeyName(server, openstackIdentity), p.serverCreatePlacementPreflight(identity, compute)); err != nil {
		return err
	}

	return nil
}

func resolveServerKeyName(server *unikornv1.Server, identity *unikornv1.OpenstackIdentity) string {
	if !server.UsesIdentitySSHKey() {
		// gophercloud omits the empty key_name field, which disables legacy Nova key injection
		// for servers that do not use the identity keypair.
		return ""
	}

	if identity.Spec.SSHKeyName == nil {
		return ""
	}

	return *identity.Spec.SSHKeyName
}

//nolint:cyclop
func (p *Provider) DeleteServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error {
	log := log.FromContext(ctx)

	provisioned, err := p.openstackIdentityProvisioned(ctx, identity)
	if err != nil {
		return err
	}

	if !provisioned {
		return nil
	}

	compute, err := p.computeFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	openstackServer, err := compute.GetServer(ctx, server)
	if err != nil && !errors.Is(err, coreerrors.ErrResourceNotFound) {
		return err
	}

	if openstackServer != nil {
		log.V(1).Info("deleting server")

		if err := compute.DeleteServer(ctx, openstackServer.ID); err != nil {
			return err
		}
	}

	networking, err := p.networkFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	port, err := networking.GetServerPort(ctx, server)
	if err != nil && !errors.Is(err, coreerrors.ErrResourceNotFound) {
		return err
	}

	//nolint:nestif
	if port != nil {
		floatingip, err := networking.GetFloatingIP(ctx, port.ID)
		if err != nil && !errors.Is(err, coreerrors.ErrResourceNotFound) {
			return err
		}

		if floatingip != nil {
			log.V(1).Info("deleting floating ip")

			if err := networking.DeleteFloatingIP(ctx, floatingip.ID); err != nil {
				return err
			}
		}

		log.V(1).Info("deleting port")

		if err := networking.DeletePort(ctx, port.ID); err != nil {
			return err
		}
	}

	return nil
}

func (p *Provider) RebootServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, hard bool) error {
	compute, err := p.computeFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	openstackServer, err := compute.GetServer(ctx, server)
	if err != nil {
		return err
	}

	if err := compute.RebootServer(ctx, openstackServer.ID, hard); err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return fmt.Errorf("%w: no server found with ID %s", coreerrors.ErrResourceNotFound, openstackServer.ID)
		}

		if gophercloud.ResponseCodeIs(err, http.StatusConflict) {
			return fmt.Errorf("%w: server %s cannot be rebooted in its current state", coreerrors.ErrConflict, openstackServer.ID)
		}

		return err
	}

	return nil
}

func (p *Provider) StartServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error {
	compute, err := p.computeFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	openstackServer, err := compute.GetServer(ctx, server)
	if err != nil {
		return err
	}

	if err := compute.StartServer(ctx, openstackServer.ID); err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return fmt.Errorf("%w: no server found with ID %s", coreerrors.ErrResourceNotFound, openstackServer.ID)
		}

		if gophercloud.ResponseCodeIs(err, http.StatusConflict) {
			return fmt.Errorf("%w: server %s cannot be started in its current state", coreerrors.ErrConflict, openstackServer.ID)
		}

		return err
	}

	return nil
}

func (p *Provider) StopServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error {
	compute, err := p.computeFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	openstackServer, err := compute.GetServer(ctx, server)
	if err != nil {
		return err
	}

	if err := compute.StopServer(ctx, openstackServer.ID); err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return fmt.Errorf("%w: no server found with ID %s", coreerrors.ErrResourceNotFound, openstackServer.ID)
		}

		if gophercloud.ResponseCodeIs(err, http.StatusConflict) {
			return fmt.Errorf("%w: server %s cannot be stopped in its current state", coreerrors.ErrConflict, openstackServer.ID)
		}

		return err
	}

	return nil
}

// UpdateServerState checks a server's state and modifies the resource in place.
func (p *Provider) UpdateServerState(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error {
	compute, err := p.computeFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	return p.updateServerStateWithClients(ctx, identity, server, compute, p.baremetalForPhase)
}

// lookupIronicNodeForPhase fetches the bound Ironic node for a baremetal
// server in Nova BUILD so setServerPhase can distinguish Queued (pre-deploy)
// from Building (active deploy). All failure modes log and return nil;
// setServerPhase then falls back to Building, matching the VM default — the
// monitor must never error on a missing or unreachable Ironic.
func (p *Provider) lookupIronicNodeForPhase(
	ctx context.Context,
	identity *unikornv1.Identity,
	server *unikornv1.Server,
	openstackServer *servers.Server,
	baremetalForPhase func(context.Context, *unikornv1.Identity) (BaremetalInterface, error),
) *nodes.Node {
	baremetalClient, err := baremetalForPhase(ctx, identity)
	if err != nil {
		log.FromContext(ctx).Error(err, "failed to create ironic client for server phase derivation", "server", server.Name, "flavor", server.Spec.FlavorID, "instance_uuid", openstackServer.ID)

		return nil
	}

	node, err := baremetalClient.GetNodeByInstanceUUID(ctx, openstackServer.ID)
	if err != nil {
		log.FromContext(ctx).Error(err, "failed to get ironic node for server", "instance_uuid", openstackServer.ID)

		return nil
	}

	return node
}

func (p *Provider) updateServerStateWithClients(
	ctx context.Context,
	identity *unikornv1.Identity,
	server *unikornv1.Server,
	compute ComputeInterface,
	baremetalForPhase func(context.Context, *unikornv1.Identity) (BaremetalInterface, error),
) error {
	openstackServer, err := compute.GetServer(ctx, server)
	if err != nil {
		return err
	}

	setServerHealthStatus(server, openstackServer)
	setServerMACAddress(ctx, server, openstackServer)

	region, _ := p.openstack.regionSnapshot()
	baremetal := isBaremetalFlavor(region, server.Spec.FlavorID)

	var ironicNode *nodes.Node

	if shouldCallIronicForPhase(*openstackServer, baremetal) {
		ironicNode = p.lookupIronicNodeForPhase(ctx, identity, server, openstackServer, baremetalForPhase)
	}

	setServerPhase(ctx, server, openstackServer, ironicNode)

	return nil
}

func (p *Provider) CreateConsoleSession(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) (string, error) {
	compute, err := p.computeFromServicePrincipal(ctx, identity)
	if err != nil {
		return "", err
	}

	openstackServer, err := compute.GetServer(ctx, server)
	if err != nil {
		return "", err
	}

	result, err := compute.CreateRemoteConsole(ctx, openstackServer.ID)
	if err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return "", fmt.Errorf("%w: no server found with ID %s", coreerrors.ErrResourceNotFound, openstackServer.ID)
		}

		if gophercloud.ResponseCodeIs(err, http.StatusConflict) {
			return "", fmt.Errorf("%w: server %s cannot be accessed in its current state", coreerrors.ErrConflict, openstackServer.ID)
		}

		return "", err
	}

	return result.URL, nil
}

func (p *Provider) GetConsoleOutput(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, length *int) (string, error) {
	compute, err := p.computeFromServicePrincipal(ctx, identity)
	if err != nil {
		return "", err
	}

	openstackServer, err := compute.GetServer(ctx, server)
	if err != nil {
		return "", err
	}

	result, err := compute.ShowConsoleOutput(ctx, openstackServer.ID, length)
	if err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return "", fmt.Errorf("%w: no server found with ID %s", coreerrors.ErrResourceNotFound, openstackServer.ID)
		}

		if gophercloud.ResponseCodeIs(err, http.StatusConflict) {
			return "", fmt.Errorf("%w: console output of server %s cannot be retrieved in its current state", coreerrors.ErrConflict, openstackServer.ID)
		}

		return "", err
	}

	return result, nil
}

// CreateSnapshot creates a new image from an existing server.
//
//nolint:cyclop
func (p *Provider) CreateSnapshot(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, image *types.Image) (*types.Image, error) {
	if p.imageCache == nil {
		return nil, fmt.Errorf("%w: image caching is disabled", coreerrors.ErrResourceNotFound)
	}

	log := log.FromContext(ctx)

	compute, err := p.computeFromServicePrincipal(ctx, identity)
	if err != nil {
		return nil, err
	}

	// make sure that the input image is scoped to an organization, because we're going to
	// make this image public in a minute.
	if image.OrganizationID == nil {
		return nil, fmt.Errorf("%w: image not scoped to an organization", coreerrors.ErrConsistency)
	}

	openstackServer, err := compute.GetServer(ctx, server)
	if err != nil {
		return nil, err
	}

	metadata, err := createImageMetadata(image)
	if err != nil {
		return nil, err
	}

	// Save the identity this snapshot belongs to, and implicitly the project,
	// which will be required for deletion.
	metadata[identityIDLabel] = identity.Name

	opts := &servers.CreateImageOpts{
		Name:     image.Name,
		Metadata: metadata,
	}

	imageID, err := compute.CreateImageFromServer(ctx, openstackServer.ID, opts)
	if err != nil {
		return nil, interpretGophercloudError(err)
	}

	// The snapshot is created in the project, and with the OpenStack identity, of the server.
	// To make it public, I need a client using that identity.
	imageService, err := p.privilegedImageFromServicePrincipal(ctx, identity)
	if err != nil {
		return nil, err
	}

	publishOpts := images.UpdateOpts{
		images.UpdateVisibility{
			Visibility: images.ImageVisibilityPublic,
		},
	}

	updatedImage, err := imageService.UpdateImage(ctx, imageID, publishOpts)
	if err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return nil, fmt.Errorf("image %w", coreerrors.ErrResourceNotFound)
		}

		// Make a best effort to delete the image to free up resources.
		if err := imageService.DeleteImage(ctx, imageID); err != nil {
			log.Error(err, "failed to delete failed image, please manually remove me", "imageID", imageID)
		}

		return nil, err
	}

	imageSnapshot, err := convertImage(updatedImage)
	if err != nil {
		return nil, err
	}

	// Snapshot creation follows the same cache-overlay path as direct image creation,
	// but the seeded entry should come from the authoritative OpenStack response rather
	// than the request-shaped provider image.
	if err := p.imageCache.InsertIfAbsent(imageSnapshot); err != nil {
		return nil, err
	}

	return imageSnapshot, nil
}

func interpretGophercloudError(err error) error {
	if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
		return fmt.Errorf("server %w", coreerrors.ErrResourceNotFound)
	}

	if gophercloud.ResponseCodeIs(err, http.StatusConflict) {
		return fmt.Errorf("server %w", coreerrors.ErrConflict) // FIXME: or unprocessable?
	}

	return err
}

// loadBalancerNetwork resolves the Network CRD referenced by the load balancer's
// constants.NetworkLabel.
func (p *Provider) loadBalancerNetwork(ctx context.Context, loadBalancer *unikornv1.LoadBalancer) (*unikornv1.Network, error) {
	networkID, ok := loadBalancer.Labels[constants.NetworkLabel]
	if !ok || networkID == "" {
		return nil, fmt.Errorf("%w: load balancer %s missing network label", coreerrors.ErrConsistency, loadBalancer.Name)
	}

	network := &unikornv1.Network{}
	if err := p.client.Get(ctx, client.ObjectKey{Namespace: loadBalancer.Namespace, Name: networkID}, network); err != nil {
		return nil, fmt.Errorf("%w: get network %s for load balancer %s: %w", coreerrors.ErrConsistency, networkID, loadBalancer.Name, err)
	}

	return network, nil
}

// classifyOctaviaStatus maps an Octavia ProvisioningStatus to a reconcile
// outcome:
//   - "ACTIVE": nil (proceed)
//   - "PENDING_*": provisioners.ErrYield (transient; requeue)
//   - anything else (incl. ""): wrapped coreerrors.ErrConsistency (terminal)
func classifyOctaviaStatus(kind, name, status string) error {
	switch status {
	case "ACTIVE":
		return nil
	case "PENDING_CREATE", "PENDING_UPDATE", "PENDING_DELETE":
		return provisioners.ErrYield
	default:
		return fmt.Errorf("%w: octavia %s %q in unexpected state %q", coreerrors.ErrConsistency, kind, name, status)
	}
}

// parseIPv4Address parses a non-empty OpenStack-returned address string into
// an IPv4Address. Empty, malformed, and IPv6 inputs return ErrConsistency —
// callers wrap with their own context. Callers that want to tolerate an
// empty input (e.g. pre-ACTIVE Octavia states) must guard with `if s != ""`
// before calling.
func parseIPv4Address(s string) (*unikornv1core.IPv4Address, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return nil, fmt.Errorf("%w: %q is not a valid IPv4 address", coreerrors.ErrConsistency, s)
	}

	return &unikornv1core.IPv4Address{IP: ip}, nil
}

// octaviaListenerProtocol maps a CRD listener protocol to Octavia's listener
// protocol enum.
func octaviaListenerProtocol(protocol unikornv1.LoadBalancerListenerProtocol) listeners.Protocol {
	if protocol == unikornv1.LoadBalancerListenerProtocolUDP {
		return listeners.ProtocolUDP
	}

	return listeners.ProtocolTCP
}

// octaviaPoolProtocol maps a CRD listener protocol (and ProxyProtocolV2 flag)
// to Octavia's pool protocol enum.
func octaviaPoolProtocol(protocol unikornv1.LoadBalancerListenerProtocol, proxyProtocolV2 bool) pools.Protocol {
	if protocol == unikornv1.LoadBalancerListenerProtocolUDP {
		return pools.ProtocolUDP
	}

	if proxyProtocolV2 {
		return pools.ProtocolPROXYV2
	}

	return pools.ProtocolTCP
}

// octaviaMonitorType maps a CRD listener protocol to Octavia's health monitor
// type.
func octaviaMonitorType(protocol unikornv1.LoadBalancerListenerProtocol) string {
	if protocol == unikornv1.LoadBalancerListenerProtocolUDP {
		return monitors.TypeUDPConnect
	}

	return monitors.TypeTCP
}

// desiredListenerCIDRs returns the listener's AllowedCIDRs as a slice of
// stringified CIDRs, or nil when none are set.
func desiredListenerCIDRs(listener *unikornv1.LoadBalancerListener) []string {
	if len(listener.AllowedCIDRs) == 0 {
		return nil
	}

	out := make([]string, len(listener.AllowedCIDRs))
	for i := range listener.AllowedCIDRs {
		out[i] = listener.AllowedCIDRs[i].String()
	}

	return out
}

// idleTimeoutMillis converts a CRD IdleTimeoutSeconds (nil-able) into the
// milliseconds form used by Octavia, or nil when the spec field is unset.
func idleTimeoutMillis(seconds *int) *int {
	if seconds == nil {
		return nil
	}

	return ptr.To(*seconds * 1000)
}

// buildMemberOpts builds the BatchUpdateMembers payload for a listener's pool.
func buildMemberOpts(listener *unikornv1.LoadBalancerListener) []pools.BatchUpdateMemberOpts {
	out := make([]pools.BatchUpdateMemberOpts, len(listener.Pool.Members))

	for i := range listener.Pool.Members {
		out[i] = pools.BatchUpdateMemberOpts{
			Address:      listener.Pool.Members[i].Address.String(),
			ProtocolPort: listener.Pool.Members[i].Port,
		}
	}

	return out
}

// buildMonitorCreateOpts builds the monitor CreateOpts for a listener's pool.
func buildMonitorCreateOpts(loadBalancer *unikornv1.LoadBalancer, listener *unikornv1.LoadBalancerListener, poolID string) monitors.CreateOpts {
	hc := listener.Pool.HealthCheck

	return monitors.CreateOpts{
		PoolID:         poolID,
		Name:           loadBalancerMonitorName(loadBalancer, listener),
		Type:           octaviaMonitorType(listener.Protocol),
		Delay:          hc.IntervalSeconds,
		Timeout:        hc.TimeoutSeconds,
		MaxRetries:     hc.HealthyThreshold,
		MaxRetriesDown: hc.UnhealthyThreshold,
	}
}

// buildPoolCreateOpts builds a standalone pool CreateOpts (used for both the
// nested single-call create payload and the post-create per-resource path).
// The returned opts do not include LoadbalancerID/ListenerID — the caller sets
// those depending on the path.
func buildPoolCreateOpts(loadBalancer *unikornv1.LoadBalancer, listener *unikornv1.LoadBalancerListener) pools.CreateOpts {
	return pools.CreateOpts{
		Name:     loadBalancerPoolName(loadBalancer, listener),
		LBMethod: pools.LBMethodRoundRobin,
		Protocol: octaviaPoolProtocol(listener.Protocol, listener.Pool.ProxyProtocolV2),
	}
}

// buildListenerCreateOpts builds the listener CreateOpts for the per-resource
// create path. The pool is created first and attached via DefaultPoolID.
func buildListenerCreateOpts(loadBalancer *unikornv1.LoadBalancer, listener *unikornv1.LoadBalancerListener, loadBalancerID, defaultPoolID string) listeners.CreateOpts {
	return listeners.CreateOpts{
		LoadbalancerID:    loadBalancerID,
		Name:              loadBalancerListenerName(loadBalancer, listener),
		Protocol:          octaviaListenerProtocol(listener.Protocol),
		ProtocolPort:      listener.Port,
		DefaultPoolID:     defaultPoolID,
		AllowedCIDRs:      desiredListenerCIDRs(listener),
		TimeoutClientData: idleTimeoutMillis(listener.IdleTimeoutSeconds),
		TimeoutMemberData: idleTimeoutMillis(listener.IdleTimeoutSeconds),
	}
}

// buildLoadBalancerCreateOpts builds the fully-populated nested CreateOpts tree
// used when the load balancer does not yet exist.
func buildLoadBalancerCreateOpts(loadBalancer *unikornv1.LoadBalancer, subnetID string) loadbalancers.CreateOpts {
	opts := loadbalancers.CreateOpts{
		Name:        loadBalancerName(loadBalancer),
		VipSubnetID: subnetID,
	}

	if loadBalancer.Spec.RequestedVIPAddress != nil {
		opts.VipAddress = loadBalancer.Spec.RequestedVIPAddress.String()
	}

	opts.Listeners = make([]listeners.CreateOpts, len(loadBalancer.Spec.Listeners))

	for i := range loadBalancer.Spec.Listeners {
		listener := &loadBalancer.Spec.Listeners[i]

		poolOpts := buildPoolCreateOpts(loadBalancer, listener)

		members := make([]pools.CreateMemberOpts, len(listener.Pool.Members))
		for j := range listener.Pool.Members {
			members[j] = pools.CreateMemberOpts{
				Address:      listener.Pool.Members[j].Address.String(),
				ProtocolPort: listener.Pool.Members[j].Port,
			}
		}

		poolOpts.Members = members

		if listener.Pool.HealthCheck != nil {
			monitorOpts := buildMonitorCreateOpts(loadBalancer, listener, "")
			poolOpts.Monitor = monitorOpts
		}

		opts.Listeners[i] = listeners.CreateOpts{
			Name:              loadBalancerListenerName(loadBalancer, listener),
			Protocol:          octaviaListenerProtocol(listener.Protocol),
			ProtocolPort:      listener.Port,
			AllowedCIDRs:      desiredListenerCIDRs(listener),
			TimeoutClientData: idleTimeoutMillis(listener.IdleTimeoutSeconds),
			TimeoutMemberData: idleTimeoutMillis(listener.IdleTimeoutSeconds),
			DefaultPool:       &poolOpts,
		}
	}

	return opts
}

// reconcileLoadBalancer ensures the Octavia load balancer (and on first create
// its full nested tree) exists, returning the live resource. It never returns
// ErrYield — the orchestrator decides whether to yield based on
// ProvisioningStatus.
func (p *Provider) reconcileLoadBalancer(ctx context.Context, lbClient LoadBalancingInterface, loadBalancer *unikornv1.LoadBalancer, subnetID string) (*loadbalancers.LoadBalancer, error) {
	log := log.FromContext(ctx)

	osLB, err := lbClient.GetLoadBalancer(ctx, loadBalancer)
	if err != nil {
		if !errors.Is(err, coreerrors.ErrResourceNotFound) {
			return nil, err
		}

		log.V(1).Info("creating load balancer")

		opts := buildLoadBalancerCreateOpts(loadBalancer, subnetID)

		osLB, err = lbClient.CreateLoadBalancer(ctx, opts)
		if err != nil {
			return nil, err
		}
	}

	if osLB.VipAddress != "" {
		addr, err := parseIPv4Address(osLB.VipAddress)
		if err != nil {
			return nil, fmt.Errorf("load balancer %s VIP: %w", loadBalancer.Name, err)
		}

		loadBalancer.Status.VIPAddress = addr
	}

	if loadBalancer.Spec.RequestedVIPAddress != nil && osLB.VipAddress != "" && osLB.VipAddress != loadBalancer.Spec.RequestedVIPAddress.String() {
		return nil, fmt.Errorf("%w: load balancer %s VIP %s does not match requested %s", coreerrors.ErrConsistency, loadBalancer.Name, osLB.VipAddress, loadBalancer.Spec.RequestedVIPAddress.String())
	}

	return osLB, nil
}

// reconcilePool ensures the Octavia pool for a listener exists, and that its
// mutable fields (LBMethod) match the desired state. Protocol drift cannot be
// reconciled here — Octavia rejects protocol mutation; the handler-layer
// immutability check blocks user-driven drift before it reaches the provider.
func (p *Provider) reconcilePool(ctx context.Context, lbClient LoadBalancingInterface, loadBalancer *unikornv1.LoadBalancer, listener *unikornv1.LoadBalancerListener, loadBalancerID string) (*pools.Pool, error) {
	log := log.FromContext(ctx)

	pool, err := lbClient.GetPool(ctx, loadBalancerID, loadBalancer, listener)
	if err != nil {
		if !errors.Is(err, coreerrors.ErrResourceNotFound) {
			return nil, err
		}

		log.V(1).Info("creating pool", "listener", listener.Name)

		opts := buildPoolCreateOpts(loadBalancer, listener)
		opts.LoadbalancerID = loadBalancerID

		return lbClient.CreatePool(ctx, opts)
	}

	desiredLBMethod := pools.LBMethodRoundRobin
	if pool.LBMethod != string(desiredLBMethod) {
		log.V(1).Info("updating pool lb method", "listener", listener.Name)

		return lbClient.UpdatePool(ctx, pool.ID, pools.UpdateOpts{LBMethod: desiredLBMethod})
	}

	return pool, nil
}

// reconcileListener ensures the Octavia listener for a spec listener exists
// and that its mutable fields (AllowedCIDRs, idle timeouts) match the desired
// state. Returns the live listener.
func (p *Provider) reconcileListener(ctx context.Context, lbClient LoadBalancingInterface, loadBalancer *unikornv1.LoadBalancer, listener *unikornv1.LoadBalancerListener, loadBalancerID, defaultPoolID string) (*listeners.Listener, error) {
	log := log.FromContext(ctx)

	live, err := lbClient.GetListener(ctx, loadBalancerID, loadBalancer, listener)
	if err != nil {
		if !errors.Is(err, coreerrors.ErrResourceNotFound) {
			return nil, err
		}

		log.V(1).Info("creating listener", "listener", listener.Name)

		opts := buildListenerCreateOpts(loadBalancer, listener, loadBalancerID, defaultPoolID)

		return lbClient.CreateListener(ctx, opts)
	}

	updateOpts := listeners.UpdateOpts{}
	dirty := false

	desiredCIDRs := desiredListenerCIDRs(listener)
	if !cidrSetsEqual(live.AllowedCIDRs, desiredCIDRs) {
		cidrs := desiredCIDRs
		if cidrs == nil {
			cidrs = []string{}
		}

		updateOpts.AllowedCIDRs = &cidrs
		dirty = true
	}

	if live.DefaultPoolID != defaultPoolID {
		updateOpts.DefaultPoolID = ptr.To(defaultPoolID)
		dirty = true
	}

	if desiredTimeout := idleTimeoutMillis(listener.IdleTimeoutSeconds); desiredTimeout != nil {
		if live.TimeoutClientData != *desiredTimeout || live.TimeoutMemberData != *desiredTimeout {
			updateOpts.TimeoutClientData = desiredTimeout
			updateOpts.TimeoutMemberData = desiredTimeout
			dirty = true
		}
	}

	if !dirty {
		return live, nil
	}

	log.V(1).Info("updating listener", "listener", listener.Name)

	return lbClient.UpdateListener(ctx, live.ID, updateOpts)
}

// reconcileMembers ensures the Octavia pool membership matches the spec set.
// It compares (Address, Port) sets, only invoking BatchUpdateMembers when they
// differ. Returns a mutated flag so the caller can yield after the LB enters
// PENDING_UPDATE.
func (p *Provider) reconcileMembers(ctx context.Context, lbClient LoadBalancingInterface, loadBalancer *unikornv1.LoadBalancer, listener *unikornv1.LoadBalancerListener, poolID string) (bool, error) {
	log := log.FromContext(ctx)

	live, err := lbClient.ListMembers(ctx, poolID)
	if err != nil {
		return false, err
	}

	desired := buildMemberOpts(listener)

	if memberSetsEqual(live, desired) {
		return false, nil
	}

	log.V(1).Info("updating pool members", "loadbalancer", loadBalancer.Name, "listener", listener.Name)

	if err := lbClient.BatchUpdateMembers(ctx, poolID, desired); err != nil {
		return false, err
	}

	return true, nil
}

// reconcileMonitor ensures the Octavia health monitor for a listener's pool
// exists and that its mutable threshold fields match the desired state.
func (p *Provider) reconcileMonitor(ctx context.Context, lbClient LoadBalancingInterface, loadBalancer *unikornv1.LoadBalancer, listener *unikornv1.LoadBalancerListener, poolID string) (*monitors.Monitor, error) {
	log := log.FromContext(ctx)

	hc := listener.Pool.HealthCheck

	live, err := lbClient.GetMonitor(ctx, poolID, loadBalancer, listener)
	if err != nil {
		if !errors.Is(err, coreerrors.ErrResourceNotFound) {
			return nil, err
		}

		log.V(1).Info("creating health monitor", "listener", listener.Name)

		opts := buildMonitorCreateOpts(loadBalancer, listener, poolID)

		return lbClient.CreateMonitor(ctx, opts)
	}

	updateOpts := monitors.UpdateOpts{}
	dirty := false

	if live.Delay != hc.IntervalSeconds {
		updateOpts.Delay = hc.IntervalSeconds
		dirty = true
	}

	if live.Timeout != hc.TimeoutSeconds {
		updateOpts.Timeout = hc.TimeoutSeconds
		dirty = true
	}

	if live.MaxRetries != hc.HealthyThreshold {
		updateOpts.MaxRetries = hc.HealthyThreshold
		dirty = true
	}

	if live.MaxRetriesDown != hc.UnhealthyThreshold {
		updateOpts.MaxRetriesDown = hc.UnhealthyThreshold
		dirty = true
	}

	if !dirty {
		return live, nil
	}

	log.V(1).Info("updating health monitor", "listener", listener.Name)

	return lbClient.UpdateMonitor(ctx, live.ID, updateOpts)
}

// desiredNameSets bundles the listener/pool/monitor name sets a load balancer
// spec implies, so callers can pick out only the sets they need.
type desiredNameSets struct {
	listeners, pools, monitors map[string]struct{}
}

// desiredLoadBalancerNames returns the listener/pool/monitor names a load
// balancer spec implies.
func desiredLoadBalancerNames(loadBalancer *unikornv1.LoadBalancer) desiredNameSets {
	sets := desiredNameSets{
		listeners: make(map[string]struct{}, len(loadBalancer.Spec.Listeners)),
		pools:     make(map[string]struct{}, len(loadBalancer.Spec.Listeners)),
		monitors:  make(map[string]struct{}, len(loadBalancer.Spec.Listeners)),
	}

	for i := range loadBalancer.Spec.Listeners {
		listener := &loadBalancer.Spec.Listeners[i]
		sets.listeners[loadBalancerListenerName(loadBalancer, listener)] = struct{}{}
		sets.pools[loadBalancerPoolName(loadBalancer, listener)] = struct{}{}

		if listener.Pool.HealthCheck != nil {
			sets.monitors[loadBalancerMonitorName(loadBalancer, listener)] = struct{}{}
		}
	}

	return sets
}

// pruneOrphanedListener deletes the first listener whose name has the LB
// prefix and is not in the desired set, returning whether work was done.
func pruneOrphanedListener(ctx context.Context, lbClient LoadBalancingInterface, loadBalancerID, prefix string, desired map[string]struct{}) (bool, error) {
	log := log.FromContext(ctx)

	list, err := lbClient.ListListeners(ctx, loadBalancerID, "")
	if err != nil {
		return false, err
	}

	for i := range list {
		listener := &list[i]
		if !strings.HasPrefix(listener.Name, prefix) {
			continue
		}

		if _, ok := desired[listener.Name]; ok {
			continue
		}

		log.V(1).Info("deleting orphaned listener", "name", listener.Name)

		return true, lbClient.DeleteListener(ctx, listener.ID)
	}

	return false, nil
}

// pruneOrphanedPoolOrMonitor deletes either an orphaned pool or an orphaned
// monitor (in that order), returning whether work was done.
func pruneOrphanedPoolOrMonitor(ctx context.Context, lbClient LoadBalancingInterface, loadBalancerID, prefix string, desiredPools, desiredMonitors map[string]struct{}) (bool, error) {
	log := log.FromContext(ctx)

	poolList, err := lbClient.ListPools(ctx, loadBalancerID, "")
	if err != nil {
		return false, err
	}

	for i := range poolList {
		pool := &poolList[i]
		if !strings.HasPrefix(pool.Name, prefix) {
			continue
		}

		if _, ok := desiredPools[pool.Name]; ok {
			continue
		}

		log.V(1).Info("deleting orphaned pool", "name", pool.Name)

		return true, lbClient.DeletePool(ctx, pool.ID)
	}

	for i := range poolList {
		pool := &poolList[i]
		if !strings.HasPrefix(pool.Name, prefix) {
			continue
		}

		done, err := pruneOrphanedMonitor(ctx, lbClient, pool.ID, prefix, desiredMonitors)
		if err != nil || done {
			return done, err
		}
	}

	return false, nil
}

// pruneOrphanedMonitor deletes the first monitor on the given pool whose name
// has the LB prefix and is not in the desired set.
func pruneOrphanedMonitor(ctx context.Context, lbClient LoadBalancingInterface, poolID, prefix string, desired map[string]struct{}) (bool, error) {
	log := log.FromContext(ctx)

	list, err := lbClient.ListMonitors(ctx, poolID, "")
	if err != nil {
		return false, err
	}

	for i := range list {
		monitor := &list[i]
		if !strings.HasPrefix(monitor.Name, prefix) {
			continue
		}

		if _, ok := desired[monitor.Name]; ok {
			continue
		}

		log.V(1).Info("deleting orphaned health monitor", "name", monitor.Name)

		return true, lbClient.DeleteMonitor(ctx, monitor.ID)
	}

	return false, nil
}

// pruneOrphanedListenersOnce deletes a single orphaned listener (one whose
// name has the LB prefix but is not in the desired set), returning whether it
// mutated state. The caller must yield on a true result so the LB
// PENDING_UPDATE can settle before the next reconcile pass.
//
// Listener pruning runs *before* the desired listener loop so that a rename
// preserving (protocol, port) — e.g. http→api on TCP/80 — frees the port
// before the create attempt would otherwise be rejected as a duplicate.
func (p *Provider) pruneOrphanedListenersOnce(ctx context.Context, lbClient LoadBalancingInterface, loadBalancer *unikornv1.LoadBalancer, loadBalancerID string) (bool, error) {
	desired := desiredLoadBalancerNames(loadBalancer)
	prefix := loadBalancerName(loadBalancer) + "-"

	return pruneOrphanedListener(ctx, lbClient, loadBalancerID, prefix, desired.listeners)
}

// pruneOrphanedPoolsAndMonitorsOnce deletes a single orphaned pool or monitor,
// returning whether it mutated state. Runs after the desired listener loop so
// that pools no longer referenced by any listener can be safely removed.
func (p *Provider) pruneOrphanedPoolsAndMonitorsOnce(ctx context.Context, lbClient LoadBalancingInterface, loadBalancer *unikornv1.LoadBalancer, loadBalancerID string) (bool, error) {
	desired := desiredLoadBalancerNames(loadBalancer)
	prefix := loadBalancerName(loadBalancer) + "-"

	return pruneOrphanedPoolOrMonitor(ctx, lbClient, loadBalancerID, prefix, desired.pools, desired.monitors)
}

// cidrSetsEqual compares two CIDR string lists as sorted sets.
func cidrSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	aa := append([]string(nil), a...)
	slices.Sort(aa)

	bb := append([]string(nil), b...)
	slices.Sort(bb)

	return slices.Equal(aa, bb)
}

// memberSetsEqual reports whether the live members and desired BatchUpdate
// payload describe the same (Address, Port) set.
func memberSetsEqual(live []pools.Member, desired []pools.BatchUpdateMemberOpts) bool {
	if len(live) != len(desired) {
		return false
	}

	type key struct {
		address string
		port    int
	}

	set := make(map[key]struct{}, len(live))
	for i := range live {
		set[key{address: live[i].Address, port: live[i].ProtocolPort}] = struct{}{}
	}

	for i := range desired {
		if _, ok := set[key{address: desired[i].Address, port: desired[i].ProtocolPort}]; !ok {
			return false
		}
	}

	return true
}

// CreateLoadBalancer reconciles the full Octavia topology — load balancer,
// listeners, pools, members, and health monitors — for the given spec. It
// yields between PENDING transitions and surfaces VIP mismatches and other
// terminal Octavia states as ErrConsistency.
func (p *Provider) CreateLoadBalancer(ctx context.Context, identity *unikornv1.Identity, loadBalancer *unikornv1.LoadBalancer) error {
	network, err := p.loadBalancerNetwork(ctx, loadBalancer)
	if err != nil {
		return err
	}

	if network.Status.Openstack == nil || network.Status.Openstack.SubnetID == nil {
		return fmt.Errorf("%w: network %s missing subnet ID", coreerrors.ErrConsistency, network.Name)
	}

	subnetID := *network.Status.Openstack.SubnetID

	lbClient, err := p.loadBalancerFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	networking, err := p.networkFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	return p.createLoadBalancer(ctx, lbClient, networking, loadBalancer, subnetID)
}

// createLoadBalancer drives the reconcile-up flow against a resolved load
// balancing client. Split from CreateLoadBalancer so unit tests can inject a
// mock without standing up a service principal.
//
//nolint:cyclop
func (p *Provider) createLoadBalancer(ctx context.Context, lbClient LoadBalancingInterface, fipClient FloatingIPInterface, loadBalancer *unikornv1.LoadBalancer, subnetID string) error {
	osLB, err := p.reconcileLoadBalancer(ctx, lbClient, loadBalancer, subnetID)
	if err != nil {
		return err
	}

	if err := classifyOctaviaStatus("loadbalancer", osLB.Name, osLB.ProvisioningStatus); err != nil {
		return err
	}

	if osLB.VipAddress == "" {
		return fmt.Errorf("%w: load balancer %s is ACTIVE but has no VIP address",
			coreerrors.ErrConsistency, loadBalancer.Name)
	}

	if osLB.VipPortID == "" {
		return fmt.Errorf("%w: load balancer %s has VIP %s but no VIP port", coreerrors.ErrConsistency, loadBalancer.Name, osLB.VipAddress)
	}

	if err := p.reconcileLoadBalancerFloatingIP(ctx, fipClient, loadBalancer, osLB.VipPortID); err != nil {
		return err
	}

	mutated, err := p.pruneOrphanedListenersOnce(ctx, lbClient, loadBalancer, osLB.ID)
	if err != nil {
		return err
	}

	if mutated {
		return provisioners.ErrYield
	}

	for i := range loadBalancer.Spec.Listeners {
		listener := &loadBalancer.Spec.Listeners[i]

		pool, err := p.reconcilePool(ctx, lbClient, loadBalancer, listener, osLB.ID)
		if err != nil {
			return err
		}

		if err := classifyOctaviaStatus("pool", pool.Name, pool.ProvisioningStatus); err != nil {
			return err
		}

		osListener, err := p.reconcileListener(ctx, lbClient, loadBalancer, listener, osLB.ID, pool.ID)
		if err != nil {
			return err
		}

		if err := classifyOctaviaStatus("listener", osListener.Name, osListener.ProvisioningStatus); err != nil {
			return err
		}

		mutated, err := p.reconcileMembers(ctx, lbClient, loadBalancer, listener, pool.ID)
		if err != nil {
			return err
		}

		if mutated {
			return provisioners.ErrYield
		}

		if listener.Pool.HealthCheck != nil {
			osMonitor, err := p.reconcileMonitor(ctx, lbClient, loadBalancer, listener, pool.ID)
			if err != nil {
				return err
			}

			if err := classifyOctaviaStatus("monitor", osMonitor.Name, osMonitor.ProvisioningStatus); err != nil {
				return err
			}
		}
	}

	mutated, err = p.pruneOrphanedPoolsAndMonitorsOnce(ctx, lbClient, loadBalancer, osLB.ID)
	if err != nil {
		return err
	}

	if mutated {
		return provisioners.ErrYield
	}

	return nil
}

// DeleteLoadBalancer removes the Octavia topology and any attached floating
// IP idempotently. It yields while Octavia is in any PENDING_* state and
// after issuing a cascade delete so the next reconcile can confirm completion.
func (p *Provider) DeleteLoadBalancer(ctx context.Context, identity *unikornv1.Identity, loadBalancer *unikornv1.LoadBalancer) error {
	provisioned, err := p.openstackIdentityProvisioned(ctx, identity)
	if err != nil {
		return err
	}

	if !provisioned {
		return nil
	}

	lbClient, err := p.loadBalancerFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	networking, err := p.networkFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	return p.deleteLoadBalancer(ctx, lbClient, networking, loadBalancer)
}

// deleteLoadBalancer drives the delete flow against resolved clients. Split
// from DeleteLoadBalancer so unit tests can inject mocks without standing up a
// service principal. Cleanup order: floating IP first (the cascade kills the
// VIP port, after which the FIP would leak), then cascade-delete the load
// balancer. Already-absent resources are success.
//
//nolint:cyclop
func (p *Provider) deleteLoadBalancer(ctx context.Context, lbClient LoadBalancingInterface, fipClient FloatingIPInterface, loadBalancer *unikornv1.LoadBalancer) error {
	log := log.FromContext(ctx)

	osLB, err := lbClient.GetLoadBalancer(ctx, loadBalancer)
	if err != nil {
		if errors.Is(err, coreerrors.ErrResourceNotFound) {
			loadBalancer.Status.PublicIP = nil
			loadBalancer.Status.VIPAddress = nil

			return nil
		}

		return err
	}

	if osLB.ProvisioningStatus == "PENDING_CREATE" ||
		osLB.ProvisioningStatus == "PENDING_UPDATE" ||
		osLB.ProvisioningStatus == "PENDING_DELETE" {
		return provisioners.ErrYield
	}

	// FIP first — cascade kills the VIP port, after which the FIP would leak.
	if osLB.VipPortID != "" {
		floatingip, err := fipClient.GetFloatingIP(ctx, osLB.VipPortID)
		if err != nil && !errors.Is(err, coreerrors.ErrResourceNotFound) {
			return err
		}

		if floatingip != nil {
			log.V(1).Info("deleting floating ip")

			if err := fipClient.DeleteFloatingIP(ctx, floatingip.ID); err != nil && !gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
				return err
			}
		}
	}

	// PublicIP cleared eagerly: the FIP is gone (deleted above or never existed).
	// VIPAddress stays until GetLoadBalancer returns NotFound — the LB still exists.
	loadBalancer.Status.PublicIP = nil

	log.V(1).Info("deleting load balancer")

	if err := lbClient.DeleteLoadBalancer(ctx, osLB.ID, true); err != nil {
		if !gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return err
		}

		loadBalancer.Status.VIPAddress = nil

		return nil
	}

	return provisioners.ErrYield
}
