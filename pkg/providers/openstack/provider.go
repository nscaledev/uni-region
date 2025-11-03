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
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	gophercloud "github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/roles"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"
	"github.com/gophercloud/utils/openstack/clientconfig"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
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
	_network  NetworkingInterface

	lock sync.Mutex

	imageCache *cache.TimeoutCache[[]images.Image]
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
		imageCache:    cache.New[[]images.Image](time.Hour),
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

// identity returns an admin-level identity client.
func (p *Provider) identity(ctx context.Context) (*IdentityClient, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if err := p.serviceClientRefresh(ctx); err != nil {
		return nil, err
	}

	return p._identity, nil
}

// compute returns an admin-level compute client.
func (p *Provider) compute(ctx context.Context) (ComputeInterface, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if err := p.serviceClientRefresh(ctx); err != nil {
		return nil, err
	}

	return p._compute, nil
}

// identity returns an admin-level image client.
func (p *Provider) image(ctx context.Context) (*ImageClient, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if err := p.serviceClientRefresh(ctx); err != nil {
		return nil, err
	}

	return p._image, nil
}

// identity returns an admin-level network client.
func (p *Provider) network(ctx context.Context) (NetworkingInterface, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if err := p.serviceClientRefresh(ctx); err != nil {
		return nil, err
	}

	return p._network, nil
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

	return NewPasswordProvider(p.region.Spec.Openstack.Endpoint, *identity.Spec.UserID, *identity.Spec.Password, *identity.Spec.ProjectID), nil
}

// computeFromServicePrincipalData gets a compute client scoped to the service principal data.
func (p *Provider) computeFromServicePrincipalData(ctx context.Context, identity *unikornv1.OpenstackIdentity) (ComputeInterface, error) {
	provider, err := p.getProviderFromServicePrincipalData(identity)
	if err != nil {
		return nil, err
	}

	client, err := NewComputeClient(ctx, provider, p.region.Spec.Openstack.Compute)
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

// computeFromServicePrincipal gets a compute client scoped to the service principal.
func (p *Provider) computeFromServicePrincipal(ctx context.Context, identity *unikornv1.Identity) (ComputeInterface, error) {
	provider, err := p.getProviderFromServicePrincipal(ctx, identity)
	if err != nil {
		return nil, err
	}

	client, err := NewComputeClient(ctx, provider, p.region.Spec.Openstack.Compute)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// networkFromServicePrincipal get a network client scoped to the service principal.
func (p *Provider) networkFromServicePrincipal(ctx context.Context, identity *unikornv1.Identity) (NetworkingInterface, error) {
	provider, err := p.getProviderFromServicePrincipal(ctx, identity)
	if err != nil {
		return nil, err
	}

	client, err := NewNetworkClient(ctx, provider, p.region.Spec.Openstack.Network)
	if err != nil {
		return nil, err
	}

	return client, nil
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
	compute, err := p.compute(ctx)
	if err != nil {
		return nil, err
	}

	resources, err := compute.GetFlavors(ctx)
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

func isPublicOrOrganizationOwnedImage(image *images.Image, organizationID string) bool {
	value := image.Properties["unikorn:organization:id"]
	return value == nil || value == organizationID
}

func getPublicOrOrganizationOwnedImages(resources []images.Image, organizationID string) []images.Image {
	return slices.DeleteFunc(resources, func(image images.Image) bool {
		return !isPublicOrOrganizationOwnedImage(&image, organizationID)
	})
}

func (p *Provider) imageDiskFormat(image *images.Image) types.ImageDiskFormat {
	temp, _ := image.Properties["unikorn:disk_format"].(string)
	// Assume all image disk formats are valid, as they should have already been validated by the JSON schema.
	return types.ImageDiskFormat(temp)
}

func (p *Provider) imageDataSource(image *images.Image) types.ImageDataSource {
	temp, _ := image.Properties["unikorn:data_source"].(string)

	var dataSource types.ImageDataSource

	switch temp {
	case string(types.ImageDataSourceFile), string(types.ImageDataSourceURL), string(types.ImageDataSourceServer):
		dataSource = types.ImageDataSource(temp)
	default:
		// Fallback to file for all images that were created before this field was added.
		dataSource = types.ImageDataSourceFile
	}

	return dataSource
}

func (p *Provider) imageStatus(image *images.Image, dataSource types.ImageDataSource) types.ImageStatus {
	var status types.ImageStatus

	switch image.Status {
	case images.ImageStatusQueued:
		if dataSource == types.ImageDataSourceFile {
			status = types.ImageStatusPending
		} else {
			status = types.ImageStatusCreating
		}
	case images.ImageStatusSaving:
		status = types.ImageStatusCreating
	case images.ImageStatusActive:
		status = types.ImageStatusReady
	case images.ImageStatusKilled:
		status = types.ImageStatusFailed
	case images.ImageStatusDeleted, images.ImageStatusPendingDelete, images.ImageStatusDeactivated, images.ImageStatusImporting:
		// These statuses are not directly mappable, mark them as failed.
		status = types.ImageStatusFailed
	}

	return status
}

func (p *Provider) convertImage(image *images.Image) (*types.Image, error) {
	var organizationID *string
	if temp, _ := image.Properties["unikorn:organization:id"].(string); temp != "" {
		organizationID = &temp
	}

	size := image.MinDiskGigabytes

	if size == 0 {
		// Round up to the nearest GiB.
		size = int((image.VirtualSize + (1 << 30) - 1) >> 30)
	}

	virtualization, _ := image.Properties["unikorn:virtualization"].(string)

	dataSource := p.imageDataSource(image)

	providerImage := types.Image{
		ID:             image.ID,
		Name:           image.Name,
		OrganizationID: organizationID,
		Created:        image.CreatedAt,
		Modified:       image.UpdatedAt,
		SizeGiB:        size,
		Virtualization: types.ImageVirtualization(virtualization),
		OS:             p.imageOS(image),
		Packages:       p.imagePackages(image),
		DiskFormat:     p.imageDiskFormat(image),
		DataSource:     dataSource,
		Status:         p.imageStatus(image, dataSource),
	}

	if gpuVendor, ok := image.Properties["unikorn:gpu_vendor"].(string); ok {
		gpuDriver, ok := image.Properties["unikorn:gpu_driver_version"].(string)
		if !ok {
			// TODO: it's perhaps better to just skip this one, rather than kill the entire service??
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

	return &providerImage, nil
}

// ClearImageCache clears the image cache.
func (p *Provider) ClearImageCache(ctx context.Context) error {
	p.imageCache.Invalidate()
	return nil
}

// ListImages lists all available images.
func (p *Provider) ListImages(ctx context.Context, organizationID string) (types.ImageList, error) {
	resources, err := p.listImages(ctx)
	if err != nil {
		return nil, err
	}

	resources = getPublicOrOrganizationOwnedImages(resources, organizationID)

	result := make(types.ImageList, len(resources))

	for i := range resources {
		providerImage, err := p.convertImage(&resources[i])
		if err != nil {
			return nil, err
		}

		result[i] = *providerImage
	}

	return result, nil
}

func (p *Provider) listImages(ctx context.Context) ([]images.Image, error) {
	if cached, found := p.imageCache.Get(); found {
		return cached, nil
	}

	imageService, err := p.image(ctx)
	if err != nil {
		return nil, err
	}

	resources, err := imageService.ListImages(ctx)
	if err != nil {
		return nil, err
	}

	p.imageCache.Set(resources)

	return resources, nil
}

// GetImage retrieves a specific image by its ID.
func (p *Provider) GetImage(ctx context.Context, organizationID, imageID string) (*types.Image, error) {
	resource, err := p.getImage(ctx, imageID)
	if err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return nil, fmt.Errorf("image %w", types.ErrResourceNotFound)
		}

		return nil, err
	}

	if !isPublicOrOrganizationOwnedImage(resource, organizationID) {
		// This mimics the error returned by the OpenStack when an image is not found,
		// allowing us to have consistent error handling over a single error type.
		return nil, fmt.Errorf("image %w", types.ErrResourceNotFound)
	}

	return p.convertImage(resource)
}

func (p *Provider) getImage(ctx context.Context, imageID string) (*images.Image, error) {
	if cached, found := p.imageCache.Get(); found {
		imageIndexFunc := func(image images.Image) bool {
			return image.ID == imageID
		}

		index := slices.IndexFunc(cached, imageIndexFunc)
		if index != -1 {
			return &cached[index], nil
		}
	}

	imageService, err := p.image(ctx)
	if err != nil {
		return nil, err
	}

	resource, err := imageService.GetImage(ctx, imageID)
	if err != nil {
		return nil, err
	}

	if resource.Visibility == images.ImageVisibilityPublic {
		// Invalidate the cache as we had a cache miss.
		p.imageCache.Invalidate()
	}

	return resource, nil
}

func SetMetadata[T ~string](metadata map[string]string, key string, value T) {
	metadata[key] = string(value)
}

func SetNonNilMetadata[T ~string](metadata map[string]string, key string, value *T) {
	if value != nil {
		metadata[key] = string(*value)
	}
}

func (p *Provider) createImageMetadata(image *types.Image) (map[string]string, error) {
	metadata := make(map[string]string)

	SetMetadata(metadata, "unikorn:os:kernal", image.OS.Kernel)
	SetMetadata(metadata, "unikorn:os:family", image.OS.Family)
	SetMetadata(metadata, "unikorn:os:distro", image.OS.Distro)
	SetNonNilMetadata(metadata, "unikorn:os:variant", image.OS.Variant)
	SetNonNilMetadata(metadata, "unikorn:os:codename", image.OS.Codename)

	if image.Packages != nil {
		for name, version := range *image.Packages {
			key := fmt.Sprintf("unikorn:package:%s", name)
			SetMetadata(metadata, key, version)
		}
	}

	//nolint:nestif
	if image.GPU != nil {
		if image.GPU.Vendor == "" {
			return nil, fmt.Errorf("%w: GPU vendor must be defined when GPU information is provided", ErrKeyUndefined)
		}

		if len(image.GPU.Models) == 0 {
			return nil, fmt.Errorf("%w: GPU models must be defined when GPU information is provided", ErrKeyUndefined)
		}

		if image.GPU.Driver == "" {
			return nil, fmt.Errorf("%w: GPU driver must be defined when GPU information is provided", ErrKeyUndefined)
		}

		var modelsBuffer bytes.Buffer

		csvWriter := csv.NewWriter(&modelsBuffer)
		if err := csvWriter.Write(image.GPU.Models); err != nil {
			return nil, err
		}

		csvWriter.Flush()

		gpuModels := modelsBuffer.String()
		if gpuModels[len(gpuModels)-1] == '\n' {
			gpuModels = gpuModels[:len(gpuModels)-1]
		}

		SetMetadata(metadata, "unikorn:gpu_vendor", image.GPU.Vendor)
		SetMetadata(metadata, "unikorn:gpu_models", gpuModels)
		SetMetadata(metadata, "unikorn:gpu_driver_version", image.GPU.Driver)
	}

	SetMetadata(metadata, "unikorn:virtualization", image.Virtualization)
	SetNonNilMetadata(metadata, "unikorn:organization:id", image.OrganizationID)
	SetMetadata(metadata, "unikorn:data_source", image.DataSource)

	return metadata, nil
}

// CreateImageForUpload creates a new image resource for upload.
func (p *Provider) CreateImageForUpload(ctx context.Context, image *types.Image) (*types.Image, error) {
	imageService, err := p.image(ctx)
	if err != nil {
		return nil, err
	}

	properties, err := p.createImageMetadata(image)
	if err != nil {
		return nil, err
	}

	opts := &images.CreateOpts{
		Name:       image.Name,
		Visibility: ptr.To(images.ImageVisibilityPublic),
		Hidden:     ptr.To(false),
		DiskFormat: string(image.DiskFormat),
		Protected:  ptr.To(false),
		Properties: properties,
	}

	resource, err := imageService.CreateImage(ctx, opts)
	if err != nil {
		return nil, err
	}

	p.imageCache.Invalidate()

	return p.convertImage(resource)
}

func (p *Provider) CreateImageFromServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, image *types.Image) (string, error) {
	compute, err := p.computeFromServicePrincipal(ctx, identity)
	if err != nil {
		return "", err
	}

	openstackServer, err := compute.GetServer(ctx, server)
	if err != nil {
		return "", err
	}

	metadata, err := p.createImageMetadata(image)
	if err != nil {
		return "", err
	}

	opts := &servers.CreateImageOpts{
		Name:     image.Name,
		Metadata: metadata,
	}

	imageID, err := compute.CreateImageFromServer(ctx, openstackServer.ID, opts)
	if err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return "", fmt.Errorf("server %w", types.ErrResourceNotFound)
		}

		if gophercloud.ResponseCodeIs(err, http.StatusConflict) {
			return "", types.ErrServerNotReadyForSnapshot
		}

		return "", err
	}

	return imageID, nil
}

// UploadImage uploads data to an image.
func (p *Provider) UploadImage(ctx context.Context, imageID string, reader io.Reader) error {
	imageService, err := p.image(ctx)
	if err != nil {
		return err
	}

	if err = imageService.UploadImageData(ctx, imageID, reader); err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return fmt.Errorf("image %w", types.ErrResourceNotFound)
		}

		if gophercloud.ResponseCodeIs(err, http.StatusConflict) {
			return types.ErrImageNotReadyForUpload
		}

		return err
	}

	return nil
}

// PublishImage makes an image publicly available.
func (p *Provider) PublishImage(ctx context.Context, imageID string) (*types.Image, error) {
	imageService, err := p.image(ctx)
	if err != nil {
		return nil, err
	}

	opts := images.UpdateOpts{
		images.UpdateVisibility{
			Visibility: images.ImageVisibilityPublic,
		},
	}

	resource, err := imageService.UpdateImage(ctx, imageID, opts)
	if err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return nil, fmt.Errorf("image %w", types.ErrResourceNotFound)
		}

		return nil, err
	}

	p.imageCache.Invalidate()

	return p.convertImage(resource)
}

func (p *Provider) DeleteImage(ctx context.Context, imageID string) error {
	imageService, err := p.image(ctx)
	if err != nil {
		return err
	}

	if err = imageService.DeleteImage(ctx, imageID); err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return fmt.Errorf("image %w", types.ErrResourceNotFound)
		}

		if gophercloud.ResponseCodeIs(err, http.StatusConflict) {
			return types.ErrImageStillInUse
		}

		return err
	}

	p.imageCache.Invalidate()

	return nil
}

// ListExternalNetworks returns a list of external networks if the platform
// supports such a concept.
func (p *Provider) ListExternalNetworks(ctx context.Context) (types.ExternalNetworks, error) {
	networking, err := p.network(ctx)
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

	identityService, err := p.identity(ctx)
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

// dhcpRange returns a range from the prefix starting at .2 and extending
// to the address before the last /25.
func dhcpRange(prefix net.IPNet) (string, string) {
	ba := big.NewInt(0).SetBytes(prefix.IP)

	// Start.
	bs := big.NewInt(0).Add(ba, big.NewInt(2))

	// End.
	ones, bits := prefix.Mask.Size()
	size := 1 << (bits - ones)

	be := big.NewInt(0).Add(ba, big.NewInt(int64(size-(1<<7)-1)))

	start := net.IP(bs.Bytes())
	end := net.IP(be.Bytes())

	return start.String(), end.String()
}

// storageRange returns a range from prefix that starts at the top /25
// and ends at the end of the range (less the broadcast address).
func storageRange(prefix net.IPNet) (string, string) {
	ba := big.NewInt(0).SetBytes(prefix.IP)

	// Start.
	ones, bits := prefix.Mask.Size()
	size := 1 << (bits - ones)

	bs := big.NewInt(0).Add(ba, big.NewInt(int64(size)-(1<<7)))

	// End.
	be := big.NewInt(0).Sub(big.NewInt(0).Add(ba, big.NewInt(int64(size))), big.NewInt(2))

	start := net.IP(bs.Bytes())
	end := net.IP(be.Bytes())

	return start.String(), end.String()
}

func (p *Provider) reconcileNetwork(ctx context.Context, client NetworkInterface, network *unikornv1.Network) (*networks.Network, error) {
	log := log.FromContext(ctx)

	result, err := client.GetNetwork(ctx, network)
	if err == nil {
		log.V(1).Info("L2 network already exists")

		return &result.Network, nil
	}

	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	log.V(1).Info("creating L2 network")

	var vlanID *int

	if p.region.Spec.Openstack.Network.UseProviderNetworks() {
		v, err := p.vlanAllocator.Allocate(ctx, network.Name)
		if err != nil {
			return nil, err
		}

		log.V(1).Info("allocated VLAN", "id", v)

		vlanID = &v
	}

	result2, err := client.CreateNetwork(ctx, network, vlanID)
	if err != nil {
		if vlanID != nil {
			if rerr := p.vlanAllocator.Free(ctx, *vlanID); rerr != nil {
				log.Error(rerr, "failed to free vlan", "id", *vlanID)
			}
		}

		return nil, err
	}

	return result2, nil
}

func (p *Provider) reconcileSubnet(ctx context.Context, client SubnetInterface, network *unikornv1.Network, openstackNetwork *networks.Network) (*subnets.Subnet, error) {
	log := log.FromContext(ctx)

	result, err := client.GetSubnet(ctx, network)
	if err == nil {
		log.V(1).Info("L3 subnet already exists")

		return result, nil
	}

	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	log.V(1).Info("creating L3 subnet")

	dnsNameservers := make([]string, len(network.Spec.DNSNameservers))

	for i, ip := range network.Spec.DNSNameservers {
		dnsNameservers[i] = ip.String()
	}

	start, end := dhcpRange(network.Spec.Prefix.IPNet)

	allocationPools := []subnets.AllocationPool{
		{
			Start: start,
			End:   end,
		},
	}

	result, err = client.CreateSubnet(ctx, network, openstackNetwork.ID, network.Spec.Prefix.String(), gatewayIP(network.Spec.Prefix.IPNet), dnsNameservers, allocationPools)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (p *Provider) reconcileRouter(ctx context.Context, client RouterInterface, network *unikornv1.Network) (*routers.Router, error) {
	log := log.FromContext(ctx)

	result, err := client.GetRouter(ctx, network)
	if err == nil {
		log.V(1).Info("router already exists")

		return result, nil
	}

	if !errors.Is(err, ErrNotFound) {
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
	networking, err := p.networkFromServicePrincipal(ctx, identity)
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

// DeleteNetwork deletes a physical network.
//
//nolint:gocognit,cyclop
func (p *Provider) DeleteNetwork(ctx context.Context, identity *unikornv1.Identity, network *unikornv1.Network) error {
	log := log.FromContext(ctx)

	networking, err := p.networkFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	openstackNetwork, err := networking.GetNetwork(ctx, network)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}

	subnet, err := networking.GetSubnet(ctx, network)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}

	router, err := networking.GetRouter(ctx, network)
	if err != nil && !errors.Is(err, ErrNotFound) {
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

	//nolint:nestif
	if openstackNetwork != nil {
		log.V(1).Info("deleting network")

		if err := networking.DeleteNetwork(ctx, openstackNetwork.ID); err != nil {
			return err
		}

		if p.region.Spec.Openstack.Network.UseProviderNetworks() {
			log.V(1).Info("freeing vlan", "id", openstackNetwork.SegmentationID)

			vlanID, err := strconv.Atoi(openstackNetwork.SegmentationID)
			if err != nil {
				log.Error(err, "failed to free vlan", "id", vlanID)

				return nil
			}

			if err := p.vlanAllocator.Free(ctx, vlanID); err != nil {
				log.Error(err, "failed to free vlan", "id", vlanID)

				return nil
			}
		}
	}

	return nil
}

// securityGroupRulePortRange expands a security group port into a start-end range as
// required by Neutron.
func securityGroupRulePortRange(port *unikornv1.SecurityGroupRulePort) (int, int, error) {
	if port.Number != nil {
		return *port.Number, *port.Number, nil
	}

	if port.Range != nil {
		return port.Range.Start, port.Range.End, nil
	}

	return 0, 0, fmt.Errorf("%w: at least one of number or range must be defined for security rule", ErrKeyUndefined)
}

// securityGroupRuleID generates a deterministic, but unique, ID for a security group rule.
func securityGroupRuleID(direction, protocol string, startPort, endPort int, prefix string) string {
	return fmt.Sprintf("%s,%s,%d-%d,%s", direction, protocol, startPort, endPort, prefix)
}

// securityGroupRuleIDFromSecurityGroupRule generates a deterministic, but unique, ID for a security group rule.
func securityGroupRuleIDFromSecurityGroupRule(rule *unikornv1.SecurityGroupRule) (string, error) {
	// The data is a tuple of direction, protocol, port and prefix.
	start, end, err := securityGroupRulePortRange(&rule.Port)
	if err != nil {
		return "", err
	}

	return securityGroupRuleID(string(rule.Direction), string(rule.Protocol), start, end, rule.CIDR.String()), nil
}

func listOpenstackSecurityGroupRules(ctx context.Context, client SecurityGroupInterface, securityGroupID string) (map[string]*rules.SecGroupRule, error) {
	resources, err := client.ListSecurityGroupRules(ctx, securityGroupID)
	if err != nil {
		return nil, err
	}

	out := map[string]*rules.SecGroupRule{}

	for i := range resources {
		rule := &resources[i]

		id := securityGroupRuleID(rule.Direction, rule.Protocol, rule.PortRangeMin, rule.PortRangeMax, rule.RemoteIPPrefix)

		out[id] = rule
	}

	return out, nil
}

// generateSecurityGroupRules maps all rules to a unique ID.
func generateSecurityGroupRules(securityGroup *unikornv1.SecurityGroup) (map[string]*unikornv1.SecurityGroupRule, error) {
	out := map[string]*unikornv1.SecurityGroupRule{
		// Secret hidden rule that comes by default, don't delete it by accident!
		securityGroupRuleID("egress", "", 0, 0, ""): nil,
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

		direction := rules.RuleDirection(rule.Direction)
		protocol := rules.RuleProtocol(rule.Protocol)

		portStart, portEnd, err := securityGroupRulePortRange(&rule.Port)
		if err != nil {
			return err
		}

		if _, err := client.CreateSecurityGroupRule(ctx, openstackSecurityGroup.ID, direction, protocol, portStart, portEnd, rule.CIDR.String()); err != nil {
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

	if !errors.Is(err, ErrNotFound) {
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

	providerClient := NewPasswordProvider(p.region.Spec.Openstack.Endpoint, p.credentials.userID, p.credentials.password, *openstackIdentity.Spec.ProjectID)

	networking, err := NewNetworkClient(ctx, providerClient, p.region.Spec.Openstack.Network)
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

	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return err
	}

	providerClient := NewPasswordProvider(p.region.Spec.Openstack.Endpoint, p.credentials.userID, p.credentials.password, *openstackIdentity.Spec.ProjectID)

	networking, err := NewNetworkClient(ctx, providerClient, p.region.Spec.Openstack.Network)
	if err != nil {
		return err
	}

	openstackSecurityGroup, err := networking.GetSecurityGroup(ctx, securityGroup)
	if err != nil && errors.Is(err, ErrNotFound) {
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

func (p *Provider) lookupNetwork(ctx context.Context, networks NetworkInterface, namespace, id string) (*networks.Network, error) {
	network := &unikornv1.Network{}

	if err := p.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: id}, network); err != nil {
		return nil, err
	}

	openstackNetwork, err := networks.GetNetwork(ctx, network)
	if err != nil {
		return nil, err
	}

	return &openstackNetwork.Network, nil
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

	port, err := client.GetPort(ctx, server.Name)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}

		log.V(1).Info("creating port")

		port, err = client.CreatePort(ctx, network.ID, server.Name, securityGroupIDs, addressPairs)
		if err != nil {
			return nil, err
		}

		return port, nil
	}

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

	if !errors.Is(err, ErrNotFound) {
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

func (p *Provider) reconcileServer(ctx context.Context, client ServerInterface, server *unikornv1.Server, port *ports.Port, keyName string) (*servers.Server, error) {
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

	metadata := map[string]string{
		"serverID":       server.Name,
		"organizationID": server.Labels[coreconstants.OrganizationLabel],
		"projectID":      server.Labels[coreconstants.ProjectLabel],
		"regionID":       server.Labels[constants.RegionLabel],
	}

	log.V(1).Info("creating server")

	openstackServer, err = client.CreateServer(ctx, server, keyName, networks, nil, metadata)
	if err != nil {
		return nil, err
	}

	setServerHealthStatus(server, openstackServer)
	setServerPhase(ctx, server, openstackServer)

	return openstackServer, nil
}

// CreateServer creates or updates a server.
func (p *Provider) CreateServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error {
	openstackIdentity, err := p.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return err
	}

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

	compute, err := p.computeFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	if _, err := p.reconcileServer(ctx, compute, server, port, *openstackIdentity.Spec.SSHKeyName); err != nil {
		return err
	}

	return nil
}

//nolint:cyclop
func (p *Provider) DeleteServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error {
	log := log.FromContext(ctx)

	compute, err := p.computeFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	openstackServer, err := compute.GetServer(ctx, server)
	if err != nil && !errors.Is(err, ErrNotFound) {
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

	port, err := networking.GetPort(ctx, server.Name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}

	//nolint:nestif
	if port != nil {
		floatingip, err := networking.GetFloatingIP(ctx, port.ID)
		if err != nil && !errors.Is(err, ErrNotFound) {
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
		// ignore not found errors
		if !gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return err
		}
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
		// ignore not found errors
		if !gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return err
		}
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
		// ignore not found errors
		if !gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return err
		}
	}

	return nil
}

// UpdateServerState checks a server's state and modifies the resource in place.
func (p *Provider) UpdateServerState(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error {
	compute, err := p.computeFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	openstackServer, err := compute.GetServer(ctx, server)
	if err != nil {
		return err
	}

	setServerHealthStatus(server, openstackServer)
	setServerPhase(ctx, server, openstackServer)

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
			return "", fmt.Errorf("%w: server is being deprovisioned", ErrResourceDependency)
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
			return "", fmt.Errorf("%w: server is being deprovisioned", ErrResourceDependency)
		}

		return "", err
	}

	return result, nil
}
