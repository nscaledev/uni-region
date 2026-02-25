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
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/util/cache"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Provider extends ProvisionerProvider with API-server-only capabilities
// (image management, console access, snapshots).
type Provider struct {
	*ProvisionerProvider

	// imageCache is used to downsample the OpenStack image API, because responses can
	// take seconds. This reduces the effect of that latency on most callers.
	imageCache *cache.TimeoutCache[[]images.Image]
}

var _ types.Provider = &Provider{}

func New(ctx context.Context, cli client.Client, region *unikornv1.Region) (*Provider, error) {
	core, err := NewProvisioner(ctx, cli, region)
	if err != nil {
		return nil, err
	}

	return &Provider{
		ProvisionerProvider: core,
		imageCache:          cache.New[[]images.Image](imageCacheTTL),
	}, nil
}

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

const (
	imageCacheTTL = 5 * time.Minute
)

// Kind returns the provider kind.
func (p *Provider) Kind() unikornv1.Provider {
	return unikornv1.ProviderOpenstack
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

// imageOS extracts the image OS from the image properties.
func imageOS(image *images.Image) types.ImageOS {
	kernel, _ := image.Properties[osKernelLabel].(string)
	family, _ := image.Properties[osFamilyLabel].(string)
	distro, _ := image.Properties[osDistroLabel].(string)
	version, _ := image.Properties[osVersionLabel].(string)

	result := types.ImageOS{
		Kernel:  types.OsKernel(kernel),
		Family:  types.OsFamily(family),
		Distro:  types.OsDistro(distro),
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

func isPublicOrOrganizationOwnedImage(image *images.Image, organizationIDs []string) bool {
	value, _ := image.Properties[organizationIDLabel].(string)
	return value == "" || slices.Contains(organizationIDs, value)
}

func isOrganizationOwnedImage(image *images.Image, organizationIDs []string) bool {
	value, _ := image.Properties[organizationIDLabel].(string)
	return value != "" && slices.Contains(organizationIDs, value)
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

type imagePredicate func(*images.Image) bool

type imageQuery struct {
	listFunc   func(context.Context) ([]images.Image, error)
	predicates []imagePredicate
}

func (q *imageQuery) AvailableToOrganization(organizationIDs ...string) types.ImageQuery {
	q.predicates = append(q.predicates, func(im *images.Image) bool {
		return isPublicOrOrganizationOwnedImage(im, organizationIDs)
	})

	return q
}

func (q *imageQuery) OwnedByOrganization(organizationIDs ...string) types.ImageQuery {
	q.predicates = append(q.predicates, func(im *images.Image) bool {
		return isOrganizationOwnedImage(im, organizationIDs)
	})

	return q
}

func (q *imageQuery) StatusIn(statuses ...types.ImageStatus) types.ImageQuery {
	q.predicates = append(q.predicates, func(im *images.Image) bool {
		st := imageStatus(im)
		return slices.Contains(statuses, st)
	})

	return q
}

func (q *imageQuery) List(ctx context.Context) (types.ImageList, error) {
	images, err := q.listFunc(ctx)
	if err != nil {
		return nil, err
	}

	var result []types.Image

images:
	for i := range images {
		for _, f := range q.predicates {
			if !f(&images[i]) {
				continue images
			}
		}

		im, err := convertImage(&images[i])
		if err != nil {
			return nil, err
		}

		result = append(result, *im)
	}

	return result, nil
}

func (p *Provider) listImages(ctx context.Context) ([]images.Image, error) {
	if cached, found := p.imageCache.Get(); found {
		return cached, nil
	}

	imageService, err := p.openstack.image(ctx)
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

func (p *Provider) QueryImages() (types.ImageQuery, error) {
	return &imageQuery{listFunc: p.listImages}, nil
}

// GetImage retrieves a specific image by its ID.
func (p *Provider) GetImage(ctx context.Context, organizationID, imageID string) (*types.Image, error) {
	resource, err := p.getImage(ctx, imageID)
	if err != nil {
		return nil, err
	}

	if !isPublicOrOrganizationOwnedImage(resource, []string{organizationID}) {
		return nil, fmt.Errorf(
			"%w: image %s is not accessible to organization %s",
			coreerrors.ErrResourceNotFound,
			imageID,
			organizationID,
		)
	}

	return convertImage(resource)
}

// getImage finds a particular image, given the ID. It checks the cache first, and if not
// present, assumes that the cache is out of date and fetches from the provider.
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

	imageService, err := p.openstack.image(ctx)
	if err != nil {
		return nil, err
	}

	resource, err := imageService.GetImage(ctx, imageID)
	if err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return nil, fmt.Errorf("%w: no image found with ID %s", coreerrors.ErrResourceNotFound, imageID)
		}

		return nil, err
	}

	if resource.Visibility == images.ImageVisibilityPublic {
		// Invalidate the cache as we had a cache miss.
		p.imageCache.Invalidate()
	}

	return resource, nil
}

func setIfNotNil[T ~string](metadata map[string]string, key string, value *T) {
	if value != nil {
		metadata[key] = string(*value)
	}
}

func createImageMetadata(image *types.Image) (map[string]string, error) {
	metadata := make(map[string]string)

	metadata[osKernelLabel] = string(image.OS.Kernel)
	metadata[osFamilyLabel] = string(image.OS.Family)
	metadata[osDistroLabel] = string(image.OS.Distro)
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

	p.imageCache.Invalidate()

	return convertImage(resource)
}

func (p *Provider) DeleteImage(ctx context.Context, imageID string) error {
	image, err := p.getImage(ctx, imageID)
	if err != nil {
		return err
	}

	// If we've set the identity ID, then that means it's a snapshot and
	// currently lives in the service principal's project, so rescope to
	// that.
	if identityID, ok := image.Properties[identityIDLabel].(string); ok {
		identity := &unikornv1.Identity{}

		region, _ := p.openstack.regionSnapshot()

		if err := p.client.Get(ctx, client.ObjectKey{Namespace: region.Namespace, Name: identityID}, identity); err != nil {
			return err
		}

		imageService, err := p.imageFromServicePrincipal(ctx, identity)
		if err != nil {
			return err
		}

		return p.deleteImage(ctx, imageService, imageID)
	}

	// Otherwise it exists in our project...
	imageService, err := p.openstack.image(ctx)
	if err != nil {
		return err
	}

	return p.deleteImage(ctx, imageService, imageID)
}

func (p *Provider) deleteImage(ctx context.Context, imageService *ImageClient, imageID string) error {
	if err := imageService.DeleteImage(ctx, imageID); err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return fmt.Errorf("image %w", coreerrors.ErrResourceNotFound)
		}

		if gophercloud.ResponseCodeIs(err, http.StatusConflict) {
			return types.ErrImageStillInUse
		}

		return err
	}

	p.imageCache.Invalidate()

	return nil
}

// CreateSnapshot creates a new image from an existing server.
//
//nolint:cyclop
func (p *Provider) CreateSnapshot(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, image *types.Image) (*types.Image, error) {
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

	if _, err = imageService.UpdateImage(ctx, imageID, publishOpts); err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return nil, fmt.Errorf("image %w", coreerrors.ErrResourceNotFound)
		}

		// Make a best effort to delete the image to free up resources.
		if err := imageService.DeleteImage(ctx, imageID); err != nil {
			log.Error(err, "failed to delete failed image, please manually remove me", "imageID", imageID)
		}

		return nil, err
	}

	newImage, err := p.getImage(ctx, imageID)
	if err != nil {
		return nil, err
	}

	return convertImage(newImage)
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
