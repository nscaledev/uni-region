/*
Copyright 2022-2024 EscherCloud.
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
	"slices"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/availabilityzones"
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/quotasets"
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/volumes"
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/volumetypes"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/unikorn-cloud/core/pkg/util/cache"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	"k8s.io/utils/ptr"
)

func volumeName(volume *unikornv1.Volume) string {
	return "volume-" + volume.Name
}

// BlockStorageClient wraps the generic client because gophercloud is unsafe.
type BlockStorageClient struct {
	client          *gophercloud.ServiceClient
	options         *unikornv1.RegionOpenstackBlockStorageSpec
	volumeTypeCache *cache.TimeoutCache[[]volumetypes.VolumeType]
}

// NewBlockStorageClient provides a simple one-liner to start computing.
func NewBlockStorageClient(ctx context.Context, provider CredentialProvider, options *unikornv1.RegionOpenstackBlockStorageSpec) (*BlockStorageClient, error) {
	providerClient, err := provider.Client(ctx)
	if err != nil {
		return nil, err
	}

	client, err := openstack.NewBlockStorageV3(providerClient, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}

	c := &BlockStorageClient{
		client:          client,
		options:         options,
		volumeTypeCache: cache.New[[]volumetypes.VolumeType](time.Hour),
	}

	return c, nil
}

// AvailabilityZones retrieves block storage availability zones.
func (c *BlockStorageClient) AvailabilityZones(ctx context.Context) ([]availabilityzones.AvailabilityZone, error) {
	_, span := traceStart(ctx, "GET /block-storage/v3/os-availability-zone")
	defer span.End()

	pages, err := availabilityzones.List(c.client).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	result, err := availabilityzones.ExtractAvailabilityZones(pages)
	if err != nil {
		return nil, err
	}

	filtered := []availabilityzones.AvailabilityZone{}

	for _, az := range result {
		if !az.ZoneState.Available {
			continue
		}

		filtered = append(filtered, az)
	}

	return filtered, nil
}

func (c *BlockStorageClient) GetVolume(ctx context.Context, volume *unikornv1.Volume) (*volumes.Volume, error) {
	_, span := traceStart(ctx, "GET /block-storage/v3/volumes/detail")
	defer span.End()

	name := volumeName(volume)

	pages, err := volumes.List(c.client, &volumes.ListOpts{
		Name: name,
	}).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	result, err := volumes.ExtractVolumes(pages)
	if err != nil {
		return nil, err
	}

	return findExactResource(result, name, "volume", func(resource *volumes.Volume) string {
		return resource.Name
	})
}

func (c *BlockStorageClient) CreateVolume(ctx context.Context, volume *unikornv1.Volume, metadata map[string]string) (*volumes.Volume, error) {
	_, span := traceStart(ctx, "POST /block-storage/v3/volumes")
	defer span.End()

	opts := &volumes.CreateOpts{
		Name:        volumeName(volume),
		Description: "unikorn managed block storage volume",
		Size:        int(volume.Spec.Size.Value() / (1 << 30)),
		VolumeType:  volume.Spec.VolumeClassID,
		Metadata:    metadata,
	}

	return volumes.Create(ctx, c.client, opts, nil).Extract()
}

func (c *BlockStorageClient) DeleteVolume(ctx context.Context, id string) error {
	spanAttributes := trace.WithAttributes(
		attribute.String("block_storage.volume.id", id),
	)

	_, span := traceStart(ctx, "DELETE /block-storage/v3/volumes/{id}", spanAttributes)
	defer span.End()

	return volumes.Delete(ctx, c.client, id, nil).ExtractErr()
}

func (c *BlockStorageClient) GetVolumeTypes(ctx context.Context) ([]volumetypes.VolumeType, error) {
	if result, ok := c.volumeTypeCache.Get(); ok {
		return result, nil
	}

	_, span := traceStart(ctx, "GET /block-storage/v3/types")
	defer span.End()

	pages, err := volumetypes.List(c.client, nil).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	result, err := volumetypes.ExtractVolumeTypes(pages)
	if err != nil {
		return nil, err
	}

	result = slices.DeleteFunc(result, func(volumeType volumetypes.VolumeType) bool {
		// We are admin, so see all the things, throw out private volume types.
		if !volumeTypeIsPublic(volumeType) {
			return true
		}

		config := openstackVolumeClassesConfig(c.options)
		if config == nil || config.Selector == nil {
			return true
		}

		return !slices.Contains(config.Selector.IDs, volumeType.ID)
	})

	c.volumeTypeCache.Set(result)

	return result, nil
}

func (c *BlockStorageClient) UpdateQuotas(ctx context.Context, projectID string) error {
	_, span := traceStart(ctx, "PUT /block-storage/v3/os-quota-sets")
	defer span.End()

	// Quotas are handled globally, not on a per-region basis, so it's safe to
	// unconditionally remove all OpenStack block storage limits here.
	opts := &quotasets.UpdateOpts{
		Volumes:            ptr.To(-1),
		Gigabytes:          ptr.To(-1),
		Snapshots:          ptr.To(-1),
		Backups:            ptr.To(-1),
		BackupGigabytes:    ptr.To(-1),
		PerVolumeGigabytes: ptr.To(-1),
		Groups:             ptr.To(-1),
	}

	return quotasets.Update(ctx, c.client, projectID, opts).Err
}

func volumeTypeIsPublic(volumeType volumetypes.VolumeType) bool {
	return volumeType.IsPublic || volumeType.PublicAccess
}

func openstackVolumeClassesConfig(blockStorage *unikornv1.RegionOpenstackBlockStorageSpec) *unikornv1.OpenstackVolumeClassesSpec {
	if blockStorage == nil {
		return nil
	}

	return blockStorage.VolumeClasses
}
