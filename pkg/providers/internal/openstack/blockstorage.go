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
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/volumetypes"

	"github.com/unikorn-cloud/core/pkg/util/cache"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/utils/ptr"
)

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
		if config == nil || config.Selector == nil || len(config.Selector.IDs) == 0 {
			return false
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

func (p *Provider) VolumeClasses(ctx context.Context) (types.VolumeClassList, error) {
	blockStorage, err := p.blockStorage(ctx)
	if err != nil {
		return nil, err
	}

	resources, err := blockStorage.GetVolumeTypes(ctx)
	if err != nil {
		return nil, err
	}

	region, _ := p.openstack.regionSnapshot()

	return convertVolumeClasses(region, resources), nil
}

func (p *Provider) blockStorage(ctx context.Context) (VolumeTypeInterface, error) {
	region, credentials, err := p.openstack.regionRefresh(ctx)
	if err != nil {
		return nil, err
	}

	providerClient := NewPasswordProvider(region.Spec.Openstack.Endpoint, credentials.userID, credentials.password, credentials.projectID)

	return NewBlockStorageClient(ctx, providerClient, region.Spec.Openstack.BlockStorage)
}

func convertVolumeClasses(region *unikornv1.Region, resources []volumetypes.VolumeType) types.VolumeClassList {
	var config *unikornv1.OpenstackVolumeClassesSpec
	if region != nil && region.Spec.Openstack != nil {
		config = openstackVolumeClassesConfig(region.Spec.Openstack.BlockStorage)
	}

	result := make(types.VolumeClassList, 0, len(resources))

	for i := range resources {
		resource := &resources[i]

		class := types.VolumeClass{
			ID:          resource.ID,
			Name:        resource.Name,
			Description: resource.Description,
		}

		if metadata := volumeClassMetadata(config, resource.ID); metadata != nil {
			class.Media = types.VolumeClassMedia(metadata.Media)
			class.Encrypted = metadata.Encrypted

			class.Performance = convertVolumeClassPerformance(metadata.Performance)
		}

		result = append(result, class)
	}

	return result
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

func volumeClassMetadata(config *unikornv1.OpenstackVolumeClassesSpec, id string) *unikornv1.VolumeClassMetadata {
	if config == nil {
		return nil
	}

	i := slices.IndexFunc(config.Metadata, func(metadata unikornv1.VolumeClassMetadata) bool {
		return id == metadata.ID
	})
	if i < 0 {
		return nil
	}

	return &config.Metadata[i]
}

func convertVolumeClassPerformance(in *unikornv1.VolumeClassPerformanceSpec) *types.VolumeClassPerformance {
	if in == nil {
		return nil
	}

	out := &types.VolumeClassPerformance{}

	if in.MaxIOPS != nil {
		out.MaxIOPS = ptr.To(*in.MaxIOPS)
	}

	if in.MaxThroughput != nil {
		out.MaxThroughput = ptr.To(*in.MaxThroughput)
	}

	return out
}
