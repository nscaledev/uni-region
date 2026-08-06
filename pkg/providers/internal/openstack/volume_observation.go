/*
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
	"math"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/apimachinery/pkg/api/resource"
)

func volumeSystemMetadata(identity *unikornv1.Identity, volume *unikornv1.Volume) map[string]string {
	return map[string]string{
		"region:volume_id":         volume.Name,
		"identity:organization_id": volume.Labels[coreconstants.OrganizationLabel],
		"identity:project_id":      volume.Labels[coreconstants.ProjectLabel],
		"region:region_id":         volume.Labels[constants.RegionLabel],
		"region:network_id":        volume.Spec.NetworkID,
		"region:identity_id":       identity.Name,
	}
}

func validateVolumeSystemMetadata(identity *unikornv1.Identity, volume *unikornv1.Volume, metadata map[string]string) error {
	for key, want := range volumeSystemMetadata(identity, volume) {
		if want == "" {
			return fmt.Errorf("%w: Region volume %s has empty linkage metadata %s", coreerrors.ErrConsistency, volume.Name, key)
		}

		if got, ok := metadata[key]; !ok || got != want {
			return fmt.Errorf("%w: Cinder volume metadata %s does not match Region volume %s", coreerrors.ErrConsistency, key, volume.Name)
		}
	}

	return nil
}

func volumeStatus(status string) types.VolumeStatus {
	switch status {
	case "creating":
		return types.VolumeStatusCreating
	case "available":
		return types.VolumeStatusAvailable
	case "reserved", "attaching":
		return types.VolumeStatusAttaching
	case "in-use":
		return types.VolumeStatusAttached
	case "detaching":
		return types.VolumeStatusDetaching
	case "deleting":
		return types.VolumeStatusDeleting
	case "managing", "maintenance", "restoring-backup", "awaiting-transfer", "backing-up", "downloading", "uploading", "retyping", "extending":
		return types.VolumeStatusUpdating
	case "error", "error_deleting", "error_managing", "error_restoring", "error_backing-up", "error_extending":
		return types.VolumeStatusError
	default:
		return types.VolumeStatusUnknown
	}
}

func volumeSize(sizeGiB int) (resource.Quantity, error) {
	const bytesPerGiB = int64(1 << 30)

	if sizeGiB < 0 || int64(sizeGiB) > math.MaxInt64/bytesPerGiB {
		return resource.Quantity{}, fmt.Errorf("%w: invalid Cinder volume size %d GiB", coreerrors.ErrConsistency, sizeGiB)
	}

	return *resource.NewQuantity(int64(sizeGiB)*bytesPerGiB, resource.BinarySI), nil
}

func observeVolume(ctx context.Context, blockStorage VolumeInterface, identity *unikornv1.Identity, volume *unikornv1.Volume) (*types.VolumeObservation, error) {
	cinderVolume, err := blockStorage.GetVolume(ctx, volume)
	if err != nil {
		return nil, err
	}

	if cinderVolume == nil {
		return nil, fmt.Errorf("%w: nil Cinder volume returned for Region volume %s", coreerrors.ErrConsistency, volume.Name)
	}

	if err := validateVolumeSystemMetadata(identity, volume, cinderVolume.Metadata); err != nil {
		return nil, err
	}

	size, err := volumeSize(cinderVolume.Size)
	if err != nil {
		return nil, err
	}

	return &types.VolumeObservation{Size: size, Status: volumeStatus(cinderVolume.Status)}, nil
}

func (p *Provider) ObserveVolume(ctx context.Context, identity *unikornv1.Identity, volume *unikornv1.Volume) (*types.VolumeObservation, error) {
	blockStorage, err := p.blockStorageFromServicePrincipal(ctx, identity)
	if err != nil {
		return nil, err
	}

	return observeVolume(ctx, blockStorage, identity, volume)
}
