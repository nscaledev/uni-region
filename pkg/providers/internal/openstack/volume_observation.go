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
	"errors"
	"fmt"
	"math"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"

	corev1 "k8s.io/api/core/v1"
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

func volumeSize(sizeGiB int) (resource.Quantity, error) {
	const bytesPerGiB = int64(1 << 30)

	if sizeGiB < 0 || int64(sizeGiB) > math.MaxInt64/bytesPerGiB {
		return resource.Quantity{}, fmt.Errorf("%w: invalid Cinder volume size %d GiB", coreerrors.ErrConsistency, sizeGiB)
	}

	return *resource.NewQuantity(int64(sizeGiB)*bytesPerGiB, resource.BinarySI), nil
}

func setVolumeHealth(volume *unikornv1.Volume, status string) {
	switch status {
	case "creating", "available", "reserved", "attaching", "in-use", "detaching", "managing", "maintenance", "restoring-backup", "awaiting-transfer", "backing-up", "downloading", "uploading", "retyping", "extending":
		unikornv1core.UpdateCondition(&volume.Status.Conditions, unikornv1core.ConditionHealthy, corev1.ConditionTrue, string(unikornv1core.ConditionReasonHealthy), "the provider volume state is healthy")
	case "deleting":
		unikornv1core.UpdateCondition(&volume.Status.Conditions, unikornv1core.ConditionHealthy, corev1.ConditionFalse, string(unikornv1core.ConditionReasonDegraded), "the provider volume is being deleted")
	case "error", "error_deleting", "error_managing", "error_restoring", "error_backing-up", "error_extending":
		unikornv1core.UpdateCondition(&volume.Status.Conditions, unikornv1core.ConditionHealthy, corev1.ConditionFalse, string(unikornv1core.ConditionReasonDegraded), "the provider reported the volume in an error state")
	default:
		unikornv1core.UpdateCondition(&volume.Status.Conditions, unikornv1core.ConditionHealthy, corev1.ConditionUnknown, string(unikornv1core.ConditionReasonUnknown), "the provider volume state is unknown")
	}
}

func updateVolumeState(ctx context.Context, blockStorage VolumeInterface, identity *unikornv1.Identity, volume *unikornv1.Volume) error {
	cinderVolume, err := blockStorage.GetVolume(ctx, volume)
	if err != nil {
		if !errors.Is(err, coreerrors.ErrResourceNotFound) {
			return err
		}

		available, availableErr := unikornv1core.GetAvailableCondition(volume)
		if availableErr != nil {
			return nil //nolint:nilerr // absence before provisioning is expected
		}

		if available.Status != corev1.ConditionTrue || available.Reason != unikornv1core.ConditionReasonProvisioned {
			return nil
		}

		volume.Status.Size = nil
		unikornv1core.UpdateCondition(&volume.Status.Conditions, unikornv1core.ConditionHealthy, corev1.ConditionFalse, string(unikornv1core.ConditionReasonDegraded), "the provider volume is missing")

		return nil
	}

	if cinderVolume == nil {
		return fmt.Errorf("%w: nil Cinder volume returned for Region volume %s", coreerrors.ErrConsistency, volume.Name)
	}

	if err := validateVolumeSystemMetadata(identity, volume, cinderVolume.Metadata); err != nil {
		return err
	}

	size, err := volumeSize(cinderVolume.Size)
	if err != nil {
		return err
	}

	volume.Status.Size = &size
	setVolumeHealth(volume, cinderVolume.Status)

	return nil
}

func (p *Provider) UpdateVolumeState(ctx context.Context, identity *unikornv1.Identity, volume *unikornv1.Volume) error {
	blockStorage, err := p.blockStorageFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	return updateVolumeState(ctx, blockStorage, identity, volume)
}
