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
	"fmt"
	"math"
	"strings"

	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/volumes"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func volumeSize(sizeGiB int) (resource.Quantity, error) {
	const bytesPerGiB = int64(1 << 30)

	if sizeGiB < 0 || int64(sizeGiB) > math.MaxInt64/bytesPerGiB {
		return resource.Quantity{}, fmt.Errorf("%w: invalid Cinder volume size %d GiB", coreerrors.ErrConsistency, sizeGiB)
	}

	return *resource.NewQuantity(int64(sizeGiB)*bytesPerGiB, resource.BinarySI), nil
}

// TODO: move this.  Healthy only makes sense for a cluster; a volume's own
// state wants its own condition.
func setVolumeHealth(volume *unikornv1.Volume, status string) {
	if strings.HasPrefix(status, volumeStatusError) {
		volume.SetHealthCondition(corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "the provider reported the volume in an error state")

		return
	}

	switch status {
	case "creating", "available", "reserved", "attaching", "in-use", "detaching", "managing", "maintenance", "restoring-backup", "awaiting-transfer", "backing-up", "downloading", "uploading", "retyping", "extending":
		volume.SetHealthCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "the provider volume state is healthy")
	case "deleting":
		volume.SetHealthCondition(corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "the provider volume is being deleted")
	default:
		volume.SetHealthCondition(corev1.ConditionUnknown, unikornv1core.ConditionReasonUnknown, "the provider volume state is unknown")
	}
}

func projectVolumeState(volume *unikornv1.Volume, cinderVolume *volumes.Volume) error {
	size, err := volumeSize(cinderVolume.Size)
	if err != nil {
		return err
	}

	volume.Status.Size = &size
	setVolumeHealth(volume, cinderVolume.Status)

	return nil
}
