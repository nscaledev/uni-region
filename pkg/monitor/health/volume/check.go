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

package volume

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-logr/logr"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers"
	providertypes "github.com/unikorn-cloud/region/pkg/providers/types"

	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Checker projects provider-observed Volume state into Region status.
type Checker struct {
	client    client.Client
	namespace string
	providers providers.Providers
}

// New creates a Volume health checker.
func New(client client.Client, namespace string, providers providers.Providers) *Checker {
	return &Checker{client: client, namespace: namespace, providers: providers}
}

func volumeLogger(ctx context.Context, volume *unikornv1.Volume) logr.Logger {
	return log.FromContext(ctx).WithValues(
		"volume_id", volume.Name,
		"org_id", volume.Labels[coreconstants.OrganizationLabel],
		"region_id", volume.Labels[constants.RegionLabel],
	)
}

func volumePhase(status providertypes.VolumeStatus) unikornv1.VolumePhaseReason {
	switch status {
	case providertypes.VolumeStatusCreating:
		return unikornv1.VolumePhaseReasonCreating
	case providertypes.VolumeStatusAvailable:
		return unikornv1.VolumePhaseReasonAvailable
	case providertypes.VolumeStatusAttaching:
		return unikornv1.VolumePhaseReasonAttaching
	case providertypes.VolumeStatusAttached:
		return unikornv1.VolumePhaseReasonAttached
	case providertypes.VolumeStatusDetaching:
		return unikornv1.VolumePhaseReasonDetaching
	case providertypes.VolumeStatusUpdating:
		return unikornv1.VolumePhaseReasonUpdating
	case providertypes.VolumeStatusDeleting:
		return unikornv1.VolumePhaseReasonDeleting
	case providertypes.VolumeStatusError:
		return unikornv1.VolumePhaseReasonError
	case providertypes.VolumeStatusUnknown:
		return unikornv1.VolumePhaseReasonUnknown
	}

	return unikornv1.VolumePhaseReasonUnknown
}

func setObservedStatus(volume *unikornv1.Volume, observation *providertypes.VolumeObservation) {
	size := observation.Size.DeepCopy()
	volume.Status.Size = &size
	phase := volumePhase(observation.Status)
	volume.SetVolumePhase(phase)

	switch phase {
	case unikornv1.VolumePhaseReasonError:
		volume.SetHealthCondition(corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "the provider reported the volume in an error state")
	case unikornv1.VolumePhaseReasonUnknown:
		volume.SetHealthCondition(corev1.ConditionUnknown, unikornv1core.ConditionReasonUnknown, "the provider volume state is unknown")
	case unikornv1.VolumePhaseReasonMissing:
		volume.SetHealthCondition(corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "the provider volume is missing")
	case unikornv1.VolumePhaseReasonCreating,
		unikornv1.VolumePhaseReasonAvailable,
		unikornv1.VolumePhaseReasonAttaching,
		unikornv1.VolumePhaseReasonAttached,
		unikornv1.VolumePhaseReasonDetaching,
		unikornv1.VolumePhaseReasonUpdating,
		unikornv1.VolumePhaseReasonDeleting:
		volume.SetHealthCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "the provider volume state is healthy")
	}
}

func setMissingStatus(volume *unikornv1.Volume) {
	volume.Status.Size = nil
	volume.SetVolumePhase(unikornv1.VolumePhaseReasonMissing)
	volume.SetHealthCondition(corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "the provider volume is missing")
}

func logTransitions(ctx context.Context, before, after *unikornv1.Volume) {
	logger := volumeLogger(ctx, after)

	oldPhase, oldErr := unikornv1.GetVolumePhase(before)
	newPhase, newErr := unikornv1.GetVolumePhase(after)

	if newErr == nil && (oldErr != nil || oldPhase.Reason != newPhase.Reason) {
		from := ""

		if oldErr == nil {
			from = string(oldPhase.Reason)
		}

		logger.Info("volume phase transition", "from_phase", from, "to_phase", newPhase.Reason)
	}

	oldHealth, oldErr := unikornv1core.GetHealthyCondition(before)
	newHealth, newErr := unikornv1core.GetHealthyCondition(after)

	if newErr == nil && (oldErr != nil || oldHealth.Status != newHealth.Status || oldHealth.Reason != newHealth.Reason) {
		from := ""

		if oldErr == nil {
			from = string(oldHealth.Reason)
		}

		logger.Info("volume health transition", "from_health", from, "to_health", newHealth.Reason)
	}
}

func isFatal(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

//nolint:cyclop // The branches keep independent provider failures isolated to the affected Volume.
func (c *Checker) processVolume(ctx context.Context, volume *unikornv1.Volume) error {
	if volume.DeletionTimestamp != nil {
		return nil
	}

	regionID, ok := volume.Labels[constants.RegionLabel]
	if !ok {
		volumeLogger(ctx, volume).Info("volume missing region label, skipping")
		return nil
	}

	identityID, ok := volume.Labels[constants.IdentityLabel]
	if !ok {
		volumeLogger(ctx, volume).Info("volume missing identity label, skipping")
		return nil
	}

	provider, err := c.providers.LookupCloud(regionID)
	if err != nil {
		if isFatal(err) {
			return err
		}

		volumeLogger(ctx, volume).Error(err, "failed to resolve volume provider, skipping")

		return nil
	}

	identity := &unikornv1.Identity{}
	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: identityID}, identity); err != nil {
		if isFatal(err) {
			return err
		}

		volumeLogger(ctx, volume).Error(err, "failed to resolve volume identity, skipping")

		return nil
	}

	updated := volume.DeepCopy()
	observation, err := provider.ObserveVolume(ctx, identity, volume)

	switch {
	case isFatal(err):
		return err
	case errors.Is(err, coreerrors.ErrResourceNotFound):
		setMissingStatus(updated)
	case err != nil:
		volumeLogger(ctx, volume).Error(err, "failed to observe volume, skipping")

		return nil
	case observation == nil:
		volumeLogger(ctx, volume).Error(fmt.Errorf("%w: nil volume observation", coreerrors.ErrConsistency), "failed to observe volume, skipping")

		return nil
	default:
		setObservedStatus(updated, observation)
	}

	if err := c.client.Status().Patch(ctx, updated, client.MergeFromWithOptions(volume, &client.MergeFromWithOptimisticLock{})); err != nil {
		if isFatal(err) {
			return err
		}

		volumeLogger(ctx, volume).Error(err, "failed to update volume status, skipping")

		return nil
	}

	logTransitions(ctx, volume, updated)

	return nil
}

// Check observes every non-deleting Volume in the configured namespace.
func (c *Checker) Check(ctx context.Context) error {
	volumes := &unikornv1.VolumeList{}
	if err := c.client.List(ctx, volumes, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return err
	}

	for i := range volumes.Items {
		if err := c.processVolume(ctx, &volumes.Items[i]); err != nil {
			return err
		}
	}

	return nil
}
