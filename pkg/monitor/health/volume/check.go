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
	apiMeta "k8s.io/apimachinery/pkg/api/meta"

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

func setObservedStatus(volume *unikornv1.Volume, observation *providertypes.VolumeObservation) {
	size := observation.Size.DeepCopy()
	volume.Status.Size = &size

	switch observation.Status {
	case providertypes.VolumeStatusError:
		volume.SetHealthCondition(corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "the provider reported the volume in an error state")
	case providertypes.VolumeStatusDeleting:
		volume.SetHealthCondition(corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "the provider volume is being deleted")
	case providertypes.VolumeStatusUnknown:
		volume.SetHealthCondition(corev1.ConditionUnknown, unikornv1core.ConditionReasonUnknown, "the provider volume state is unknown")
	case providertypes.VolumeStatusCreating,
		providertypes.VolumeStatusAvailable,
		providertypes.VolumeStatusAttaching,
		providertypes.VolumeStatusAttached,
		providertypes.VolumeStatusDetaching,
		providertypes.VolumeStatusUpdating:
		volume.SetHealthCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "the provider volume state is healthy")
	default:
		volume.SetHealthCondition(corev1.ConditionUnknown, unikornv1core.ConditionReasonUnknown, "the provider volume state is unknown")
	}
}

func setMissingStatus(volume *unikornv1.Volume) {
	volume.Status.Size = nil
	volume.SetHealthCondition(corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "the provider volume is missing")
}

func setObservationFailureStatus(volume *unikornv1.Volume) {
	volume.SetHealthCondition(corev1.ConditionUnknown, unikornv1core.ConditionReasonUnknown, "unable to observe provider volume state")
}

func logTransitions(ctx context.Context, before, after *unikornv1.Volume) {
	logger := volumeLogger(ctx, after)

	oldHealth, oldErr := unikornv1core.GetHealthyCondition(before)
	newHealth, newErr := unikornv1core.GetHealthyCondition(after)

	if newErr == nil && (oldErr != nil || oldHealth.Status != newHealth.Status || oldHealth.Reason != newHealth.Reason || oldHealth.Message != newHealth.Message) {
		fromStatus := corev1.ConditionUnknown
		fromReason := unikornv1core.HealthConditionReason("")
		fromMessage := ""

		if oldErr == nil {
			fromStatus = oldHealth.Status
			fromReason = oldHealth.Reason
			fromMessage = oldHealth.Message
		}

		logger.Info("volume health transition",
			"from_status", fromStatus,
			"from_health", fromReason,
			"from_message", fromMessage,
			"to_status", newHealth.Status,
			"to_health", newHealth.Reason,
			"to_message", newHealth.Message,
		)
	}
}

func isFatal(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

type providerEntry struct {
	provider providertypes.Provider
	err      error
}

func (c *Checker) resolveProvider(ctx context.Context, cache map[string]providerEntry, regionID string) (providertypes.Provider, error) {
	if entry, ok := cache[regionID]; ok {
		return entry.provider, entry.err
	}

	provider, err := c.providers.LookupCloud(regionID)
	if err != nil {
		if !isFatal(err) {
			log.FromContext(ctx).Error(err, "failed to resolve volume provider, skipping", "region_id", regionID)
			cache[regionID] = providerEntry{err: err}
		}

		return nil, err
	}

	cache[regionID] = providerEntry{provider: provider}

	return provider, nil
}

//nolint:cyclop // The branches keep independent provider failures isolated to the affected Volume.
func (c *Checker) processVolume(ctx context.Context, volume *unikornv1.Volume, providers map[string]providerEntry) error {
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

	provider, err := c.resolveProvider(ctx, providers, regionID)
	if err != nil {
		if isFatal(err) {
			return err
		}

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
	apiMeta.RemoveStatusCondition(&updated.Status.Conditions, string(unikornv1core.ConditionActive))

	observation, err := provider.ObserveVolume(ctx, identity, volume)

	switch {
	case isFatal(err):
		return err
	case errors.Is(err, coreerrors.ErrResourceNotFound):
		available, availableErr := unikornv1core.GetAvailableCondition(volume)
		if availableErr != nil || available.Status != corev1.ConditionTrue || available.Reason != unikornv1core.ConditionReasonProvisioned {
			volumeLogger(ctx, volume).Info("provider volume not found before provisioning completed")

			break
		}

		setMissingStatus(updated)
	case err != nil:
		volumeLogger(ctx, volume).Error(err, "failed to observe volume")
		setObservationFailureStatus(updated)
	case observation == nil:
		volumeLogger(ctx, volume).Error(fmt.Errorf("%w: nil volume observation", coreerrors.ErrConsistency), "failed to observe volume")
		setObservationFailureStatus(updated)
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

	providers := make(map[string]providerEntry)

	for i := range volumes.Items {
		if err := c.processVolume(ctx, &volumes.Items[i], providers); err != nil {
			return err
		}
	}

	return nil
}
