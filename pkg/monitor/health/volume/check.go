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

	"github.com/go-logr/logr"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers"
	providertypes "github.com/unikorn-cloud/region/pkg/providers/types"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"

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

func logTransitions(ctx context.Context, before, after *unikornv1.Volume) {
	logger := volumeLogger(ctx, after)

	oldHealth, oldErr := unikornv1core.GetHealthyCondition(before)
	newHealth, newErr := unikornv1core.GetHealthyCondition(after)

	if healthChanged(oldHealth, oldErr, newHealth, newErr) {
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

func healthChanged(oldHealth *unikornv1core.TypedCondition[unikornv1core.HealthConditionReason], oldErr error, newHealth *unikornv1core.TypedCondition[unikornv1core.HealthConditionReason], newErr error) bool {
	if newErr != nil {
		return false
	}

	return oldErr != nil || oldHealth.Status != newHealth.Status || oldHealth.Reason != newHealth.Reason || oldHealth.Message != newHealth.Message
}

func isFatal(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

type providerEntry struct {
	provider providertypes.Provider
	err      error
}

func (c *Checker) resolveProvider(cache map[string]providerEntry, regionID string) (providertypes.Provider, error) {
	if entry, ok := cache[regionID]; ok {
		return entry.provider, entry.err
	}

	provider, err := c.providers.LookupCloud(regionID)
	if err != nil {
		cache[regionID] = providerEntry{err: err}
		return nil, err
	}

	cache[regionID] = providerEntry{provider: provider}

	return provider, nil
}

func (c *Checker) patchStatus(ctx context.Context, volume, updated *unikornv1.Volume) error {
	if err := c.client.Status().Patch(ctx, updated, client.MergeFromWithOptions(volume, &client.MergeFromWithOptimisticLock{})); err != nil {
		return err
	}

	logTransitions(ctx, volume, updated)

	return nil
}

func (c *Checker) observeVolume(ctx context.Context, volume *unikornv1.Volume, providers map[string]providerEntry) error {
	regionID := volume.Labels[constants.RegionLabel]
	identityID := volume.Labels[constants.IdentityLabel]
	updated := volume.DeepCopy()

	provider, err := c.resolveProvider(providers, regionID)
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

	if err := provider.UpdateVolumeState(ctx, identity, updated); err != nil {
		if isFatal(err) {
			return err
		}

		volumeLogger(ctx, volume).Error(err, "failed to update provider volume state, skipping")

		return nil
	}

	if equality.Semantic.DeepEqual(volume.Status, updated.Status) {
		return nil
	}

	if err := c.patchStatus(ctx, volume, updated); err != nil {
		if isFatal(err) {
			return err
		}

		volumeLogger(ctx, volume).Error(err, "failed to update volume status, skipping")
	}

	return nil
}

func (c *Checker) processVolume(ctx context.Context, volume *unikornv1.Volume, providers map[string]providerEntry) error {
	if volume.DeletionTimestamp != nil {
		return nil
	}

	if volume.Labels[constants.RegionLabel] == "" {
		volumeLogger(ctx, volume).Info("volume missing region label, skipping")
		return nil
	}

	if volume.Labels[constants.IdentityLabel] == "" {
		volumeLogger(ctx, volume).Info("volume missing identity label, skipping")
		return nil
	}

	return c.observeVolume(ctx, volume, providers)
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
