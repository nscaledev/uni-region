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

package openstack_test

import (
	"errors"
	"math"
	"strconv"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/volumes"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack/mock"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

var errVolumeStateProvider = errors.New("cinder unavailable")

func observedCinderVolume(identity *regionv1.Identity, volume *regionv1.Volume, status string, size int) *volumes.Volume {
	return &volumes.Volume{
		ID:     "provider-volume-id",
		Name:   "volume-" + volume.Name,
		Status: status,
		Size:   size,
		Metadata: map[string]string{
			"region:volume_id":         volume.Name,
			"identity:organization_id": organizationID,
			"identity:project_id":      projectID,
			"region:region_id":         regionID,
			"region:network_id":        volume.Spec.NetworkID,
			"region:identity_id":       identity.Name,
		},
	}
}

func updateVolumeState(t *testing.T, identity *regionv1.Identity, volume *regionv1.Volume, providerVolume *volumes.Volume, providerErr error) error {
	t.Helper()
	c := gomock.NewController(t)
	blockStorage := mock.NewMockVolumeInterface(c)
	blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(providerVolume, providerErr)

	return openstack.UpdateVolumeStateWithClient(t.Context(), blockStorage, identity, volume)
}

func TestUpdateVolumeStateProjectsSizeAndHealth(t *testing.T) {
	t.Parallel()

	identity, volume := identityFixture(), volumeFixture()
	require.NoError(t, updateVolumeState(t, identity, volume, observedCinderVolume(identity, volume, "available", 20), nil))

	require.NotNil(t, volume.Status.Size)
	require.True(t, volume.Status.Size.Equal(resource.MustParse("20Gi")))
	health, err := unikornv1core.GetHealthyCondition(volume)
	require.NoError(t, err)
	require.Equal(t, corev1.ConditionTrue, health.Status)
	require.Equal(t, unikornv1core.ConditionReasonHealthy, health.Reason)
}

func TestUpdateVolumeStateMapsCinderStatuses(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		status  corev1.ConditionStatus
		reason  unikornv1core.HealthConditionReason
		message string
	}{
		"creating":          {corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "the provider volume state is healthy"},
		"available":         {corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "the provider volume state is healthy"},
		"reserved":          {corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "the provider volume state is healthy"},
		"attaching":         {corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "the provider volume state is healthy"},
		"in-use":            {corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "the provider volume state is healthy"},
		"detaching":         {corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "the provider volume state is healthy"},
		"managing":          {corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "the provider volume state is healthy"},
		"maintenance":       {corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "the provider volume state is healthy"},
		"restoring-backup":  {corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "the provider volume state is healthy"},
		"awaiting-transfer": {corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "the provider volume state is healthy"},
		"backing-up":        {corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "the provider volume state is healthy"},
		"downloading":       {corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "the provider volume state is healthy"},
		"uploading":         {corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "the provider volume state is healthy"},
		"retyping":          {corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "the provider volume state is healthy"},
		"extending":         {corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "the provider volume state is healthy"},
		"deleting":          {corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "the provider volume is being deleted"},
		"error":             {corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "the provider reported the volume in an error state"},
		"error_deleting":    {corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "the provider reported the volume in an error state"},
		"error_managing":    {corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "the provider reported the volume in an error state"},
		"error_restoring":   {corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "the provider reported the volume in an error state"},
		"error_backing-up":  {corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "the provider reported the volume in an error state"},
		"error_extending":   {corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "the provider reported the volume in an error state"},
		"":                  {corev1.ConditionUnknown, unikornv1core.ConditionReasonUnknown, "the provider volume state is unknown"},
		"future-state":      {corev1.ConditionUnknown, unikornv1core.ConditionReasonUnknown, "the provider volume state is unknown"},
	}

	for cinderStatus, want := range tests {
		t.Run(cinderStatus, func(t *testing.T) {
			t.Parallel()

			identity, volume := identityFixture(), volumeFixture()

			require.NoError(t, updateVolumeState(t, identity, volume, observedCinderVolume(identity, volume, cinderStatus, 20), nil))

			health, err := unikornv1core.GetHealthyCondition(volume)
			require.NoError(t, err)
			require.Equal(t, want.status, health.Status)
			require.Equal(t, want.reason, health.Reason)
			require.Equal(t, want.message, health.Message)
		})
	}
}

func TestUpdateVolumeStateHandlesMissingAfterProvisioning(t *testing.T) {
	t.Parallel()

	identity, volume := identityFixture(), volumeFixture()

	volume.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "")

	size := resource.MustParse("20Gi")
	volume.Status.Size = &size

	require.NoError(t, updateVolumeState(t, identity, volume, nil, coreerrors.ErrResourceNotFound))
	require.Nil(t, volume.Status.Size)
	health, err := unikornv1core.GetHealthyCondition(volume)
	require.NoError(t, err)
	require.Equal(t, corev1.ConditionFalse, health.Status)
	require.Equal(t, unikornv1core.ConditionReasonDegraded, health.Reason)
	require.Equal(t, "the provider volume is missing", health.Message)
}

func TestUpdateVolumeStateIgnoresMissingBeforeProvisioning(t *testing.T) {
	t.Parallel()

	identity, volume := identityFixture(), volumeFixture()
	size := resource.MustParse("20Gi")
	volume.Status.Size = &size

	require.NoError(t, updateVolumeState(t, identity, volume, nil, coreerrors.ErrResourceNotFound))
	require.NotNil(t, volume.Status.Size)
	require.True(t, volume.Status.Size.Equal(size))
	_, err := unikornv1core.GetHealthyCondition(volume)
	require.Error(t, err)
}

func TestUpdateVolumeStatePreservesStateOnProviderError(t *testing.T) {
	t.Parallel()

	identity, volume := identityFixture(), volumeFixture()
	require.ErrorIs(t, updateVolumeState(t, identity, volume, nil, errVolumeStateProvider), errVolumeStateProvider)
	_, err := unikornv1core.GetHealthyCondition(volume)
	require.Error(t, err)
}

func TestUpdateVolumeStateRejectsInvalidProviderData(t *testing.T) {
	t.Parallel()

	check := func(size int) {
		identity, volume := identityFixture(), volumeFixture()

		require.ErrorIs(t, updateVolumeState(t, identity, volume, observedCinderVolume(identity, volume, "available", size), nil), coreerrors.ErrConsistency)
	}

	check(-1)

	if strconv.IntSize >= 64 {
		check(int(math.MaxInt64>>30) + 1)
	}
}

func TestUpdateVolumeStateRejectsInvalidMetadata(t *testing.T) {
	t.Parallel()

	identity, volume := identityFixture(), volumeFixture()
	cinderVolume := observedCinderVolume(identity, volume, "available", 20)
	delete(cinderVolume.Metadata, "region:volume_id")
	require.ErrorIs(t, updateVolumeState(t, identity, volume, cinderVolume, nil), coreerrors.ErrConsistency)
}
