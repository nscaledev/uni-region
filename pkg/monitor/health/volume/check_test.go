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

package volume_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	volumehealth "github.com/unikorn-cloud/region/pkg/monitor/health/volume"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	providertypes "github.com/unikorn-cloud/region/pkg/providers/types"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace      = "test-ns"
	testRegionID       = "region-1"
	testIdentityID     = "identity-1"
	testVolumeID       = "11111111-1111-4111-8111-111111111111"
	testOrganizationID = "00000000-0000-4000-8000-000000000001"
)

var errProviderObservation = errors.New("provider observation failed")

type captureSink struct {
	entries   *[]map[string]any
	presetKVs []any
}

func newCaptureSink() *captureSink {
	entries := make([]map[string]any, 0)

	return &captureSink{entries: &entries}
}

func (s *captureSink) Init(logr.RuntimeInfo)        {}
func (s *captureSink) Enabled(int) bool             { return true }
func (s *captureSink) WithName(string) logr.LogSink { return s }

func (s *captureSink) WithValues(kvs ...any) logr.LogSink {
	result := *s
	result.presetKVs = append(append([]any{}, s.presetKVs...), kvs...)

	return &result
}

func (s *captureSink) record(msg string, kvs ...any) {
	entry := map[string]any{"_msg": msg}

	for i := 0; i+1 < len(s.presetKVs); i += 2 {
		entry[fmt.Sprint(s.presetKVs[i])] = s.presetKVs[i+1]
	}

	for i := 0; i+1 < len(kvs); i += 2 {
		entry[fmt.Sprint(kvs[i])] = kvs[i+1]
	}

	*s.entries = append(*s.entries, entry)
}

func (s *captureSink) Info(_ int, msg string, kvs ...any) {
	s.record(msg, kvs...)
}

func (s *captureSink) Error(err error, msg string, kvs ...any) {
	s.record(msg, append(kvs, "error", err)...)
}

func (s *captureSink) entry(msg string) map[string]any {
	for _, entry := range *s.entries {
		if entry["_msg"] == msg {
			return entry
		}
	}

	return nil
}

func volumeFixture() *unikornv1.Volume {
	volume := &unikornv1.Volume{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testVolumeID,
			Namespace: testNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel: testOrganizationID,
				constants.RegionLabel:           testRegionID,
				constants.IdentityLabel:         testIdentityID,
			},
		},
	}
	volume.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "")

	return volume
}

func fakeClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&unikornv1.Volume{}).
		WithObjects(objects...).
		Build()
}

func runCheck(t *testing.T, volume *unikornv1.Volume, observation *providertypes.VolumeObservation, observationErr error) (*unikornv1.Volume, *captureSink) {
	t.Helper()
	ctrl := gomock.NewController(t)
	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().ObserveVolume(gomock.Any(), gomock.Any(), gomock.Any()).Return(observation, observationErr)

	providerSet := mockproviders.NewMockProviders(ctrl)
	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	identity := &unikornv1.Identity{ObjectMeta: metav1.ObjectMeta{Name: testIdentityID, Namespace: testNamespace}}
	k8sClient := fakeClient(t, identity, volume)
	sink := newCaptureSink()
	ctx := logr.NewContext(t.Context(), logr.New(sink))
	require.NoError(t, volumehealth.New(k8sClient, testNamespace, providerSet).Check(ctx))

	updated := &unikornv1.Volume{}
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(volume), updated))

	return updated, sink
}

func TestCheckProjectsEveryNeutralVolumeStatus(t *testing.T) {
	t.Parallel()

	tests := map[providertypes.VolumeStatus]struct {
		phase        unikornv1.VolumePhaseReason
		activeStatus corev1.ConditionStatus
		healthStatus corev1.ConditionStatus
		healthReason unikornv1core.HealthConditionReason
	}{
		providertypes.VolumeStatusCreating:  {unikornv1.VolumePhaseReasonCreating, corev1.ConditionFalse, corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy},
		providertypes.VolumeStatusAvailable: {unikornv1.VolumePhaseReasonAvailable, corev1.ConditionTrue, corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy},
		providertypes.VolumeStatusAttaching: {unikornv1.VolumePhaseReasonAttaching, corev1.ConditionFalse, corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy},
		providertypes.VolumeStatusAttached:  {unikornv1.VolumePhaseReasonAttached, corev1.ConditionTrue, corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy},
		providertypes.VolumeStatusDetaching: {unikornv1.VolumePhaseReasonDetaching, corev1.ConditionFalse, corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy},
		providertypes.VolumeStatusUpdating:  {unikornv1.VolumePhaseReasonUpdating, corev1.ConditionFalse, corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy},
		providertypes.VolumeStatusDeleting:  {unikornv1.VolumePhaseReasonDeleting, corev1.ConditionFalse, corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy},
		providertypes.VolumeStatusError:     {unikornv1.VolumePhaseReasonError, corev1.ConditionFalse, corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded},
		providertypes.VolumeStatusUnknown:   {unikornv1.VolumePhaseReasonUnknown, corev1.ConditionFalse, corev1.ConditionUnknown, unikornv1core.ConditionReasonUnknown},
	}

	for status, want := range tests {
		t.Run(string(status), func(t *testing.T) {
			t.Parallel()
			updated, _ := runCheck(t, volumeFixture(), &providertypes.VolumeObservation{Size: resource.MustParse("20Gi"), Status: status}, nil)

			require.NotNil(t, updated.Status.Size)
			require.True(t, updated.Status.Size.Equal(resource.MustParse("20Gi")))

			phase, err := unikornv1.GetVolumePhase(updated)
			require.NoError(t, err)
			require.Equal(t, want.phase, phase.Reason)
			require.Equal(t, want.activeStatus, phase.Status)

			health, err := unikornv1core.GetHealthyCondition(updated)
			require.NoError(t, err)
			require.Equal(t, want.healthStatus, health.Status)
			require.Equal(t, want.healthReason, health.Reason)

			available, err := unikornv1core.GetAvailableCondition(updated)
			require.NoError(t, err)
			require.Equal(t, unikornv1core.ConditionReasonProvisioned, available.Reason)
		})
	}
}

func TestCheckProjectsMissingProviderVolumeAndLogsTransition(t *testing.T) {
	t.Parallel()

	volume := volumeFixture()
	size := resource.MustParse("10Gi")
	volume.Status.Size = &size
	volume.SetVolumePhase(unikornv1.VolumePhaseReasonAvailable)
	volume.SetHealthCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "")

	updated, sink := runCheck(t, volume, nil, coreerrors.ErrResourceNotFound)
	require.Nil(t, updated.Status.Size)

	phase, err := unikornv1.GetVolumePhase(updated)
	require.NoError(t, err)
	require.Equal(t, unikornv1.VolumePhaseReasonMissing, phase.Reason)

	health, err := unikornv1core.GetHealthyCondition(updated)
	require.NoError(t, err)
	require.Equal(t, corev1.ConditionFalse, health.Status)
	require.Equal(t, unikornv1core.ConditionReasonDegraded, health.Reason)

	available, err := unikornv1core.GetAvailableCondition(updated)
	require.NoError(t, err)
	require.Equal(t, unikornv1core.ConditionReasonProvisioned, available.Reason)

	entry := sink.entry("volume phase transition")
	require.Equal(t, testVolumeID, entry["volume_id"])
	require.Equal(t, testOrganizationID, entry["org_id"])
	require.Equal(t, testRegionID, entry["region_id"])
	require.Equal(t, string(unikornv1.VolumePhaseReasonAvailable), entry["from_phase"])
	require.Equal(t, unikornv1.VolumePhaseReasonMissing, entry["to_phase"])
}

func TestCheckPreservesLastObservationOnProviderErrorAndLogs(t *testing.T) {
	t.Parallel()

	volume := volumeFixture()
	size := resource.MustParse("10Gi")
	volume.Status.Size = &size
	volume.SetVolumePhase(unikornv1.VolumePhaseReasonAttached)
	volume.SetHealthCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "")
	updated, sink := runCheck(t, volume, nil, errProviderObservation)
	require.NotNil(t, updated.Status.Size)
	require.True(t, updated.Status.Size.Equal(size))

	phase, err := unikornv1.GetVolumePhase(updated)
	require.NoError(t, err)
	require.Equal(t, unikornv1.VolumePhaseReasonAttached, phase.Reason)

	health, err := unikornv1core.GetHealthyCondition(updated)
	require.NoError(t, err)
	require.Equal(t, corev1.ConditionTrue, health.Status)
	require.Equal(t, unikornv1core.ConditionReasonHealthy, health.Reason)

	available, err := unikornv1core.GetAvailableCondition(updated)
	require.NoError(t, err)
	require.Equal(t, unikornv1core.ConditionReasonProvisioned, available.Reason)

	entry := sink.entry("failed to observe volume, skipping")
	require.Equal(t, testVolumeID, entry["volume_id"])
	require.Equal(t, testOrganizationID, entry["org_id"])
	require.Equal(t, testRegionID, entry["region_id"])

	loggedErr, ok := entry["error"].(error)
	require.True(t, ok)
	require.ErrorIs(t, loggedErr, errProviderObservation)
}
