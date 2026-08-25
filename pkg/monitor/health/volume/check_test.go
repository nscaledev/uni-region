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
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	volumehealth "github.com/unikorn-cloud/region/pkg/monitor/health/volume"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
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

var (
	errProviderLookup = errors.New("provider lookup failed")
	errProviderState  = errors.New("provider state failed")
)

func volumeFixture() *unikornv1.Volume {
	volume := &unikornv1.Volume{ObjectMeta: metav1.ObjectMeta{
		Name: testVolumeID, Namespace: testNamespace,
		Labels: map[string]string{
			coreconstants.OrganizationLabel: testOrganizationID,
			constants.RegionLabel:           testRegionID,
			constants.IdentityLabel:         testIdentityID,
		},
	}}
	volume.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "")
	unikornv1core.UpdateCondition(&volume.Status.Conditions, unikornv1core.ConditionActive, corev1.ConditionTrue, "legacy", "legacy condition")

	return volume
}

func fakeClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme() //nolint:wsl

	require.NoError(t, unikornv1.AddToScheme(scheme))

	return fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&unikornv1.Volume{}).WithObjects(objects...).Build()
}

func runCheck(t *testing.T, volume *unikornv1.Volume, lookupErr, updateErr error, mutate func(*unikornv1.Volume)) *unikornv1.Volume {
	t.Helper()
	ctrl := gomock.NewController(t)
	provider := mocktypes.NewMockProvider(ctrl)
	providers := mockproviders.NewMockProviders(ctrl)
	if lookupErr != nil { //nolint:wsl
		providers.EXPECT().LookupCloud(testRegionID).Return(nil, lookupErr)
	} else {
		providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
		provider.EXPECT().UpdateVolumeState(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ any, _ any, got *unikornv1.Volume) error {
			if mutate != nil {
				mutate(got)
			}

			return updateErr
		})
	}

	identity := &unikornv1.Identity{ObjectMeta: metav1.ObjectMeta{Name: testIdentityID, Namespace: testNamespace}}
	k8sClient := fakeClient(t, identity, volume)

	require.NoError(t, volumehealth.New(k8sClient, testNamespace, providers).Check(t.Context()))
	updated := &unikornv1.Volume{} //nolint:wsl

	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKeyFromObject(volume), updated))

	return updated
}

func TestCheckPersistsProviderProjection(t *testing.T) {
	t.Parallel()

	updated := runCheck(t, volumeFixture(), nil, nil, func(volume *unikornv1.Volume) {
		size := resource.MustParse("20Gi")
		volume.Status.Size = &size
		unikornv1core.UpdateCondition(&volume.Status.Conditions, unikornv1core.ConditionHealthy, corev1.ConditionTrue, string(unikornv1core.ConditionReasonHealthy), "provider healthy")
	})
	require.NotNil(t, updated.Status.Size)
	require.True(t, updated.Status.Size.Equal(resource.MustParse("20Gi")))
	health, err := unikornv1core.GetHealthyCondition(updated)
	require.NoError(t, err)
	require.Equal(t, "provider healthy", health.Message)

	_, err = unikornv1core.GetCondition(updated.Status.Conditions, unikornv1core.ConditionActive)
	require.Error(t, err)
}

func TestCheckPreservesStateWhenProviderUnavailable(t *testing.T) {
	t.Parallel()

	volume := volumeFixture()
	size := resource.MustParse("10Gi")
	volume.Status.Size = &size
	unikornv1core.UpdateCondition(&volume.Status.Conditions, unikornv1core.ConditionHealthy, corev1.ConditionTrue, string(unikornv1core.ConditionReasonHealthy), "last state")
	updated := runCheck(t, volume, errProviderLookup, nil, nil)
	require.True(t, updated.Status.Size.Equal(resource.MustParse("10Gi")))
	health, err := unikornv1core.GetHealthyCondition(updated)
	require.NoError(t, err)
	require.Equal(t, "last state", health.Message)
}

func TestCheckPreservesStateWhenProviderObservationFails(t *testing.T) {
	t.Parallel()

	volume := volumeFixture()
	unikornv1core.UpdateCondition(&volume.Status.Conditions, unikornv1core.ConditionHealthy, corev1.ConditionTrue, string(unikornv1core.ConditionReasonHealthy), "last state")
	updated := runCheck(t, volume, nil, errProviderState, nil)
	health, err := unikornv1core.GetHealthyCondition(updated)
	require.NoError(t, err)
	require.Equal(t, "last state", health.Message)
}

func TestCheckPersistsProviderMissingProjection(t *testing.T) {
	t.Parallel()

	updated := runCheck(t, volumeFixture(), nil, nil, func(volume *unikornv1.Volume) {
		volume.Status.Size = nil
		unikornv1core.UpdateCondition(&volume.Status.Conditions, unikornv1core.ConditionHealthy, corev1.ConditionFalse, string(unikornv1core.ConditionReasonDegraded), "the provider volume is missing")
	})
	health, err := unikornv1core.GetHealthyCondition(updated)
	require.NoError(t, err)
	require.Equal(t, unikornv1core.ConditionReasonDegraded, health.Reason)
	require.Nil(t, updated.Status.Size)
}
