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
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	identitymock "github.com/unikorn-cloud/identity/pkg/openapi/mock"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"
	volume "github.com/unikorn-cloud/region/pkg/provisioners/managers/volume"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace    = "test-ns"
	testRegionID     = "region-1"
	testIdentityID   = "identity-1"
	testVolumeID     = "11111111-1111-4111-8111-111111111111"
	testOrganization = "00000000-0000-4000-8000-000000000001"
	testProject      = "00000000-0000-4000-8000-000000000002"
	testAllocationID = "00000000-0000-4000-8000-000000000003"
)

var (
	errProviderCreate   = errors.New("provider create failed")
	errProviderDelete   = errors.New("provider delete failed")
	errProviderLookup   = errors.New("provider lookup failed")
	errAllocationDelete = errors.New("allocation delete failed")
)

func testVolume(withAllocation bool) *unikornv1.Volume {
	resource := &unikornv1.Volume{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testVolumeID,
			Namespace: testNamespace,
			Labels: map[string]string{
				constants.RegionLabel:           testRegionID,
				constants.IdentityLabel:         testIdentityID,
				coreconstants.OrganizationLabel: testOrganization,
				coreconstants.ProjectLabel:      testProject,
			},
		},
	}

	if withAllocation {
		resource.Annotations = map[string]string{
			coreconstants.AllocationAnnotation: testAllocationID,
		}
	}

	return resource
}

func testIdentity(ready bool) *unikornv1.Identity {
	identity := &unikornv1.Identity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testIdentityID,
			Namespace: testNamespace,
		},
	}

	if ready {
		identity.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "")
	}

	return identity
}

func controllerContext(t *testing.T, objects ...client.Object) context.Context {
	t.Helper()

	scheme, err := coreclient.NewScheme(unikornv1.AddToScheme)
	require.NoError(t, err)

	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

	return coreclient.NewContext(t.Context(), cli)
}

func volumeMocks(t *testing.T) (*mocktypes.MockProvider, *mockproviders.MockProviders) {
	t.Helper()

	ctrl := gomock.NewController(t)
	provider := mocktypes.NewMockProvider(ctrl)
	providerSet := mockproviders.NewMockProviders(ctrl)

	return provider, providerSet
}

func identityNamed() gomock.Matcher {
	return gomock.Cond(func(identity *unikornv1.Identity) bool {
		return identity != nil && identity.Name == testIdentityID
	})
}

func expectAllocationDelete(mockIdentity *identitymock.MockClientWithResponsesInterface, status int) *gomock.Call {
	return mockIdentity.EXPECT().
		DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDWithResponse(
			gomock.Any(),
			identityids.MustParseOrganizationID(testOrganization),
			identityids.MustParseProjectID(testProject),
			identityids.MustParseAllocationID(testAllocationID),
		).
		Return(&identityapi.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDResponse{
			HTTPResponse: &http.Response{StatusCode: status},
		}, nil)
}

func TestProvisionCreatesVolume(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	identity := testIdentity(true)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	require.NoError(t, provisioner.Provision(controllerContext(t, resource, identity)))
}

func TestProvisionWaitsForIdentity(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	identity := testIdentity(false)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	err := provisioner.Provision(controllerContext(t, resource, identity))
	require.ErrorIs(t, err, provisioners.ErrYield)
}

func TestProvisionReturnsProviderYield(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	identity := testIdentity(true)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(provisioners.ErrYield)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	err := provisioner.Provision(controllerContext(t, resource, identity))
	require.ErrorIs(t, err, provisioners.ErrYield)
}

func TestProvisionReturnsProviderError(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	identity := testIdentity(true)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(errProviderCreate)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	err := provisioner.Provision(controllerContext(t, resource, identity))
	require.ErrorIs(t, err, errProviderCreate)
}

func TestDeprovisionDeletesProviderForUnreadyIdentity(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	identity := testIdentity(false)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	provider.EXPECT().DeleteVolume(gomock.Any(), identityNamed(), resource).Return(nil)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	require.NoError(t, provisioner.Deprovision(controllerContext(t, resource, identity)))
}

func TestDeprovisionProviderFailurePreservesAllocation(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(true)
	identity := testIdentity(false)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	provider.EXPECT().DeleteVolume(gomock.Any(), identityNamed(), resource).Return(errProviderDelete)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	err := provisioner.Deprovision(controllerContext(t, resource, identity))
	require.ErrorIs(t, err, errProviderDelete)
	require.Equal(t, testAllocationID, resource.Annotations[coreconstants.AllocationAnnotation])
}

func TestDeprovisionProviderAlreadyAbsentReleasesAllocation(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	provider := mocktypes.NewMockProvider(ctrl)
	providerSet := mockproviders.NewMockProviders(ctrl)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	resource := testVolume(true)
	identity := testIdentity(false)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	gomock.InOrder(
		provider.EXPECT().DeleteVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		expectAllocationDelete(mockIdentity, http.StatusAccepted),
	)

	provisioner := volume.NewForTest(resource, providerSet, mockIdentity)
	require.NoError(t, provisioner.Deprovision(controllerContext(t, resource, identity)))
}

func TestDeprovisionUnsupportedProviderReleasesAllocation(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	providerSet := mockproviders.NewMockProviders(ctrl)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	resource := testVolume(true)
	identity := testIdentity(false)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(nil, providers.ErrRegionWrongKind)
	expectAllocationDelete(mockIdentity, http.StatusAccepted)

	provisioner := volume.NewForTest(resource, providerSet, mockIdentity)
	require.NoError(t, provisioner.Deprovision(controllerContext(t, resource, identity)))
}

func TestDeprovisionProviderLookupFailurePreservesAllocation(t *testing.T) {
	t.Parallel()

	_, providerSet := volumeMocks(t)
	resource := testVolume(true)
	identity := testIdentity(false)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(nil, errProviderLookup)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	err := provisioner.Deprovision(controllerContext(t, resource, identity))
	require.ErrorIs(t, err, errProviderLookup)
	require.Equal(t, testAllocationID, resource.Annotations[coreconstants.AllocationAnnotation])
}

func TestDeprovisionAllocationAlreadyGone(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	provider := mocktypes.NewMockProvider(ctrl)
	providerSet := mockproviders.NewMockProviders(ctrl)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	resource := testVolume(true)
	identity := testIdentity(false)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	gomock.InOrder(
		provider.EXPECT().DeleteVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		expectAllocationDelete(mockIdentity, http.StatusNotFound),
	)

	provisioner := volume.NewForTest(resource, providerSet, mockIdentity)
	require.NoError(t, provisioner.Deprovision(controllerContext(t, resource, identity)))
}

func TestDeprovisionMissingAllocationMetadata(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	identity := testIdentity(false)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	provider.EXPECT().DeleteVolume(gomock.Any(), identityNamed(), resource).Return(nil)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	require.NoError(t, provisioner.Deprovision(controllerContext(t, resource, identity)))
}

func TestDeprovisionMissingIdentityPreservesAllocation(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	providerSet := mockproviders.NewMockProviders(ctrl)
	resource := testVolume(true)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	err := provisioner.Deprovision(controllerContext(t, resource))
	require.True(t, kerrors.IsNotFound(err))
	require.Equal(t, testAllocationID, resource.Annotations[coreconstants.AllocationAnnotation])
}

func TestDeprovisionRetriesAllocationCleanupAfterProviderCleanup(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	provider := mocktypes.NewMockProvider(ctrl)
	providerSet := mockproviders.NewMockProviders(ctrl)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	resource := testVolume(true)
	identity := testIdentity(false)

	firstAllocationDelete := mockIdentity.EXPECT().
		DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDWithResponse(
			gomock.Any(),
			identityids.MustParseOrganizationID(testOrganization),
			identityids.MustParseProjectID(testProject),
			identityids.MustParseAllocationID(testAllocationID),
		).
		Return(nil, errAllocationDelete)

	gomock.InOrder(
		providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil),
		provider.EXPECT().DeleteVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		firstAllocationDelete,
		providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil),
		provider.EXPECT().DeleteVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		expectAllocationDelete(mockIdentity, http.StatusAccepted),
	)

	provisioner := volume.NewForTest(resource, providerSet, mockIdentity)
	ctx := controllerContext(t, resource, identity)

	err := provisioner.Deprovision(ctx)
	require.ErrorIs(t, err, errAllocationDelete)
	require.Equal(t, testAllocationID, resource.Annotations[coreconstants.AllocationAnnotation])

	require.NoError(t, provisioner.Deprovision(ctx))
}
