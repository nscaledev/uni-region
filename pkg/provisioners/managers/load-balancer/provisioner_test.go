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

package loadbalancer_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	identitymock "github.com/unikorn-cloud/identity/pkg/openapi/mock"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"
	loadbalancer "github.com/unikorn-cloud/region/pkg/provisioners/managers/load-balancer"

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
	testNetworkID    = "network-1"
	testLBName       = "lb-1"
	testOrganization = "00000000-0000-0000-0000-000000000001"
	testProject      = "00000000-0000-0000-0000-000000000002"
	testAllocationID = "00000000-0000-0000-0000-000000000003"
)

// errProviderDeleteSentinel is a static sentinel used to verify that Deprovision
// returns the provider's DeleteLoadBalancer error before doing anything else.
var errProviderDeleteSentinel = errors.New("provider delete failed")

// errProviderCreateSentinel is a static sentinel used to verify that Provision
// propagates the provider's CreateLoadBalancer error unchanged.
var errProviderCreateSentinel = errors.New("provider create failed")

func testClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme, err := coreclient.NewScheme(unikornv1.AddToScheme)
	require.NoError(t, err)

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func testLoadBalancer(opts ...func(*unikornv1.LoadBalancer)) *unikornv1.LoadBalancer {
	lb := &unikornv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testLBName,
			Namespace: testNamespace,
			Labels: map[string]string{
				constants.RegionLabel:   testRegionID,
				constants.IdentityLabel: testIdentityID,
				constants.NetworkLabel:  testNetworkID,
			},
		},
	}

	for _, opt := range opts {
		opt(lb)
	}

	return lb
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

func testNetwork(ready bool) *unikornv1.Network {
	network := &unikornv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testNetworkID,
			Namespace: testNamespace,
		},
	}

	if ready {
		network.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "")
	}

	return network
}

func TestProvision_NetworkNotReady(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	provider := mocktypes.NewMockProvider(ctrl)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	lb := testLoadBalancer()
	cli := testClient(t, lb, testIdentity(true), testNetwork(false))

	prov := loadbalancer.NewForTest(lb, providers, nil)
	err := prov.Provision(coreclient.NewContext(t.Context(), cli))
	require.ErrorIs(t, err, provisioners.ErrYield)
}

func TestProvision_IdentityNotReady(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	provider := mocktypes.NewMockProvider(ctrl)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	lb := testLoadBalancer()
	cli := testClient(t, lb, testIdentity(false), testNetwork(true))

	prov := loadbalancer.NewForTest(lb, providers, nil)
	err := prov.Provision(coreclient.NewContext(t.Context(), cli))
	require.ErrorIs(t, err, provisioners.ErrYield)
}

func TestProvision_HappyPath(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	lb := testLoadBalancer()

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateLoadBalancer(gomock.Any(), gomock.Any(), lb).Return(nil)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	cli := testClient(t, lb, testIdentity(true), testNetwork(true))

	prov := loadbalancer.NewForTest(lb, providers, nil)
	require.NoError(t, prov.Provision(coreclient.NewContext(t.Context(), cli)))
}

func TestProvision_MissingNetworkLabel(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	provider := mocktypes.NewMockProvider(ctrl)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	lb := testLoadBalancer(func(lb *unikornv1.LoadBalancer) {
		delete(lb.Labels, constants.NetworkLabel)
	})
	cli := testClient(t, lb, testIdentity(true))

	prov := loadbalancer.NewForTest(lb, providers, nil)
	err := prov.Provision(coreclient.NewContext(t.Context(), cli))
	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}

func TestProvision_NetworkNotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	provider := mocktypes.NewMockProvider(ctrl)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	lb := testLoadBalancer()
	cli := testClient(t, lb, testIdentity(true)) // no Network

	prov := loadbalancer.NewForTest(lb, providers, nil)
	err := prov.Provision(coreclient.NewContext(t.Context(), cli))
	require.Error(t, err)
	require.True(t, kerrors.IsNotFound(err), "expected NotFound, got %v", err)
}

func TestDeprovision_ProviderDeleteFirst(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	lb := testLoadBalancer()

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().DeleteLoadBalancer(gomock.Any(), gomock.Any(), lb).Return(errProviderDeleteSentinel)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	cli := testClient(t, lb, testIdentity(true))

	prov := loadbalancer.NewForTest(lb, providers, nil)
	err := prov.Deprovision(coreclient.NewContext(t.Context(), cli))
	require.ErrorIs(t, err, errProviderDeleteSentinel)
}

// testLoadBalancerWithAllocation returns a load balancer carrying the principal
// labels and allocation annotation that the API records at creation time, so
// that Deprovision can resolve and delete the identity-service allocation.
func testLoadBalancerWithAllocation() *unikornv1.LoadBalancer {
	return testLoadBalancer(func(lb *unikornv1.LoadBalancer) {
		lb.Labels[coreconstants.OrganizationLabel] = testOrganization
		lb.Labels[coreconstants.ProjectLabel] = testProject
		lb.Annotations = map[string]string{
			coreconstants.AllocationAnnotation: testAllocationID,
		}
	})
}

func TestProvision_ProviderCreateError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	lb := testLoadBalancer()

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateLoadBalancer(gomock.Any(), gomock.Any(), lb).Return(errProviderCreateSentinel)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	cli := testClient(t, lb, testIdentity(true), testNetwork(true))

	prov := loadbalancer.NewForTest(lb, providers, nil)
	err := prov.Provision(coreclient.NewContext(t.Context(), cli))
	require.ErrorIs(t, err, errProviderCreateSentinel)
}

//nolint:dupl // distinct allocation-delete outcome (accepted vs already-gone); sharing would obscure intent.
func TestDeprovision_DeletesAllocation(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	lb := testLoadBalancerWithAllocation()

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().DeleteLoadBalancer(gomock.Any(), gomock.Any(), lb).Return(nil)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	mockIdentity.EXPECT().
		DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDWithResponse(gomock.Any(), identityids.MustParseOrganizationID(testOrganization), identityids.MustParseProjectID(testProject), identityids.MustParseAllocationID(testAllocationID)).
		Return(&identityapi.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusAccepted},
		}, nil)

	cli := testClient(t, lb, testIdentity(true))

	prov := loadbalancer.NewForTest(lb, providers, mockIdentity)
	require.NoError(t, prov.Deprovision(coreclient.NewContext(t.Context(), cli)))
}

//nolint:dupl // distinct allocation-delete outcome (accepted vs already-gone); sharing would obscure intent.
func TestDeprovision_AllocationAlreadyGone(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	lb := testLoadBalancerWithAllocation()

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().DeleteLoadBalancer(gomock.Any(), gomock.Any(), lb).Return(nil)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	mockIdentity.EXPECT().
		DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDWithResponse(gomock.Any(), identityids.MustParseOrganizationID(testOrganization), identityids.MustParseProjectID(testProject), identityids.MustParseAllocationID(testAllocationID)).
		Return(&identityapi.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
		}, nil)

	cli := testClient(t, lb, testIdentity(true))

	prov := loadbalancer.NewForTest(lb, providers, mockIdentity)
	require.NoError(t, prov.Deprovision(coreclient.NewContext(t.Context(), cli)))
}
