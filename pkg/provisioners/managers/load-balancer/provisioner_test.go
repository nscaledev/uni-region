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
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/provisioners"
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
	testNamespace  = "test-ns"
	testRegionID   = "region-1"
	testIdentityID = "identity-1"
	testNetworkID  = "network-1"
	testLBName     = "lb-1"
)

// errProviderDeleteSentinel is a static sentinel used to verify that Deprovision
// returns the provider's DeleteLoadBalancer error before doing anything else.
var errProviderDeleteSentinel = errors.New("provider delete failed")

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
		identity.StatusConditionWrite(unikornv1core.ConditionAvailable, corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "")
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
		network.StatusConditionWrite(unikornv1core.ConditionAvailable, corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "")
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

	prov := loadbalancer.NewForTest(lb, providers)
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

	prov := loadbalancer.NewForTest(lb, providers)
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

	prov := loadbalancer.NewForTest(lb, providers)
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

	prov := loadbalancer.NewForTest(lb, providers)
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

	prov := loadbalancer.NewForTest(lb, providers)
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

	prov := loadbalancer.NewForTest(lb, providers)
	err := prov.Deprovision(coreclient.NewContext(t.Context(), cli))
	require.ErrorIs(t, err, errProviderDeleteSentinel)
}
