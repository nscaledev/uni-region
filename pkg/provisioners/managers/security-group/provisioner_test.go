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

package securitygroup_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"
	securitygroup "github.com/unikorn-cloud/region/pkg/provisioners/managers/security-group"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace     = "test-ns"
	testRegionID      = "region-1"
	testIdentityID    = "identity-1"
	testSecurityGroup = "security-group-1"
)

// errProviderDeleteSentinel is a static sentinel used to verify that Deprovision
// returns the provider's DeleteSecurityGroup error unchanged.
var errProviderDeleteSentinel = errors.New("provider delete failed")

func testClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme, err := coreclient.NewScheme(unikornv1.AddToScheme)
	require.NoError(t, err)

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func testSecurityGroupResource() *unikornv1.SecurityGroup {
	return &unikornv1.SecurityGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testSecurityGroup,
			Namespace: testNamespace,
			Labels: map[string]string{
				constants.RegionLabel:   testRegionID,
				constants.IdentityLabel: testIdentityID,
			},
		},
	}
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

func TestProvision_HappyPath(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	sg := testSecurityGroupResource()

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateSecurityGroup(gomock.Any(), gomock.Any(), sg).Return(nil)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	cli := testClient(t, sg, testIdentity(true))

	prov := securitygroup.NewForTest(sg, providers)
	require.NoError(t, prov.Provision(coreclient.NewContext(t.Context(), cli)))
}

func TestProvision_IdentityNotReady(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	provider := mocktypes.NewMockProvider(ctrl)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	sg := testSecurityGroupResource()
	cli := testClient(t, sg, testIdentity(false))

	prov := securitygroup.NewForTest(sg, providers)
	err := prov.Provision(coreclient.NewContext(t.Context(), cli))
	require.ErrorIs(t, err, provisioners.ErrYield)
}

func TestDeprovision_HappyPath(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	sg := testSecurityGroupResource()

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().DeleteSecurityGroup(gomock.Any(), gomock.Any(), sg).Return(nil)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	cli := testClient(t, sg, testIdentity(true))

	prov := securitygroup.NewForTest(sg, providers)
	require.NoError(t, prov.Deprovision(coreclient.NewContext(t.Context(), cli)))
}

func TestDeprovision_ProviderError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	sg := testSecurityGroupResource()

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().DeleteSecurityGroup(gomock.Any(), gomock.Any(), sg).Return(errProviderDeleteSentinel)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	cli := testClient(t, sg, testIdentity(true))

	prov := securitygroup.NewForTest(sg, providers)
	err := prov.Deprovision(coreclient.NewContext(t.Context(), cli))
	require.ErrorIs(t, err, errProviderDeleteSentinel)
}
