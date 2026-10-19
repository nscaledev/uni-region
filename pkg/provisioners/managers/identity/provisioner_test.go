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

package identity_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"
	identityprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/identity"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace  = "test-ns"
	testRegionID   = "region-1"
	testIdentityID = "identity-1"
)

var (
	// errProviderSentinel verifies that the provider's error is propagated unchanged.
	errProviderSentinel = errors.New("provider operation failed")
	// errReferenceSentinel verifies that the reference manager's error is propagated unchanged.
	errReferenceSentinel = errors.New("reference operation failed")
)

// fakeReferences is a hand-rolled double for the identity-service reference seam.
// It records invocations so tests can assert ordering, and returns configurable
// errors. The provider boundary is exercised with gomock; this seam is internal
// and has no generated mock.
type fakeReferences struct {
	addErr      error
	removeErr   error
	addCalls    int
	removeCalls int
}

func (f *fakeReferences) AddReferenceToProject(context.Context, client.Object) error {
	f.addCalls++

	return f.addErr
}

func (f *fakeReferences) RemoveReferenceFromProject(context.Context, client.Object) error {
	f.removeCalls++

	return f.removeErr
}

func testIdentity() *unikornv1.Identity {
	return &unikornv1.Identity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testIdentityID,
			Namespace: testNamespace,
			Labels: map[string]string{
				constants.RegionLabel: testRegionID,
			},
		},
	}
}

func testContext(t *testing.T) context.Context {
	t.Helper()

	scheme, err := coreclient.NewScheme(unikornv1.AddToScheme)
	require.NoError(t, err)

	cli := fake.NewClientBuilder().WithScheme(scheme).Build()

	return coreclient.NewContext(t.Context(), cli)
}

func TestProvision_HappyPath(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	id := testIdentity()

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateIdentity(gomock.Any(), id).Return(nil)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	refs := &fakeReferences{}

	prov := identityprovisioner.NewForTest(id, providers, refs)
	require.NoError(t, prov.Provision(testContext(t)))
	require.Equal(t, 1, refs.addCalls)
}

func TestProvision_AddReferenceError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	id := testIdentity()

	// The provider is never consulted when the reference cannot be recorded.
	providers := mockproviders.NewMockProviders(ctrl)

	refs := &fakeReferences{addErr: errReferenceSentinel}

	prov := identityprovisioner.NewForTest(id, providers, refs)
	err := prov.Provision(testContext(t))
	require.ErrorIs(t, err, errReferenceSentinel)
}

func TestProvision_ProviderCreateError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	id := testIdentity()

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateIdentity(gomock.Any(), id).Return(errProviderSentinel)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	refs := &fakeReferences{}

	prov := identityprovisioner.NewForTest(id, providers, refs)
	err := prov.Provision(testContext(t))
	require.ErrorIs(t, err, errProviderSentinel)
}

func TestDeprovision_HappyPath(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	id := testIdentity()

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().DeleteIdentity(gomock.Any(), id).Return(nil)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	refs := &fakeReferences{}

	prov := identityprovisioner.NewForTest(id, providers, refs)
	require.NoError(t, prov.Deprovision(testContext(t)))
	require.Equal(t, 1, refs.removeCalls)
}

func TestDeprovision_ProviderDeleteError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	id := testIdentity()

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().DeleteIdentity(gomock.Any(), id).Return(errProviderSentinel)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	refs := &fakeReferences{}

	prov := identityprovisioner.NewForTest(id, providers, refs)
	err := prov.Deprovision(testContext(t))
	require.ErrorIs(t, err, errProviderSentinel)
	require.Equal(t, 0, refs.removeCalls, "reference must not be removed when provider delete fails")
}

func TestDeprovision_RemoveReferenceError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	id := testIdentity()

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().DeleteIdentity(gomock.Any(), id).Return(nil)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	refs := &fakeReferences{removeErr: errReferenceSentinel}

	prov := identityprovisioner.NewForTest(id, providers, refs)
	err := prov.Deprovision(testContext(t))
	require.ErrorIs(t, err, errReferenceSentinel)
}
