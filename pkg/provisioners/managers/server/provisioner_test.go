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

package server_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"
	serverprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/server"

	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testRegionID        = "region-1"
	testIdentityID      = "identity-1"
	testProviderGate    = "example.unikorn-cloud.org/pre-create-ready"
	testProviderActor   = "precreate-service"
	testProviderReason  = "Prepared"
	testProviderMessage = "external state is ready"
)

func testProvisionIdentity() *regionv1.Identity {
	identity := &regionv1.Identity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testIdentityID,
			Namespace: "default",
		},
	}

	identity.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "")

	return identity
}

func testProvisionServer(opts ...func(*regionv1.Server)) *regionv1.Server {
	server := testServer(func(server *regionv1.Server) {
		server.Labels = map[string]string{
			constants.RegionLabel:   testRegionID,
			constants.IdentityLabel: testIdentityID,
		}
	})

	for _, opt := range opts {
		opt(server)
	}

	return server
}

func withProviderCreateGate(status corev1.ConditionStatus) func(*regionv1.Server) {
	return func(server *regionv1.Server) {
		server.Spec.ProviderCreateGates = []regionv1.ServerProviderCreateGate{
			{ConditionType: testProviderGate},
		}

		if status != "" {
			server.ProviderCreateGateStatusWrite(testProviderGate, status, testProviderActor, testProviderReason, testProviderMessage, nil)
		}
	}
}

func testProvisionClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, regionv1.AddToScheme(scheme))

	restMapper := apimeta.NewDefaultRESTMapper([]schema.GroupVersion{regionv1.SchemeGroupVersion})
	restMapper.Add(regionv1.SchemeGroupVersion.WithKind("Server"), apimeta.RESTScopeNamespace)

	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithRESTMapper(restMapper).
		WithObjects(objects...).
		Build()
}

func TestProvisionProviderCreateGateRemaining(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	provider := mocktypes.NewMockProvider(ctrl)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	server := testProvisionServer(withProviderCreateGate(""))
	cli := testProvisionClient(t, server, testProvisionIdentity())

	prov := serverprovisioner.NewForTest(server, providers, nil)
	err := prov.Provision(coreclient.NewContext(t.Context(), cli))
	require.ErrorIs(t, err, provisioners.ErrYield)
}

func TestProvisionProviderCreateGateSatisfied(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	server := testProvisionServer(withProviderCreateGate(corev1.ConditionTrue))

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(nil)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	cli := testProvisionClient(t, server, testProvisionIdentity())

	prov := serverprovisioner.NewForTest(server, providers, nil)
	require.NoError(t, prov.Provision(coreclient.NewContext(t.Context(), cli)))
}

// userDataRecordedAnnotation is spelled out because it is persisted.
const userDataRecordedAnnotation = "regions.unikorn-cloud.org/user-data-recorded"

// provisionAfterGet runs one pass over the server as the reconciler reads it.
func provisionAfterGet(t *testing.T, provider *mocktypes.MockProvider, ctrl *gomock.Controller) (client.Client, *regionv1.Server, error) {
	t.Helper()

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	scheme := runtime.NewScheme()
	require.NoError(t, regionv1.AddToScheme(scheme))

	restMapper := apimeta.NewDefaultRESTMapper([]schema.GroupVersion{regionv1.SchemeGroupVersion})
	restMapper.Add(regionv1.SchemeGroupVersion.WithKind("Server"), apimeta.RESTScopeNamespace)

	initial := testProvisionServer()

	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRESTMapper(restMapper).
		WithObjects(initial, testProvisionIdentity()).
		WithStatusSubresource(&regionv1.Server{}).
		Build()

	server := &regionv1.Server{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(initial), server))

	err := serverprovisioner.NewForTest(server, providers, nil).Provision(coreclient.NewContext(t.Context(), cli))

	return cli, server, err
}

// TestProvisionPersistsUserDataRecorded pins that the annotation the provider
// sets in memory is saved, since the reconciler persists only status, and
// that the status update which follows the pass still succeeds with the
// provider's status intact.
func TestProvisionPersistsUserDataRecorded(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	privateIP := "192.0.2.1"

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ *regionv1.Identity, server *regionv1.Server, _ *types.ServerCreateOptions) error {
			server.Annotations = map[string]string{userDataRecordedAnnotation: "true"}
			server.Status.PrivateIP = &privateIP

			return provisioners.ErrYield
		})

	cli, server, err := provisionAfterGet(t, provider, ctrl)
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Equal(t, &privateIP, server.Status.PrivateIP)
	require.NoError(t, cli.Status().Update(t.Context(), server))

	stored := &regionv1.Server{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(server), stored))
	require.Equal(t, "true", stored.Annotations[userDataRecordedAnnotation])
	require.Equal(t, &privateIP, stored.Status.PrivateIP)
}

// TestProvisionLeavesMetadataWithoutRecord pins that a pass that does not
// establish the record writes no metadata.
func TestProvisionLeavesMetadataWithoutRecord(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	cli, server, err := provisionAfterGet(t, provider, ctrl)
	require.NoError(t, err)

	stored := &regionv1.Server{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(server), stored))
	require.Equal(t, server.ResourceVersion, stored.ResourceVersion)
	require.NotContains(t, stored.Annotations, userDataRecordedAnnotation)
}
