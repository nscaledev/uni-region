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
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
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

	identity.StatusConditionWrite(unikornv1core.ConditionAvailable, corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "")

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
			server.ProviderCreateGateStatusWrite(testProviderGate, status, testProviderActor, testProviderReason, testProviderMessage)
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

	prov := serverprovisioner.NewForTest(server, providers)
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

	prov := serverprovisioner.NewForTest(server, providers)
	require.NoError(t, prov.Provision(coreclient.NewContext(t.Context(), cli)))
}
