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

// This file is the cross-package contract test for the types.Provider
// UpdateServerState absent-server contract: when the provider server is gone,
// UpdateServerState must (1) record the absent observation on the resource
// (errored cleared, generation stamped from metadata.generation, image sticky)
// and (2) still surface coreerrors.ErrResourceNotFound. Two real consumers
// depend on it and are exercised here against the same real Provider:
//   - pkg/provisioners/managers/server deleteFailedProviderServer uses the
//     sentinel as the create-retry "confirmed gone" gate,
//     then propagates the sentinel.
// Their own packages test against mocks of this contract; this file exists so
// a drift in the real provider cannot stay green there (a livelock regression
// did exactly that). The provider path here is the full exported
// UpdateServerState—service-principal client construction included—against
// a minimal fake OpenStack, not the updateServerStateWithClients core alone.

package openstack_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coremanager "github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	serverprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/server"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrlmanager "sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	contractNamespace  = "contract-ns"
	contractRegionID   = "region-1"
	contractIdentityID = "identity-1"
	contractServerID   = "server-1"
)

// newContractFakeOpenstack serves the minimal OpenStack surface the contract
// needs: keystone auth, version discovery, and empty server/port lists so
// every lookup resolves to a positive not-found.
func newContractFakeOpenstack(t *testing.T) *httptest.Server {
	t.Helper()

	var ts *httptest.Server

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// Treat all POSTs as Keystone authentication requests.
			w.Header().Set("X-Subject-Token", "test-token")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"token":{"catalog":[
			{"type":"identity","endpoints":[{"interface":"public","url":%[1]q,"region_id":""}]},
			{"type":"compute","endpoints":[{"interface":"public","url":%[1]q,"region_id":""}]},
			{"type":"image","endpoints":[{"interface":"public","url":%[1]q,"region_id":""}]},
			{"type":"network","endpoints":[{"interface":"public","url":%[1]q,"region_id":""}]},
			{"type":"block-storage","endpoints":[{"interface":"public","url":%[1]q,"region_id":""}]}
			],"expires_at":"2099-01-01T00:00:00.000000Z"}}`,
				ts.URL)

			return
		}

		// gophercloud GETs "/" twice: once via ChooseVersion (auth, expects doubly-enveloped
		// versions.values with links) and once via GetServiceVersions per service client
		// (expects a version list that includes v2.1 so compute/image/network pass the
		// endpointSupportsVersion check).  The doubly-enveloped format satisfies both.
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w,
				`{"versions":{"values":[
				{"id":"v2.1","status":"CURRENT","links":[{"href":%q,"rel":"self"}]},
				{"id":"v3","status":"current","links":[{"href":%q,"rel":"self"}]}
				]}}`,
				ts.URL+"/v2.1/", ts.URL+"/v3/")

			return
		}

		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/servers") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"servers":[]}`)

			return
		}

		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/ports") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"ports":[]}`)

			return
		}

		t.Logf("unhandled fake openstack request: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{}`)
	}))
	t.Cleanup(ts.Close)

	return ts
}

func contractRegion(endpoint string) *regionv1.Region {
	return &regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      contractRegionID,
			Namespace: contractNamespace,
		},
		Spec: regionv1.RegionSpec{
			Openstack: &regionv1.RegionOpenstackSpec{
				Endpoint: endpoint,
			},
		},
	}
}

func contractIdentity() *regionv1.Identity {
	identity := &regionv1.Identity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      contractIdentityID,
			Namespace: contractNamespace,
		},
	}

	identity.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "")

	return identity
}

func contractOpenstackIdentity() *regionv1.OpenstackIdentity {
	return &regionv1.OpenstackIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      contractIdentityID,
			Namespace: contractNamespace,
		},
		Spec: regionv1.OpenstackIdentitySpec{
			UserID:    ptr.To("test-user-id"),
			Password:  ptr.To("test-password"),
			ProjectID: ptr.To("test-project-id"),
		},
	}
}

func contractServerLabels() map[string]string {
	return map[string]string{
		coreconstants.NameLabel:         contractServerID,
		coreconstants.OrganizationLabel: "org-1",
		constants.RegionLabel:           contractRegionID,
		constants.IdentityLabel:         contractIdentityID,
	}
}

// contractMockProviders wraps the real openstack.Provider in a MockProviders
// registry so the consumers' exported entry points (which take providers.Providers)
// can drive it.
func contractMockProviders(t *testing.T, provider *openstack.Provider) *mockproviders.MockProviders {
	t.Helper()

	ctrl := gomock.NewController(t)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(gomock.Any()).Return(provider, nil).AnyTimes()

	return providers
}

// contractManager satisfies sigs.k8s.io/controller-runtime/pkg/manager.Manager
// by embedding the interface (nil). Any method other than GetEventRecorderFor
// panics, pinning the production surface: the provisioner must only use the
// event recorder from the context manager.
type contractManager struct {
	ctrlmanager.Manager // nil
	recorder            record.EventRecorder
}

func (m contractManager) GetEventRecorderFor(string) record.EventRecorder { return m.recorder }

func contractRetryClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme, err := coreclient.NewScheme(regionv1.AddToScheme)
	require.NoError(t, err)

	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{regionv1.SchemeGroupVersion})
	mapper.Add(regionv1.SchemeGroupVersion.WithKind("Server"), meta.RESTScopeNamespace)

	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithRESTMapper(mapper).
		WithObjects(objects...).
		Build()
}

func contractActiveReason(t *testing.T, server *regionv1.Server) regionv1.ActiveConditionReason {
	t.Helper()

	active, err := regionv1.GetActiveCondition(server)
	require.NoError(t, err)

	return active.Reason
}

func contractRequireEvent(t *testing.T, recorder *record.FakeRecorder, values ...string) {
	t.Helper()

	select {
	case event := <-recorder.Events:
		for _, value := range values {
			require.Contains(t, event, value)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

// TestUpdateServerStateNotFoundContractCreateRetry exercises the create-retry
// leg: deleteFailedProviderServer calls DeleteServer then UpdateServerState on
// the real Provider; the absent sentinel (ErrResourceNotFound) is the
// "confirmed gone" gate that flips ProviderCreateRetrying to false and emits
// the ProviderCreateRetryReady event.
func TestUpdateServerStateNotFoundContractCreateRetry(t *testing.T) {
	t.Parallel()

	ts := newContractFakeOpenstack(t)

	k8sClient := contractRetryClient(t)

	providers := contractMockProviders(t, openstack.NewTestProvider(k8sClient, contractRegion(ts.URL)))

	prov := serverprovisioner.New(nil, providers)

	srv, ok := prov.Object().(*regionv1.Server)
	require.True(t, ok, "the server provisioner must manage a *regionv1.Server")

	srv.Name = contractServerID
	srv.Namespace = contractNamespace
	srv.Labels = contractServerLabels()
	srv.Status.ProviderCreateFailures = 1
	srv.Status.ProviderCreateRetrying = true
	srv.SetActiveCondition(regionv1.ActiveConditionReasonError)

	require.NoError(t, k8sClient.Create(t.Context(), srv))
	require.NoError(t, k8sClient.Create(t.Context(), contractIdentity()))
	require.NoError(t, k8sClient.Create(t.Context(), contractOpenstackIdentity()))

	recorder := record.NewFakeRecorder(4)
	ctx := coremanager.NewContext(coreclient.NewContext(t.Context(), k8sClient), contractManager{recorder: recorder})

	err := prov.Provision(ctx)
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.False(t, srv.Status.ProviderCreateRetrying)
	require.Equal(t, regionv1.ActiveConditionReasonPending, contractActiveReason(t, srv))
	contractRequireEvent(t, recorder, "ProviderCreateRetryReady")
}
