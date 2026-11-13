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
// UpdateServerState must surface coreerrors.ErrResourceNotFound.
// pkg/provisioners/managers/server deleteFailedProviderServer depends on it as
// the create-retry "confirmed gone" gate, and is exercised here against the
// real Provider.
// Its own package tests against mocks of this contract; this file exists so
// a drift in the real provider cannot stay green there (a livelock regression
// did exactly that). The provider path here is the full exported
// UpdateServerState—service-principal client construction included—against
// a minimal fake OpenStack, not the observeServer core alone.

package openstack_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
	idstest "github.com/unikorn-cloud/region/pkg/ids/idstest"
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
func newContractFakeOpenstack(t *testing.T, handlers ...func(http.ResponseWriter, *http.Request) bool) *httptest.Server {
	t.Helper()

	var ts *httptest.Server

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, handler := range handlers {
			if handler(w, r) {
				return
			}
		}

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

func TestDeprovisionDeleteWaitsForNovaAndNetworking(t *testing.T) {
	t.Parallel()

	lookupError := novaLookup(`{"error":{"message":"compute unavailable"}}`)
	lookupError.status = http.StatusInternalServerError

	endpoint := newTeardownOpenstack(t,
		novaServer("ACTIVE", ""), novaDelete(http.StatusNoContent),
		novaServer("ACTIVE", "deleting"), novaDelete(http.StatusNoContent),
		novaServer("ERROR", "deleting"), novaDelete(http.StatusNoContent),
		novaLookup(`{"servers":[]}`), portLookup(true), floatingIPLookup(false),
		teardownRequest{http.MethodDelete, "/v2.0/ports/port-1", http.StatusConflict, ""},
		novaLookup(`{"servers":[]}`), portLookup(true), floatingIPLookup(false),
		teardownRequest{http.MethodDelete, "/v2.0/ports/port-1", http.StatusNoContent, ""},
		novaServer("ACTIVE", ""),
		novaServer("ACTIVE", ""), novaDelete(http.StatusNoContent),
		novaLookup(`{"servers":[]}`), portLookup(false), lookupError,
		novaLookup(`{"servers":[]}`), portLookup(false), novaLookup(`{"servers":[]}`),
	)
	identity := contractIdentity()
	identity.UID = "identity-uid"
	identity.Finalizers = []string{coreconstants.Finalizer}

	const networkID = "11111111-1111-4111-a111-111111111111"

	reference := "servers.region.unikorn-cloud.org/" + contractServerID
	network := &regionv1.Network{ObjectMeta: metav1.ObjectMeta{
		Name: networkID, Namespace: contractNamespace, UID: "network-uid",
		Labels:          map[string]string{constants.IdentityLabel: contractIdentityID},
		Finalizers:      []string{coreconstants.Finalizer, reference},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: regionv1.SchemeGroupVersion.String(), Kind: "Identity", Name: identity.Name, UID: identity.UID, BlockOwnerDeletion: ptr.To(true)}},
	}}
	group := &regionv1.SecurityGroup{ObjectMeta: metav1.ObjectMeta{
		Name: "dropped-group", Namespace: contractNamespace,
		Labels:     map[string]string{constants.IdentityLabel: contractIdentityID},
		Finalizers: []string{coreconstants.Finalizer, reference},
	}}

	cli := contractRetryClient(t, identity, contractOpenstackIdentity(), network, group)
	for pass := range 8 {
		prov := serverprovisioner.New(nil, contractMockProviders(t, teardownProvider(cli, endpoint)))
		server, ok := prov.Object().(*regionv1.Server)
		require.True(t, ok)

		*server = *teardownServer()
		server.Spec.Networks = []regionv1.ServerNetworkSpec{{ID: idstest.MustParseNetworkID(networkID)}}
		server.Finalizers = []string{coreconstants.Finalizer}
		server.OwnerReferences = []metav1.OwnerReference{{APIVersion: regionv1.SchemeGroupVersion.String(), Kind: "Network", Name: network.Name, UID: network.UID, BlockOwnerDeletion: ptr.To(true)}}

		err := prov.Deprovision(coreclient.NewContext(t.Context(), cli))

		switch pass {
		case 0, 1, 2, 4, 5:
			require.ErrorIs(t, err, provisioners.ErrYield)
		case 3, 6:
			require.Error(t, err)
			require.NotErrorIs(t, err, provisioners.ErrYield)
		default:
			require.NoError(t, err)
		}

		_, err = regionv1.GetDeletionHeldCondition(server)
		require.Error(t, err, "never-held servers must not acquire the build hold condition")

		updated := &regionv1.Network{}
		require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(network), updated))
		require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(group), group))

		if pass < 7 {
			require.Equal(t, network.Finalizers, updated.Finalizers, "pending or failed provider cleanup retains the network reference")
		} else {
			require.Equal(t, []string{coreconstants.Finalizer}, updated.Finalizers)
		}

		require.Equal(t, updated.Finalizers, group.Finalizers, "consumed and dropped resources retain references until cleanup succeeds")
		// Provisioners leave own finalizers and blocking ownership to the reconciler/GC.
		require.Equal(t, []string{coreconstants.Finalizer}, server.Finalizers)
		require.True(t, *server.OwnerReferences[0].BlockOwnerDeletion)
		require.Equal(t, network.OwnerReferences, updated.OwnerReferences)
		require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(identity), identity))
		require.Equal(t, []string{coreconstants.Finalizer}, identity.Finalizers)
	}
}

// TestCreateServerLeavesUnreachableCloudUntyped pins that a pass which could
// not reach the cloud comes back from the real CreateServer as a plain failure
// that core's WithTransient, given the region classifier, treats as an outage:
// the condition is left alone.  A disposition would hide it from the
// classifier.
func TestCreateServerLeavesUnreachableCloudUntyped(t *testing.T) {
	t.Parallel()

	endpoint := newContractFakeOpenstack(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost {
			return false
		}

		w.WriteHeader(http.StatusServiceUnavailable)

		return true
	})

	server := &regionv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Name:      contractServerID,
			Namespace: contractNamespace,
			Labels:    contractServerLabels(),
		},
	}

	cli := contractRetryClient(t, contractIdentity(), contractOpenstackIdentity())
	provider := teardownProvider(cli, endpoint.URL)

	_, err := provider.CreateServer(t.Context(), contractIdentity(), server, nil)
	require.Error(t, err)
	require.True(t, coremanager.Unreachable(err, openstack.Transient))
}

// TestVolumeCallsLeaveUnreachableCloudUntyped pins that a pass which could not
// reach the cloud comes back from the real CreateVolume and AttachVolume as a
// plain failure that core's WithTransient, given the region classifier, treats
// as an outage, whether Keystone or Nova is down.
func TestVolumeCallsLeaveUnreachableCloudUntyped(t *testing.T) {
	t.Parallel()

	for outage, down := range map[string]func(*http.Request) bool{
		"keystone": func(r *http.Request) bool { return r.Method == http.MethodPost },
		"nova":     func(r *http.Request) bool { return strings.Contains(r.URL.Path, "/servers") },
	} {
		t.Run(outage, func(t *testing.T) {
			t.Parallel()

			endpoint := newContractFakeOpenstack(t, func(w http.ResponseWriter, r *http.Request) bool {
				if !down(r) {
					return false
				}

				w.WriteHeader(http.StatusServiceUnavailable)

				return true
			})

			volume := &regionv1.Volume{
				ObjectMeta: metav1.ObjectMeta{Name: "volume-1", Namespace: contractNamespace},
			}

			cli := contractRetryClient(t, contractIdentity(), contractOpenstackIdentity())
			provider := teardownProvider(cli, endpoint.URL)

			server := &regionv1.Server{ObjectMeta: metav1.ObjectMeta{Name: contractServerID, Namespace: contractNamespace, Labels: contractServerLabels()}}

			_, err := provider.AttachVolume(t.Context(), contractIdentity(), server, volume)
			require.Error(t, err)
			require.True(t, coremanager.Unreachable(err, openstack.Transient), "AttachVolume")

			// Nova down does not reach CreateVolume, which talks to Cinder.
			if outage == "keystone" {
				err = provider.CreateVolume(t.Context(), contractIdentity(), volume)
				require.Error(t, err)
				require.True(t, coremanager.Unreachable(err, openstack.Transient), "CreateVolume")
			}
		})
	}
}

// TestUpdateServerStateReadsAfresh pins that the create-retry gate never sees
// a kept list: it deletes a server it reads as failed, so one fixed in the
// cloud since the last list must read as fixed.
func TestUpdateServerStateReadsAfresh(t *testing.T) {
	t.Parallel()

	// The row Nova lists: failed, then fixed in the cloud and booted.
	var row atomic.Value

	row.Store(`"status":"ERROR"`)

	project := fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())

	var ts *httptest.Server

	ts = newContractFakeOpenstack(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.Method == http.MethodPost:
			// As the default, but scoped to a project, which the shared read keys on.
			w.Header().Set("X-Subject-Token", "test-token")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"token":{"project":{"id":%q,"name":"p"},"catalog":[
			{"type":"compute","endpoints":[{"interface":"public","url":%[2]q,"region_id":""}]}
			],"expires_at":"2099-01-01T00:00:00.000000Z"}}`, project, ts.URL)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/servers/detail"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"servers":[{"id":"nova-1","name":%q,%s}]}`, contractServerID, row.Load())
		default:
			return false
		}

		return true
	})

	k8sClient := contractRetryClient(t, contractIdentity(), contractOpenstackIdentity())
	provider := openstack.NewTestProvider(k8sClient, contractRegion(ts.URL))

	server := &regionv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Name:      contractServerID,
			Namespace: contractNamespace,
			Labels:    contractServerLabels(),
		},
	}

	require.NoError(t, provider.UpdateServerState(t.Context(), contractIdentity(), server))
	require.True(t, serverprovisioner.ProviderCreateFailure(server))

	row.Store(`"status":"ACTIVE","OS-EXT-STS:power_state":1,"OS-SRV-USG:launched_at":"2026-01-01T00:00:00.000000"`)

	require.NoError(t, provider.UpdateServerState(t.Context(), contractIdentity(), server))
	require.False(t, serverprovisioner.ProviderCreateFailure(server), "the gate must not be answered from the list that showed the failure")
}
