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

package openstack_test

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"

	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type teardownRequest struct {
	method string
	path   string
	status int
	body   string
}

// newTeardownOpenstack scripts lifecycle requests; auth and discovery use the
// shared contract fixture. An unexpected request fails the test before replying.
func newTeardownOpenstack(t *testing.T, steps ...teardownRequest) string {
	t.Helper()

	var mu sync.Mutex

	index := 0
	ts := newContractFakeOpenstack(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/" || strings.HasSuffix(r.URL.Path, "/auth/tokens") {
			return false
		}

		mu.Lock()
		defer mu.Unlock()

		if index >= len(steps) {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			http.Error(w, "unexpected request", http.StatusInternalServerError)

			return true
		}

		step := steps[index]
		index++

		if r.Method != step.method || r.URL.RequestURI() != step.path {
			t.Errorf("request %d: got %s %s, want %s %s", index, r.Method, r.URL.RequestURI(), step.method, step.path)
		}

		if strings.Contains(r.URL.Path, "/servers") {
			if version := r.Header.Get("X-Openstack-Nova-Api-Version"); version != "2.90" {
				t.Errorf("Nova microversion = %q, want 2.90", version)
			}
		}

		if step.status != http.StatusNoContent {
			w.Header().Set("Content-Type", "application/json")
		}

		w.WriteHeader(step.status)
		fmt.Fprint(w, step.body)

		return true
	})

	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		require.Equal(t, len(steps), index, "all scripted lifecycle requests must run")
	})

	return ts.URL
}

func novaLookup(body string) teardownRequest {
	return teardownRequest{http.MethodGet, "/servers/detail?limit=250", http.StatusOK, body}
}

func novaServer(status, task string) teardownRequest {
	return novaLookup(fmt.Sprintf(`{"servers":[{"id":"nova-1","name":"server-1","status":%q,"OS-EXT-STS:task_state":%q}]}`, status, task))
}

func novaDelete(status int) teardownRequest {
	return teardownRequest{http.MethodDelete, "/servers/nova-1", status, ""}
}

func portLookup(present bool) teardownRequest {
	body := `{"ports":[]}`
	if present {
		body = `{"ports":[{"id":"port-1","name":"server-server-1"}]}`
	}

	return teardownRequest{http.MethodGet, "/v2.0/ports?name=server-server-1", http.StatusOK, body}
}

func floatingIPLookup(present bool) teardownRequest {
	body := `{"floatingips":[]}`
	if present {
		body = `{"floatingips":[{"id":"fip-1","port_id":"port-1"}]}`
	}

	return teardownRequest{http.MethodGet, "/v2.0/floatingips?port_id=port-1", http.StatusOK, body}
}

func teardownProvider(cli client.Client, endpoint string) *openstack.Provider {
	return openstack.NewTestProviderWithCredentials(cli, contractRegion(endpoint), openstack.TestProviderCredentials{
		UserID: "manager-user", Password: "manager-password", ProjectID: "manager-project",
	})
}

func teardownServer() *unikornv1.Server {
	server := &unikornv1.Server{}
	server.Name = contractServerID
	server.Namespace = contractNamespace
	server.Labels = contractServerLabels()

	return server
}

func TestDeleteServerRetriesFailedDelete(t *testing.T) {
	t.Parallel()

	// Nova can retain deleting after synchronous cleanup fails on a down host.
	endpoint := newTeardownOpenstack(t,
		novaServer("ACTIVE", ""), novaDelete(http.StatusInternalServerError),
		novaServer("ACTIVE", "deleting"), novaDelete(http.StatusNoContent),
		novaLookup(`{"servers":[]}`), portLookup(false), novaLookup(`{"servers":[]}`),
	)
	cli := contractRetryClient(t, contractOpenstackIdentity())
	server := teardownServer()

	err := teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), server)
	require.Error(t, err)
	require.NotErrorIs(t, err, provisioners.ErrYield)

	err = teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), server)
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.NoError(t, teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), server))
}

func TestDeleteServerPresentRetainsNetworking(t *testing.T) {
	t.Parallel()

	for name, steps := range map[string][]teardownRequest{
		"build hold":     {novaServer("BUILD", "spawning")},
		"rebuild hold":   {novaServer("REBUILD", "rebuild_spawning")},
		"queued build":   {novaServer("BUILD", "scheduling"), novaDelete(204)},
		"queued rebuild": {novaServer("REBUILD", "rebuilding"), novaDelete(204)},
		"deleting":       {novaServer("ACTIVE", "deleting"), novaDelete(204)},
		"error":          {novaServer("ERROR", ""), novaDelete(204)},
		"delete race":    {novaServer("ACTIVE", ""), novaDelete(404)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			endpoint := newTeardownOpenstack(t, steps...)
			cli := contractRetryClient(t, contractOpenstackIdentity())
			require.ErrorIs(t, teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), teardownServer()), provisioners.ErrYield)
		})
	}
}

func TestDeleteServerReleasesBuildHold(t *testing.T) {
	t.Parallel()

	for _, absent := range []bool{false, true} {
		t.Run(fmt.Sprintf("absent=%t", absent), func(t *testing.T) {
			t.Parallel()

			steps := []teardownRequest{novaServer("BUILD", "spawning"), novaServer("ACTIVE", "deleting"), novaDelete(204)}

			if absent {
				portError := portLookup(false)
				portError.status = http.StatusInternalServerError
				steps[1] = novaLookup(`{"servers":[]}`)
				steps[2] = portError
			}

			endpoint := newTeardownOpenstack(t, steps...)
			cli := contractRetryClient(t, contractOpenstackIdentity())
			server := teardownServer()
			require.ErrorIs(t, teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), server), provisioners.ErrYield)
			held, err := unikornv1.GetDeletionHeldCondition(server)
			require.NoError(t, err)
			require.Equal(t, corev1.ConditionTrue, held.Status)

			err = teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), server)
			if absent {
				require.Error(t, err)
				require.NotErrorIs(t, err, provisioners.ErrYield)
			} else {
				require.ErrorIs(t, err, provisioners.ErrYield)
			}

			held, err = unikornv1.GetDeletionHeldCondition(server)
			require.NoError(t, err)
			require.Equal(t, corev1.ConditionFalse, held.Status)
			require.Equal(t, unikornv1.DeletionHeldConditionReasonReleased, held.Reason)
			require.NotContains(t, held.Message, "delete sent")
		})
	}
}

func TestDeleteServerNetworkCleanup(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusNoContent, http.StatusNotFound} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			t.Parallel()
			endpoint := newTeardownOpenstack(t,
				novaLookup(`{"servers":[]}`), portLookup(true), floatingIPLookup(true),
				teardownRequest{http.MethodDelete, "/v2.0/floatingips/fip-1", status, ""},
				teardownRequest{http.MethodDelete, "/v2.0/ports/port-1", status, ""},
				novaLookup(`{"servers":[]}`),
				novaLookup(`{"servers":[]}`), portLookup(false), novaLookup(`{"servers":[]}`),
			)
			cli := contractRetryClient(t, contractOpenstackIdentity())

			for range 2 {
				require.NoError(t, teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), teardownServer()))
			}
		})
	}
}

func TestDeleteServerRetainsLateCreate(t *testing.T) {
	t.Parallel()

	for name, networking := range map[string][]teardownRequest{
		"port removed": {
			portLookup(true), floatingIPLookup(false),
			{http.MethodDelete, "/v2.0/ports/port-1", http.StatusNoContent, ""},
		},
		"port concurrently removed": {
			portLookup(true), floatingIPLookup(false),
			{http.MethodDelete, "/v2.0/ports/port-1", http.StatusNotFound, ""},
		},
		"port already absent": {portLookup(false)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			steps := append([]teardownRequest{novaLookup(`{"servers":[]}`)}, networking...)
			steps = append(steps,
				novaServer("ACTIVE", ""),
				novaServer("ACTIVE", ""), novaDelete(http.StatusNoContent),
				novaLookup(`{"servers":[]}`), portLookup(false), novaLookup(`{"servers":[]}`),
			)
			endpoint := newTeardownOpenstack(t, steps...)
			cli := contractRetryClient(t, contractOpenstackIdentity())
			server := teardownServer()

			require.ErrorIs(t, teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), server), provisioners.ErrYield)
			require.ErrorIs(t, teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), server), provisioners.ErrYield)
			require.NoError(t, teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), server))
		})
	}
}

func TestDeleteServerRetainsOwnershipWhenFinalLookupFails(t *testing.T) {
	t.Parallel()

	lookupError := novaLookup(`{"error":{"message":"compute unavailable"}}`)
	lookupError.status = http.StatusInternalServerError
	endpoint := newTeardownOpenstack(t,
		novaLookup(`{"servers":[]}`), portLookup(false), lookupError,
	)
	cli := contractRetryClient(t, contractOpenstackIdentity())

	err := teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), teardownServer())
	require.Error(t, err)
	require.NotErrorIs(t, err, provisioners.ErrYield)
}

func TestDeleteServerDrainsLateCreateRetries(t *testing.T) {
	t.Parallel()

	const retries = `{"servers":[
		{"id":"nova-1","name":"server-1","status":"ERROR"},
		{"id":"nova-2","name":"server-1","status":"ACTIVE"}
	]}`

	const remaining = `{"servers":[{"id":"nova-2","name":"server-1","status":"ACTIVE"}]}`

	endpoint := newTeardownOpenstack(t,
		novaLookup(`{"servers":[]}`), portLookup(true), floatingIPLookup(false),
		teardownRequest{http.MethodDelete, "/v2.0/ports/port-1", http.StatusNoContent, ""},
		novaLookup(retries),
		novaLookup(retries), novaDelete(http.StatusNoContent),
		novaLookup(remaining), teardownRequest{http.MethodDelete, "/servers/nova-2", http.StatusNoContent, ""},
		novaLookup(`{"servers":[]}`), portLookup(false), novaLookup(`{"servers":[]}`),
	)
	cli := contractRetryClient(t, contractOpenstackIdentity())
	server := teardownServer()

	for range 3 {
		require.ErrorIs(t, teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), server), provisioners.ErrYield)
	}

	require.NoError(t, teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), server))
}

func TestServerDeleteHeldOnlyWhileSpawning(t *testing.T) {
	t.Parallel()

	cases := []struct {
		status    string
		taskState string
		held      bool
	}{
		{status: "BUILD", taskState: "spawning", held: true},
		{status: "REBUILD", taskState: "rebuild_spawning", held: true},
		{status: "BUILD", taskState: "scheduling"},
		{status: "BUILD", taskState: "networking"},
		{status: "BUILD", taskState: "block_device_mapping"},
		{status: "BUILD"},
		{status: "REBUILD", taskState: "rebuilding"},
		{status: "ACTIVE"},
		{status: "ACTIVE", taskState: "powering-off"},
		{status: "ERROR", taskState: "spawning"},
		{status: "SHUTOFF", taskState: "powering-on"},
	}

	for _, tc := range cases {
		t.Run(tc.status+"/"+tc.taskState, func(t *testing.T) {
			t.Parallel()

			server := &servers.Server{Status: tc.status, TaskState: tc.taskState}

			require.Equal(t, tc.held, openstack.ServerDeleteHeld(server))
		})
	}
}

func TestHoldServerDeleteTracksTheHoldOnACondition(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}
	nova := &servers.Server{ID: "nova-server", Status: "BUILD", TaskState: "spawning"}

	require.ErrorIs(t, openstack.HoldServerDelete(t.Context(), server, nova), provisioners.ErrYield)

	held, err := unikornv1.GetDeletionHeldCondition(server)
	require.NoError(t, err)
	require.Equal(t, corev1.ConditionTrue, held.Status)
	require.Equal(t, unikornv1.DeletionHeldConditionReasonProviderBuilding, held.Reason)

	began := held.LastTransitionTime

	require.ErrorIs(t, openstack.HoldServerDelete(t.Context(), server, nova), provisioners.ErrYield)

	held, err = unikornv1.GetDeletionHeldCondition(server)
	require.NoError(t, err)
	require.Equal(t, began, held.LastTransitionTime, "a later held pass must keep the time the hold began")

	openstack.ReleaseServerDelete(server)

	held, err = unikornv1.GetDeletionHeldCondition(server)
	require.NoError(t, err)
	require.Equal(t, corev1.ConditionFalse, held.Status)
	require.Equal(t, unikornv1.DeletionHeldConditionReasonReleased, held.Reason)
}

func TestReleaseServerDeleteLeavesAnUnheldServerAlone(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}

	openstack.ReleaseServerDelete(server)

	_, err := unikornv1.GetDeletionHeldCondition(server)
	require.Error(t, err)
}
