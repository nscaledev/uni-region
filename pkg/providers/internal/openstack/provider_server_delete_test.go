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

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
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
			if version := r.Header.Get("X-OpenStack-Nova-API-Version"); version != "2.90" {
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
	return teardownRequest{http.MethodGet, "/servers/detail?name=server-1", http.StatusOK, body}
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

func TestDeleteServerWaitsForNova(t *testing.T) {
	t.Parallel()

	endpoint := newTeardownOpenstack(t,
		novaServer("ACTIVE", ""), novaDelete(http.StatusNoContent),
		novaServer("ACTIVE", "deleting"), novaDelete(http.StatusNoContent),
		novaServer("ERROR", "deleting"), novaDelete(http.StatusNoContent),
		novaLookup(`{"servers":[]}`), portLookup(false),
	)
	cli := contractRetryClient(t, contractIdentity(), contractOpenstackIdentity())
	server := teardownServer()

	for range 3 {
		// Reconstruct the provider on every pass: progress must come from Nova.
		err := teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), server)
		require.ErrorIs(t, err, provisioners.ErrYield)
	}

	require.NoError(t, teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), server))
	_, err := unikornv1.GetDeletionHeldCondition(server)
	require.Error(t, err, "never-held servers must not acquire the build hold condition")
}

func TestDeleteServerRetriesFailedDelete(t *testing.T) {
	t.Parallel()

	// Nova can retain deleting after synchronous cleanup fails on a down host.
	endpoint := newTeardownOpenstack(t,
		novaServer("ACTIVE", ""), novaDelete(http.StatusInternalServerError),
		novaServer("ACTIVE", "deleting"), novaDelete(http.StatusNoContent),
		novaLookup(`{"servers":[]}`), portLookup(false),
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

func TestDeleteServerPresentAndFailedReadsRetainNetworking(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		steps []teardownRequest
		want  error
	}{
		{"build hold", []teardownRequest{novaServer("BUILD", "spawning")}, provisioners.ErrYield},
		{"rebuild hold", []teardownRequest{novaServer("REBUILD", "rebuild_spawning")}, provisioners.ErrYield},
		{"queued build", []teardownRequest{novaServer("BUILD", "scheduling"), novaDelete(204)}, provisioners.ErrYield},
		{"queued rebuild", []teardownRequest{novaServer("REBUILD", "rebuilding"), novaDelete(204)}, provisioners.ErrYield},
		{"deleting", []teardownRequest{novaServer("ACTIVE", "deleting"), novaDelete(204)}, provisioners.ErrYield},
		{"error", []teardownRequest{novaServer("ERROR", ""), novaDelete(204)}, provisioners.ErrYield},
		{"delete race", []teardownRequest{novaServer("ACTIVE", ""), novaDelete(404)}, provisioners.ErrYield},
		{"unknown", []teardownRequest{novaLookup(`{"servers":[{"id":"unknown-1","status":"UNKNOWN"}]}`)}, coreerrors.ErrConsistency},
		{"minimal", []teardownRequest{novaLookup(`{"servers":[{"id":"unknown-1"}]}`)}, coreerrors.ErrConsistency},
		{"no content", []teardownRequest{{http.MethodGet, "/servers/detail?name=server-1", 204, ""}}, coreerrors.ErrConsistency},
		{"empty continuation", []teardownRequest{novaLookup(`{"servers":[],"servers_links":[{"rel":"next","href":""}]}`)}, coreerrors.ErrConsistency},
		{"missing continuation", []teardownRequest{novaLookup(`{"servers":[],"servers_links":[{"rel":"next"}]}`)}, coreerrors.ErrConsistency},
		{"ambiguous", []teardownRequest{novaLookup(`{"servers":[{"id":"a","name":"server-1","status":"ACTIVE"},{"id":"b","name":"server-1","status":"ERROR"}]}`)}, coreerrors.ErrConsistency},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			endpoint := newTeardownOpenstack(t, tc.steps...)
			cli := contractRetryClient(t, contractOpenstackIdentity())
			require.ErrorIs(t, teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), teardownServer()), tc.want)
		})
	}

	for _, status := range []int{401, 403, 409, 500} {
		for _, operation := range []string{"lookup", "delete"} {
			t.Run(fmt.Sprintf("%s/%d", operation, status), func(t *testing.T) {
				t.Parallel()

				steps := []teardownRequest{novaServer("ACTIVE", ""), novaDelete(status)}

				if operation == "lookup" {
					step := novaLookup(`{}`)
					step.status = status
					steps = []teardownRequest{step}
				}

				if status == 401 {
					steps = append(steps, steps[len(steps)-1])
				}

				endpoint := newTeardownOpenstack(t, steps...)
				cli := contractRetryClient(t, contractOpenstackIdentity())
				err := teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), teardownServer())
				require.Error(t, err)
				require.NotErrorIs(t, err, provisioners.ErrYield)
			})
		}
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

func TestDeleteServerNetworkCleanupRetries(t *testing.T) {
	t.Parallel()

	for _, status := range []int{204, 404, 401, 403, 409, 500} {
		for _, resource := range []string{"floatingips/fip-1", "ports/port-1"} {
			t.Run(fmt.Sprintf("%s/%d", resource, status), func(t *testing.T) {
				t.Parallel()

				steps := networkCleanupSteps(resource, status)
				endpoint := newTeardownOpenstack(t, steps...)
				cli := contractRetryClient(t, contractOpenstackIdentity())

				err := teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), teardownServer())
				if status == 204 || status == 404 {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.NoError(t, teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), teardownServer()))
				}
			})
		}
	}

	t.Run("port only then already clean", func(t *testing.T) {
		endpoint := newTeardownOpenstack(t, novaLookup(`{"servers":[]}`), portLookup(true), floatingIPLookup(false),
			teardownRequest{http.MethodDelete, "/v2.0/ports/port-1", 204, ""}, novaLookup(`{"servers":[]}`), portLookup(false))
		cli := contractRetryClient(t, contractOpenstackIdentity())

		for range 2 {
			require.NoError(t, teardownProvider(cli, endpoint).DeleteServer(t.Context(), contractIdentity(), teardownServer()))
		}
	})
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

// withReauthentication includes gophercloud's one retry after a 401.
func withReauthentication(step teardownRequest) []teardownRequest {
	if step.status == http.StatusUnauthorized {
		return []teardownRequest{step, step}
	}

	return []teardownRequest{step}
}

func networkCleanupSteps(resource string, status int) []teardownRequest {
	steps := []teardownRequest{novaLookup(`{"servers":[]}`), portLookup(true), floatingIPLookup(true)}
	fipDelete := teardownRequest{http.MethodDelete, "/v2.0/floatingips/fip-1", 204, ""}
	portDelete := teardownRequest{http.MethodDelete, "/v2.0/ports/port-1", 204, ""}

	if resource == "floatingips/fip-1" {
		fipDelete.status = status
	} else {
		portDelete.status = status
	}

	steps = append(steps, withReauthentication(fipDelete)...)
	if resource != "floatingips/fip-1" || status == 204 || status == 404 {
		steps = append(steps, withReauthentication(portDelete)...)
	}
	// A later pass must re-discover and retry after an error.
	if status != 204 && status != 404 {
		steps = append(steps, novaLookup(`{"servers":[]}`), portLookup(true))
		if resource == "floatingips/fip-1" {
			steps = append(steps, floatingIPLookup(true), teardownRequest{http.MethodDelete, "/v2.0/floatingips/fip-1", 204, ""})
		} else {
			steps = append(steps, floatingIPLookup(false))
		}

		steps = append(steps, teardownRequest{http.MethodDelete, "/v2.0/ports/port-1", 204, ""})
	}

	return steps
}
