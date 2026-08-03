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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	idstest "github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// fakeNovaServer captures server create and action requests and returns minimal responses.
type fakeNovaServer struct {
	body map[string]any
}

func (f *fakeNovaServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/servers" {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := json.Unmarshal(raw, &f.body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"server":{"id":"test-id","name":"test-server","status":"BUILD"}}`))

		return
	}

	if r.Method == http.MethodPost && r.URL.Path == "/servers/server-id/action" {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := json.Unmarshal(raw, &f.body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"server":{"id":"server-id","status":"REBUILD"}}`))

		return
	}

	http.NotFound(w, r)
}

func TestRebuildServerSendsOnlyImage(t *testing.T) {
	t.Parallel()

	fake := &fakeNovaServer{}

	srv := httptest.NewServer(fake)
	defer srv.Close()

	client := openstack.NewTestComputeClient(srv.URL + "/")
	options := openstack.ServerRebuildOptions{
		ImageID: idstest.MustParseImageID("bbbbbbbb-0000-0000-0000-000000000001"),
	}

	_, err := client.RebuildServer(t.Context(), "server-id", options)
	require.NoError(t, err)

	rebuildBody, ok := fake.body["rebuild"].(map[string]any)
	require.True(t, ok, "body missing 'rebuild' key")
	assert.Equal(t, options.ImageID.String(), rebuildBody["imageRef"])

	// key_name and user_data are omitted so Nova preserves the stored keypair and
	// create-time user data, keeping the rebuilt guest create-equivalent.
	_, hasKeyName := rebuildBody["key_name"]
	assert.False(t, hasKeyName, "key_name must be omitted so Nova keeps the stored keypair")

	_, hasUserData := rebuildBody["user_data"]
	assert.False(t, hasUserData, "user_data must be omitted so Nova keeps the create-time user data")
}

// newServerFixture is a server named test-server, matching the name the fake
// Nova handlers list.
func newServerFixture() *unikornv1.Server {
	return &unikornv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				coreconstants.NameLabel: "test-server",
			},
		},
		Spec: unikornv1.ServerSpec{
			Image:    &unikornv1.ServerImage{ID: idstest.MustParseImageID("bbbbbbbb-0000-0000-0000-000000000001")},
			FlavorID: idstest.MustParseFlavorID("bbbbbbbb-0000-0000-0000-000000000002"),
		},
	}
}

func TestCreateServer_HypervisorHostname(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name               string
		infrastructureRef  *string
		wantHypervisorHost string
	}{
		{
			name:               "WithInfrastructureRef",
			infrastructureRef:  ptr.To("node-uuid-123"),
			wantHypervisorHost: "node-uuid-123",
		},
		{
			name:               "WithoutInfrastructureRef",
			infrastructureRef:  nil,
			wantHypervisorHost: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			fake := &fakeNovaServer{}

			srv := httptest.NewServer(fake)
			defer srv.Close()

			client := openstack.NewTestComputeClient(srv.URL + "/")

			server := newServerFixture()
			server.Spec.InfrastructureRef = c.infrastructureRef

			_, err := client.CreateServer(t.Context(), server, "keypair", nil, nil, nil)
			require.NoError(t, err)

			require.NotNil(t, fake.body, "no request body captured")

			serverBody, ok := fake.body["server"].(map[string]any)
			require.True(t, ok, "body missing 'server' key")

			got, _ := serverBody["hypervisor_hostname"].(string)
			assert.Equal(t, c.wantHypervisorHost, got)
		})
	}
}

// faultReadNovaServer serves a fixed one-server list and a per-ID read, counting
// the per-ID reads so tests can pin exactly when the fault-enrichment re-read
// happens. The list response never carries a fault, mirroring the Nova behaviour
// (up to 2025.2) the re-read exists for.
type faultReadNovaServer struct {
	listStatus       string
	detailHTTPStatus int
	detailReads      int
}

func (f *faultReadNovaServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/servers/detail" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"servers":[{"id":"server-id","name":"test-server","status":%q}]}`, f.listStatus)

		return
	}

	if r.Method == http.MethodGet && r.URL.Path == "/servers/server-id" {
		f.detailReads++

		if f.detailHTTPStatus != http.StatusOK {
			http.Error(w, "boom", f.detailHTTPStatus)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"server":{"id":"server-id","name":"test-server","status":%q,`+
			`"fault":{"code":500,"message":"No valid host was found","created":"2026-08-03T12:00:00Z"}}}`, f.listStatus)

		return
	}

	http.NotFound(w, r)
}

// TestGetServerHealthyDoesNotReRead pins the conditional half of the fault
// enrichment: a server listed in a non-fault status must not pay a second call
// on every read.
func TestGetServerHealthyDoesNotReRead(t *testing.T) {
	t.Parallel()

	fake := &faultReadNovaServer{listStatus: "ACTIVE", detailHTTPStatus: http.StatusOK}

	srv := httptest.NewServer(fake)
	defer srv.Close()

	client := openstack.NewTestComputeClient(srv.URL + "/")

	got, err := client.GetServer(t.Context(), newServerFixture())
	require.NoError(t, err)
	require.Equal(t, "ACTIVE", got.Status)
	assert.Zero(t, fake.detailReads, "a healthy server must be served from the list alone")
}

// TestGetServerDeletedDoesNotReRead pins that the re-read gates on ERROR alone:
// Nova's _fault_statuses also covers DELETED, but the only fault consumer
// discards a non-ERROR fault, so re-reading a deleted server is dead work.
func TestGetServerDeletedDoesNotReRead(t *testing.T) {
	t.Parallel()

	fake := &faultReadNovaServer{listStatus: "DELETED", detailHTTPStatus: http.StatusOK}

	srv := httptest.NewServer(fake)
	defer srv.Close()

	client := openstack.NewTestComputeClient(srv.URL + "/")

	got, err := client.GetServer(t.Context(), newServerFixture())
	require.NoError(t, err)
	require.Equal(t, "DELETED", got.Status)
	assert.Zero(t, fake.detailReads, "a deleted server's fault has no consumer, so it must not be fetched")
}

// TestGetServerErroredReReadsForFault pins the enrichment itself: a listed ERROR
// server carries no fault (Nova can omit it from a list response), so GetServer
// re-reads by ID and returns the detailed record with the fault populated.
func TestGetServerErroredReReadsForFault(t *testing.T) {
	t.Parallel()

	fake := &faultReadNovaServer{listStatus: "ERROR", detailHTTPStatus: http.StatusOK}

	srv := httptest.NewServer(fake)
	defer srv.Close()

	client := openstack.NewTestComputeClient(srv.URL + "/")

	got, err := client.GetServer(t.Context(), newServerFixture())
	require.NoError(t, err)
	require.Equal(t, "ERROR", got.Status)
	assert.Equal(t, 1, fake.detailReads)
	assert.Equal(t, 500, got.Fault.Code)
	assert.Equal(t, "No valid host was found", got.Fault.Message)
}

// TestGetServerErroredDegradesOnFailedReRead pins that the fault is an
// enrichment, not the reason for the read: a failed per-ID re-read degrades to
// the listed record rather than failing the lookup.
func TestGetServerErroredDegradesOnFailedReRead(t *testing.T) {
	t.Parallel()

	fake := &faultReadNovaServer{listStatus: "ERROR", detailHTTPStatus: http.StatusInternalServerError}

	srv := httptest.NewServer(fake)
	defer srv.Close()

	client := openstack.NewTestComputeClient(srv.URL + "/")

	got, err := client.GetServer(t.Context(), newServerFixture())
	require.NoError(t, err, "a failed fault re-read must not fail the lookup")
	require.Equal(t, "ERROR", got.Status)
	assert.Equal(t, 1, fake.detailReads)
	assert.Empty(t, got.Fault.Message, "the degraded record is the listed one, which carries no fault")
}
