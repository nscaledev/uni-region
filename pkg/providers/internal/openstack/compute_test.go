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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// fakeNovaServer captures server-create requests and returns a minimal response.
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

	http.NotFound(w, r)
}

func newServerFixture(name string) *unikornv1.Server {
	return &unikornv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				coreconstants.NameLabel: name,
			},
		},
		Spec: unikornv1.ServerSpec{
			Image:    &unikornv1.ServerImage{ID: "image-id"},
			FlavorID: "flavor-id",
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

			server := newServerFixture("test-server")
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
