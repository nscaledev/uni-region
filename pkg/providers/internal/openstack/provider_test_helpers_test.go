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
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	k8sv1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// fakeOpenstack is a minimal OpenStack-compatible HTTP server used by provider tests.
// It handles authentication (returning a token + service catalog), volume type
// discovery, and returns a single fake flavor for other resource requests.
type fakeOpenstack struct {
	ts                 *httptest.Server
	volumeTypeRequests atomic.Int64
}

func newFakeOpenstack(t *testing.T) *fakeOpenstack {
	t.Helper()

	f := &fakeOpenstack{}
	f.ts = httptest.NewServer(http.HandlerFunc(f.ServeHTTP))
	t.Cleanup(f.ts.Close)

	return f
}

func (f *fakeOpenstack) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
			f.ts.URL)

		return
	}

	// gophercloud GETs "/" twice: once via ChooseVersion (auth, expects doubly-enveloped
	// versions.values with links) and once via GetServiceVersions per service client
	// (expects a version list that includes v2.1 so compute/image/network pass the
	// endpointSupportsVersion check). The doubly-enveloped format satisfies both.
	if r.URL.Path == "/" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w,
			`{"versions":{"values":[
				{"id":"v2.1","status":"CURRENT","links":[{"href":%q,"rel":"self"}]},
				{"id":"v3","status":"current","links":[{"href":%q,"rel":"self"}]}
				]}}`,
			f.ts.URL+"/v2.1/", f.ts.URL+"/v3/")

		return
	}

	if r.Method == http.MethodGet && r.URL.Path == "/types" {
		f.volumeTypeRequests.Add(1)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		fmt.Fprint(w, `{"volume_types":[
			{
				"id":"slow",
				"name":"slow-hdd",
				"description":"Bulk capacity",
				"is_public":true,
				"os-volume-type-access:is_public":true
			},
			{
				"id":"fast",
				"name":"fast-nvme",
				"description":"Latency sensitive",
				"is_public":true,
				"os-volume-type-access:is_public":true
			},
			{
				"id":"private",
				"name":"private-nvme",
				"description":"Provider internal",
				"is_public":false,
				"os-volume-type-access:is_public":false
			}
		]}`)

		return
	}

	// Delay the flavor-list response so that the goroutine calling GetFlavors()
	// blocks long enough for a concurrent goroutine to acquire p.lock, run
	// serviceClientRefresh, and write p.region — creating the race window.
	time.Sleep(10 * time.Millisecond)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// A single flavor is enough; more would flood TSan's 4-cell shadow with reads
	// of p.region and evict the writer's write record before it can be matched.
	fmt.Fprintf(w, `{"flavors":[{"id":"f1","name":"m1.small","vcpus":1,"ram":1024,"disk":10,"swap":""}]}`)
}

// newProviderTestClient creates a controller-runtime fake client whose scheme
// covers both Region custom resources and core Kubernetes Secrets.
func newProviderTestClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme, err := coreclient.NewScheme(regionv1.AddToScheme, k8sv1.AddToScheme)
	require.NoError(t, err)

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}
