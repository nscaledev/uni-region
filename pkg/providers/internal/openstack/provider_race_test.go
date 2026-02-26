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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"

	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// fakeOpenstack is a minimal OpenStack-compatible HTTP server used for race tests.
// It handles authentication (returning a token + service catalog) and returns a
// single fake flavor for any other request.
type fakeOpenstack struct {
	ts *httptest.Server
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
			{"type":"network","endpoints":[{"interface":"public","url":%[1]q,"region_id":""}]}
			],"expires_at":"2099-01-01T00:00:00.000000Z"}}`,
			f.ts.URL)

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
			f.ts.URL+"/v2.1/", f.ts.URL+"/v3/")

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

// newRaceTestClient creates a controller-runtime fake client whose scheme covers
// both the region custom resources and the core Kubernetes Secret type that
// serviceClientRefresh fetches.
func newRaceTestClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme, err := coreclient.NewScheme(regionv1.AddToScheme, k8sv1.AddToScheme)
	require.NoError(t, err)

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

// TestFlavorsRegionRace exposes the data race in Flavors(): after p.compute(ctx)
// releases the lock, the method reads p.region without holding the lock.
//
// A writer goroutine rotates the K8s secret so serviceClientRefresh detects a
// change and writes p.region under p.lock.  Because Region() holds no lock after
// returning, the writer loops far faster than the readers' 10 ms GetFlavors call,
// so the write lands inside the readers' race window on almost every iteration.
//
// Run with: go test -race ./pkg/providers/internal/openstack/...
func TestFlavorsRegionRace(t *testing.T) {
	t.Parallel()

	fakeClient := newRaceTestClient(t)
	ks := newFakeOpenstack(t)

	region := &regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{Name: "test-region", Namespace: "default"},
		Spec: regionv1.RegionSpec{
			Openstack: &regionv1.RegionOpenstackSpec{
				Endpoint: ks.ts.URL,
				ServiceAccountSecret: &regionv1.NamespacedObject{
					Name:      "test-secret",
					Namespace: "default",
				},
				Compute: &regionv1.RegionOpenstackComputeSpec{
					Flavors: &regionv1.OpenstackFlavorsSpec{
						Metadata: []regionv1.FlavorMetadata{
							{ID: "f1", Baremetal: true},
						},
					},
				},
			},
		},
	}

	secret := &k8sv1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "default"},
		Data: map[string][]byte{
			"domain-id":  []byte("domain"),
			"user-id":    []byte("user"),
			"password":   []byte("initial"),
			"project-id": []byte("project"),
		},
	}

	require.NoError(t, fakeClient.Create(t.Context(), secret))
	require.NoError(t, fakeClient.Create(t.Context(), region))

	p := openstack.NewTestProvider(fakeClient, region)

	ctx := t.Context()

	start := make(chan struct{})

	// Writer: rotates the secret so serviceClientRefresh often sees a change.
	stopWriter := make(chan struct{})

	var writerWg sync.WaitGroup

	writerWg.Add(1)

	go func() {
		defer writerWg.Done()
		<-start

		for {
			select {
			case <-stopWriter:
				return
			default:
			}

			var s k8sv1.Secret
			if err := fakeClient.Get(ctx, client.ObjectKey{Name: "test-secret", Namespace: "default"}, &s); err != nil {
				continue
			}

			s.Data["password"] = []byte(uuid.NewUUID())

			if err := fakeClient.Update(ctx, &s); err != nil {
				continue
			}
		}
	}()

	var readerWg sync.WaitGroup

	// Readers: call Flavors, which does both a serviceClientRefresh and reads from provider.region
	for range 5 {
		readerWg.Add(1)

		go func() {
			defer readerWg.Done()
			<-start

			_, err := p.Flavors(ctx)
			assert.NoError(t, err)
		}()
	}

	close(start)
	readerWg.Wait()
	close(stopWriter)
	writerWg.Wait()
}
