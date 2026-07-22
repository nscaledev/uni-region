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
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"

	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

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

	fakeClient := newProviderTestClient(t)
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
