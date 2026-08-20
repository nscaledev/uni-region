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

package providers_test

import (
	"errors"
	"testing"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// newTestClient builds a fake client seeded with the supplied objects.
func newTestClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()

	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("adding client-go scheme: %v", err)
	}

	if err := unikornv1.AddToScheme(scheme); err != nil {
		t.Fatalf("adding unikorn scheme: %v", err)
	}

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

// newTestRegion returns a region of the given provider kind.
func newTestRegion(namespace, name string, provider unikornv1.Provider) *unikornv1.Region {
	return &unikornv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: unikornv1.RegionSpec{
			Provider: provider,
		},
	}
}

func TestLookupCommonLoadsRegionOnMiss(t *testing.T) {
	t.Parallel()

	namespace := "test"
	ctx := t.Context()

	region := newTestRegion(namespace, "sim-public", unikornv1.ProviderSimulated)

	runtimeClient := newTestClient(t)

	providerSet, err := providers.New(ctx, runtimeClient, runtimeClient, namespace, providers.Options{})
	if err != nil {
		t.Fatalf("creating providers: %v", err)
	}

	if err := runtimeClient.Create(ctx, region); err != nil {
		t.Fatalf("creating region after startup: %v", err)
	}

	if _, err := providerSet.LookupCommon("sim-public"); err != nil {
		t.Fatalf("lookup on miss: %v", err)
	}

	if err := runtimeClient.Delete(ctx, region); err != nil {
		t.Fatalf("deleting region after lazy load: %v", err)
	}

	if _, err := providerSet.LookupCommon("sim-public"); err != nil {
		t.Fatalf("lookup from cache after delete: %v", err)
	}
}

// TestNewSkipsRegionsThatFailToInitialize asserts that one region failing to
// initialize does not deny service to every other region. The broken region uses
// an unimplemented provider kind, which fails construction deterministically with
// no network involved; from New's point of view that is the same shape as a cloud
// region whose endpoint is unreachable.
func TestNewSkipsRegionsThatFailToInitialize(t *testing.T) {
	t.Parallel()

	namespace := "test"
	ctx := t.Context()

	healthy := newTestRegion(namespace, "sim-public", unikornv1.ProviderSimulated)
	broken := newTestRegion(namespace, "broken", unikornv1.Provider("unimplemented"))

	runtimeClient := newTestClient(t, healthy, broken)

	providerSet, err := providers.New(ctx, runtimeClient, runtimeClient, namespace, providers.Options{})
	if err != nil {
		t.Fatalf("creating providers with a broken region: %v", err)
	}

	if _, err := providerSet.LookupCommon("sim-public"); err != nil {
		t.Fatalf("lookup of the healthy region: %v", err)
	}

	// The broken region is absent from the cache rather than remembered as broken,
	// so a lookup retries initialization and fails the same way until it recovers.
	if _, err := providerSet.LookupCommon("broken"); !errors.Is(err, providers.ErrRegionProviderUnimplemented) {
		t.Fatalf("lookup of the broken region: want %v, got %v", providers.ErrRegionProviderUnimplemented, err)
	}
}
