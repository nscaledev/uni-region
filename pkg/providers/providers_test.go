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

func TestLookupCommonLoadsRegionOnMiss(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()

	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("adding client-go scheme: %v", err)
	}

	if err := unikornv1.AddToScheme(scheme); err != nil {
		t.Fatalf("adding unikorn scheme: %v", err)
	}

	namespace := "test"
	ctx := t.Context()

	region := &unikornv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "sim-public",
		},
		Spec: unikornv1.RegionSpec{
			Provider: unikornv1.ProviderSimulated,
		},
	}

	runtimeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

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

// newTestClient builds a fake client seeded with two regions: a healthy simulated
// region ("sim-public") and a region whose provider fails to construct ("broken").
// An unimplemented provider kind is used to deterministically fail construction
// without needing network or TLS fixtures — from providers.New's point of view this
// is the same failure shape as an OpenStack region with an expired or otherwise
// invalid TLS certificate: newProvider returns an error for that one region.
func newTestClient(t *testing.T, namespace string) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()

	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("adding client-go scheme: %v", err)
	}

	if err := unikornv1.AddToScheme(scheme); err != nil {
		t.Fatalf("adding unikorn scheme: %v", err)
	}

	healthyRegion := &unikornv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "sim-public",
		},
		Spec: unikornv1.RegionSpec{
			Provider: unikornv1.ProviderSimulated,
		},
	}

	brokenRegion := &unikornv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "broken",
		},
		Spec: unikornv1.RegionSpec{
			Provider: unikornv1.Provider("unimplemented"),
		},
	}

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(healthyRegion, brokenRegion).Build()
}

// TestNewFailsEntirelyByDefaultOnRegionInitError locks in the existing fail-fast
// behaviour relied on by the API server and controller manager: a single broken
// region aborts the whole call unless a caller opts out.
func TestNewFailsEntirelyByDefaultOnRegionInitError(t *testing.T) {
	t.Parallel()

	namespace := "test"
	ctx := t.Context()

	cli := newTestClient(t, namespace)

	if _, err := providers.New(ctx, cli, cli, namespace, providers.Options{}); err == nil {
		t.Fatal("expected New to fail when a region provider fails to initialize")
	}
}

// TestNewTolerateRegionInitErrorsSkipsBrokenRegion is the region-monitor case: a
// region with a broken provider (e.g. expired/invalid TLS certificate) must not
// prevent the process from starting and serving every other, healthy region.
func TestNewTolerateRegionInitErrorsSkipsBrokenRegion(t *testing.T) {
	t.Parallel()

	namespace := "test"
	ctx := t.Context()

	cli := newTestClient(t, namespace)

	providerSet, err := providers.New(ctx, cli, cli, namespace, providers.Options{TolerateRegionInitErrors: true})
	if err != nil {
		t.Fatalf("expected New to tolerate a single broken region, got: %v", err)
	}

	if _, err := providerSet.LookupCommon("sim-public"); err != nil {
		t.Fatalf("expected the healthy region to be usable: %v", err)
	}

	_, err = providerSet.LookupCommon("broken")
	if err == nil {
		t.Fatal("expected lookup of the broken region to still fail")
	}

	if !errors.Is(err, providers.ErrRegionProviderUnimplemented) {
		t.Fatalf("expected broken region lookup to retry initialization and surface the same error, got: %v", err)
	}
}
