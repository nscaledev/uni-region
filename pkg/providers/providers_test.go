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
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
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

// TestLookupIsNotHeldUpByAnotherRegionsBuild asserts that a region whose build
// hangs delays only its own lookups: another region still builds.  Both are
// created after startup, so neither is cached.  The "stalled" build hangs at
// its Region read, which runs inside the build, as one whose cloud does not
// answer does.
func TestLookupIsNotHeldUpByAnotherRegionsBuild(t *testing.T) {
	t.Parallel()

	namespace := "stall"
	ctx := t.Context()

	entered := make(chan struct{})
	release := make(chan struct{})

	var once sync.Once

	t.Cleanup(func() { close(release) })

	runtimeClient := fake.NewClientBuilder().
		WithScheme(newTestClient(t).Scheme()).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if key.Name == "stalled" {
					once.Do(func() { close(entered) })
					<-release
				}

				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	providerSet, err := providers.New(ctx, runtimeClient, runtimeClient, namespace, providers.Options{})
	if err != nil {
		t.Fatalf("creating providers: %v", err)
	}

	for _, name := range []string{"sim-public", "stalled"} {
		if err := runtimeClient.Create(ctx, newTestRegion(namespace, name, unikornv1.ProviderSimulated)); err != nil {
			t.Fatalf("creating region %s: %v", name, err)
		}
	}

	go func() {
		_, _ = providerSet.LookupCommon("stalled")
	}()

	<-entered

	done := make(chan error, 1)

	go func() {
		_, err := providerSet.LookupCommon("sim-public")
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("lookup of the healthy region: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lookup of the healthy region waited on another region's build")
	}
}

// TestConcurrentLookupsBuildOnce asserts that many concurrent lookups of a
// region missing from the cache build it once, counted by its Region reads.
// It repeats so that callers arriving as a build finishes are among those
// tested.
func TestConcurrentLookupsBuildOnce(t *testing.T) {
	t.Parallel()

	const (
		rounds  = 200
		callers = 64
	)

	for round := range rounds {
		namespace := "once"
		ctx := t.Context()
		reads := &atomic.Int32{}

		runtimeClient := fake.NewClientBuilder().
			WithScheme(newTestClient(t).Scheme()).
			WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					reads.Add(1)

					return c.Get(ctx, key, obj, opts...)
				},
			}).
			Build()

		providerSet, err := providers.New(ctx, runtimeClient, runtimeClient, namespace, providers.Options{})
		if err != nil {
			t.Fatalf("creating providers: %v", err)
		}

		if err := runtimeClient.Create(ctx, newTestRegion(namespace, "sim-public", unikornv1.ProviderSimulated)); err != nil {
			t.Fatalf("creating region: %v", err)
		}

		var wg sync.WaitGroup

		for range callers {
			wg.Go(func() {
				if _, err := providerSet.LookupCommon("sim-public"); err != nil {
					t.Errorf("lookup: %v", err)
				}
			})
		}

		wg.Wait()

		if n := reads.Load(); n != 1 {
			t.Fatalf("round %d: %d concurrent lookups built the region %d times, want 1", round, callers, n)
		}
	}
}

// errUnreachable stands in for a cloud or API server that did not answer.
var errUnreachable = errors.New("unreachable")

// TestLookupRetriesAFailedBuild asserts that a failed build is not remembered:
// the next lookup builds again, and succeeds once the cause has gone.
func TestLookupRetriesAFailedBuild(t *testing.T) {
	t.Parallel()

	namespace := "retry"
	ctx := t.Context()

	var failed atomic.Bool

	runtimeClient := fake.NewClientBuilder().
		WithScheme(newTestClient(t).Scheme()).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if failed.CompareAndSwap(false, true) {
					return errUnreachable
				}

				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	providerSet, err := providers.New(ctx, runtimeClient, runtimeClient, namespace, providers.Options{})
	if err != nil {
		t.Fatalf("creating providers: %v", err)
	}

	if err := runtimeClient.Create(ctx, newTestRegion(namespace, "sim-public", unikornv1.ProviderSimulated)); err != nil {
		t.Fatalf("creating region: %v", err)
	}

	if _, err := providerSet.LookupCommon("sim-public"); !errors.Is(err, errUnreachable) {
		t.Fatalf("first lookup: want %v, got %v", errUnreachable, err)
	}

	if _, err := providerSet.LookupCommon("sim-public"); err != nil {
		t.Fatalf("lookup after the failure cleared: %v", err)
	}
}

// TestLookupRetriesAPanickedBuild asserts that a build that panics leaves no
// entry behind, so the next lookup builds again, and that a lookup waiting on
// it never gets a nil provider with no error.  The waiter half can only pass
// wrongly, if the waiter arrives after the panic.
func TestLookupRetriesAPanickedBuild(t *testing.T) {
	t.Parallel()

	namespace := "panic"
	ctx := t.Context()

	var panicked atomic.Bool

	entered := make(chan struct{})
	release := make(chan struct{})

	runtimeClient := fake.NewClientBuilder().
		WithScheme(newTestClient(t).Scheme()).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if panicked.CompareAndSwap(false, true) {
					close(entered)
					<-release
					panic("build failed")
				}

				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	providerSet, err := providers.New(ctx, runtimeClient, runtimeClient, namespace, providers.Options{})
	if err != nil {
		t.Fatalf("creating providers: %v", err)
	}

	if err := runtimeClient.Create(ctx, newTestRegion(namespace, "sim-public", unikornv1.ProviderSimulated)); err != nil {
		t.Fatalf("creating region: %v", err)
	}

	built := make(chan struct{})

	go func() {
		defer close(built)
		defer func() { _ = recover() }()

		_, _ = providerSet.LookupCommon("sim-public")
	}()

	<-entered

	type result struct {
		provider types.CommonProvider
		err      error
	}

	waited := make(chan result, 1)

	go func() {
		provider, err := providerSet.LookupCommon("sim-public")
		waited <- result{provider, err}
	}()

	// Give the waiter time to join the build before it panics.
	time.Sleep(100 * time.Millisecond)
	close(release)
	<-built

	if r := <-waited; r.provider == nil && r.err == nil {
		t.Fatal("lookup waiting on a panicked build got no provider and no error")
	}

	provider, err := providerSet.LookupCommon("sim-public")
	if err != nil || provider == nil {
		t.Fatalf("lookup after a panicked build: want a provider, got %v, %v", provider, err)
	}
}

// TestLookupOfAMissingRegion asserts that a region that does not exist is
// reported as not found, which the API turns into a 404, and that the answer
// is not cached: once the region exists, the next lookup finds it.
func TestLookupOfAMissingRegion(t *testing.T) {
	t.Parallel()

	namespace := "missing"
	ctx := t.Context()

	runtimeClient := newTestClient(t)

	providerSet, err := providers.New(ctx, runtimeClient, runtimeClient, namespace, providers.Options{})
	if err != nil {
		t.Fatalf("creating providers: %v", err)
	}

	if _, err := providerSet.LookupCommon("late"); !errors.Is(err, providers.ErrRegionNotFound) {
		t.Fatalf("lookup of a missing region: want %v, got %v", providers.ErrRegionNotFound, err)
	}

	if err := runtimeClient.Create(ctx, newTestRegion(namespace, "late", unikornv1.ProviderSimulated)); err != nil {
		t.Fatalf("creating region: %v", err)
	}

	if _, err := providerSet.LookupCommon("late"); err != nil {
		t.Fatalf("lookup once the region exists: %v", err)
	}
}
