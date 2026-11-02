/*
Copyright 2025 the Unikorn Authors.
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

package providers

import (
	"context"
	"errors"
	"fmt"
	"sync"

	servererrors "github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/kubernetes"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
	"github.com/unikorn-cloud/region/pkg/providers/internal/simulated"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	// ErrRegionWrongKind is raised when you need one type but someone has
	// asked for a different type.
	ErrRegionWrongKind = errors.New("region is of the wrong kind")

	// ErrRegionNotFound is raised when a region doesn't exist.
	ErrRegionNotFound = errors.New("region doesn't exist")

	// ErrRegionProviderUnimplemented is raised when you haven't written
	// it yet!
	ErrRegionProviderUnimplemented = errors.New("region provider unimplemented")

	// errBuildAbandoned is what lookups waiting on a build see if it panics.
	errBuildAbandoned = errors.New("region provider build did not finish")
)

func ProviderToServerError(err error) error {
	switch {
	case errors.Is(err, ErrRegionWrongKind):
		return servererrors.OAuth2InvalidRequest("region is not valid for this endpoint")
	case errors.Is(err, ErrRegionNotFound):
		return servererrors.HTTPNotFound()
	default:
	}

	return err
}

type providersImpl struct {
	client    client.Client
	namespace string
	opts      Options

	mu    sync.Mutex
	cache map[string]*entry
}

// entry is a region's provider, or its build in progress.  provider and err
// are set before done closes, and not written after.
type entry struct {
	done     chan struct{}
	provider types.CommonProvider
	err      error
}

type Options struct {
	// WarmImageCache enables startup-time image cache initialization.
	WarmImageCache bool
}

// New creates and synchronously initializes all region providers. Startup-time region
// discovery and provider construction use initClient so bootstrap reads can happen
// before a controller manager cache has started, while the returned provider set retains
// runtimeClient for normal cached operation after startup. A region whose provider fails
// to initialize is logged and skipped rather than failing the call: provider construction
// authenticates against a remote cloud, so the health of one region's substrate would
// otherwise decide whether this process runs at all. Skipped regions, like regions
// discovered after startup, are loaded on demand and then shared for subsequent lookups.
func New(ctx context.Context, initClient client.Client, runtimeClient client.Client, namespace string, opts Options) (Providers, error) {
	var regions unikornv1.RegionList

	if err := initClient.List(ctx, &regions, &client.ListOptions{Namespace: namespace}); err != nil {
		return nil, fmt.Errorf("%w: failed to list regions", err)
	}

	cache := map[string]*entry{}

	// TODO: we can avoid long warm ups in future by doing this concurrently
	// if it becomes too slow.
	for i := range regions.Items {
		provider, err := newProvider(ctx, initClient, runtimeClient, &regions.Items[i], opts)
		if err != nil {
			log.FromContext(ctx).Error(err, "region provider initialization failed, region unavailable until it recovers", "region", regions.Items[i].Name)

			continue
		}

		done := make(chan struct{})
		close(done)

		cache[regions.Items[i].Name] = &entry{done: done, provider: provider}
	}

	providers := &providersImpl{
		client:    runtimeClient,
		namespace: namespace,
		opts:      opts,
		cache:     cache,
	}

	return providers, nil
}

// newProvider constructs a provider for a region. initClient is used only for
// startup-time bootstrap work that cannot rely on a started manager cache, while
// runtimeClient is retained by the provider for normal operation afterwards.
func newProvider(ctx context.Context, initClient client.Client, runtimeClient client.Client, region *unikornv1.Region, opts Options) (types.CommonProvider, error) {
	switch region.Spec.Provider {
	case unikornv1.ProviderKubernetes:
		return kubernetes.New(ctx, runtimeClient, region)
	case unikornv1.ProviderOpenstack:
		return openstack.New(ctx, initClient, runtimeClient, region, openstack.Options{
			WarmImageCache: opts.WarmImageCache,
		})
	case unikornv1.ProviderSimulated:
		return simulated.New(ctx, runtimeClient, region)
	}

	return nil, ErrRegionProviderUnimplemented
}

// LookupCommon returns a provider as identified by the region ID of any type.
func (p *providersImpl) LookupCommon(regionID string) (types.CommonProvider, error) {
	return p.lookup(regionID)
}

// LookupCloud returns a provider as identified by the region ID and must be
// a cloud type.
func (p *providersImpl) LookupCloud(regionID string) (types.Provider, error) {
	provider, err := p.lookup(regionID)
	if err != nil {
		return nil, err
	}

	cloudProvider, ok := provider.(types.Provider)
	if !ok {
		return nil, ErrRegionWrongKind
	}

	return cloudProvider, nil
}

// lookup returns a region's provider, building it on first use.  The entry
// goes in the map before its build starts, so concurrent lookups share one
// build, and the build runs outside mu, so it holds up no other region.  See
// the README's Invariants And Guard Rails section.
func (p *providersImpl) lookup(regionID string) (types.CommonProvider, error) {
	p.mu.Lock()

	e, ok := p.cache[regionID]
	if !ok {
		e = &entry{done: make(chan struct{})}
		p.cache[regionID] = e
	}

	p.mu.Unlock()

	if !ok {
		p.build(regionID, e)
	}

	<-e.done

	return e.provider, e.err
}

// build fills in e, and removes it if the build fails or panics, so the next
// lookup retries.  It MUST NOT take a caller's context: a provider can start
// work that outlives the lookup, so it takes none.
func (p *providersImpl) build(regionID string, e *entry) {
	e.err = errBuildAbandoned

	defer func() {
		if e.err != nil {
			p.mu.Lock()
			delete(p.cache, regionID)
			p.mu.Unlock()
		}

		close(e.done)
	}()

	ctx := context.Background()

	region := &unikornv1.Region{}

	if err := p.client.Get(ctx, client.ObjectKey{Namespace: p.namespace, Name: regionID}, region); err != nil {
		if client.IgnoreNotFound(err) == nil {
			e.err = ErrRegionNotFound

			return
		}

		e.err = fmt.Errorf("%w: failed to get region", err)

		return
	}

	e.provider, e.err = newProvider(ctx, p.client, p.client, region, p.opts)
}
