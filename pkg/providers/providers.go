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

	mu    sync.RWMutex
	cache map[string]types.CommonProvider
}

type Options struct {
	// WarmImageCache enables startup-time image cache initialization.
	WarmImageCache bool
}

// New creates and synchronously initializes all region providers. Startup-time region
// discovery and provider construction use initClient so bootstrap reads can happen
// before a controller manager cache has started, while the returned provider set retains
// runtimeClient for normal cached operation after startup. The chosen behaviour is to
// fail on initialization failure, the reasoning is that during upgrade an old version of
// the service should be running to handle traffic, and we'd rather not have something
// put into production that is known to be broken. Regions discovered after startup are
// loaded on demand and then shared for subsequent lookups.
func New(ctx context.Context, initClient client.Client, runtimeClient client.Client, namespace string, opts Options) (Providers, error) {
	var regions unikornv1.RegionList

	if err := initClient.List(ctx, &regions, &client.ListOptions{Namespace: namespace}); err != nil {
		return nil, fmt.Errorf("%w: failed to list regions", err)
	}

	cache := map[string]types.CommonProvider{}

	// TODO: we can avoid long warm ups in future by doing this concurrently
	// if it becomes too slow.
	for i := range regions.Items {
		provider, err := newProvider(ctx, initClient, runtimeClient, &regions.Items[i], opts)
		if err != nil {
			return nil, err
		}

		cache[regions.Items[i].Name] = provider
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
	return p.lookup(context.Background(), regionID)
}

// LookupCloud returns a provider as identified by the region ID and must be
// a cloud type.
func (p *providersImpl) LookupCloud(regionID string) (types.Provider, error) {
	provider, err := p.lookup(context.Background(), regionID)
	if err != nil {
		return nil, err
	}

	cloudProvider, ok := provider.(types.Provider)
	if !ok {
		return nil, ErrRegionWrongKind
	}

	return cloudProvider, nil
}

// lookup returns a provider for the given region.
func (p *providersImpl) lookup(ctx context.Context, regionID string) (types.CommonProvider, error) {
	p.mu.RLock()
	provider, ok := p.cache[regionID]
	p.mu.RUnlock()

	if !ok {
		return p.load(ctx, regionID)
	}

	return provider, nil
}

func (p *providersImpl) load(ctx context.Context, regionID string) (types.CommonProvider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Another goroutine may have populated the cache after the read-side miss
	// and before we acquired the write lock, so recheck under exclusive access.
	if provider, ok := p.cache[regionID]; ok {
		return provider, nil
	}

	region := &unikornv1.Region{}

	if err := p.client.Get(ctx, client.ObjectKey{Namespace: p.namespace, Name: regionID}, region); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return nil, ErrRegionNotFound
		}

		return nil, fmt.Errorf("%w: failed to get region", err)
	}

	provider, err := newProvider(ctx, p.client, p.client, region, p.opts)
	if err != nil {
		return nil, err
	}

	p.cache[regionID] = provider

	return provider, nil
}
