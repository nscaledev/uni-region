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
	"slices"
	"sync"

	servererrors "github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/kubernetes"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
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

// providersImpl is a generic lazy cache of providers keyed by region ID.
// The constructor is called on first lookup for each region.
type providersImpl[T any] struct {
	client      client.Client
	namespace   string
	cache       map[string]T
	lock        sync.Mutex
	constructor func(context.Context, client.Client, *unikornv1.Region) (T, error)
}

func newProvidersImpl[T any](c client.Client, namespace string, constructor func(context.Context, client.Client, *unikornv1.Region) (T, error)) *providersImpl[T] {
	return &providersImpl[T]{
		client:      c,
		namespace:   namespace,
		cache:       map[string]T{},
		constructor: constructor,
	}
}

func (p *providersImpl[T]) lookup(ctx context.Context, regionID string) (T, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if provider, ok := p.cache[regionID]; ok {
		return provider, nil
	}

	var regions unikornv1.RegionList

	if err := p.client.List(ctx, &regions, &client.ListOptions{Namespace: p.namespace}); err != nil {
		var zero T
		return zero, err
	}

	index := slices.IndexFunc(regions.Items, func(r unikornv1.Region) bool {
		return r.Name == regionID
	})

	if index < 0 {
		var zero T
		return zero, ErrRegionNotFound
	}

	provider, err := p.constructor(ctx, p.client, &regions.Items[index])
	if err != nil {
		var zero T
		return zero, err
	}

	p.cache[regionID] = provider

	return provider, nil
}

// provisionerProvidersImpl implements ProvisionerProviders for controller/provisioner use.
type provisionerProvidersImpl struct {
	*providersImpl[types.ProvisionerProvider]
}

func (p *provisionerProvidersImpl) LookupProvisioner(ctx context.Context, regionID string) (types.ProvisionerProvider, error) {
	return p.lookup(ctx, regionID)
}

func newProvisionerProvider(ctx context.Context, c client.Client, region *unikornv1.Region) (types.ProvisionerProvider, error) {
	switch region.Spec.Provider {
	case unikornv1.ProviderOpenstack:
		return openstack.NewProvisioner(ctx, c, region)
	case unikornv1.ProviderKubernetes:
		break
	}

	return nil, ErrRegionWrongKind
}

// New creates a provider factory for controller/provisioner use.
func NewForProvisioner(c client.Client, namespace string) ProvisionerProviders {
	return &provisionerProvidersImpl{
		newProvidersImpl(c, namespace, newProvisionerProvider),
	}
}

// cloudProvidersImpl implements Providers for API server use.
type serverProvidersImpl struct {
	*providersImpl[types.CommonProvider]
}

func (p *serverProvidersImpl) LookupCommon(ctx context.Context, regionID string) (types.CommonProvider, error) {
	return p.lookup(ctx, regionID)
}

func (p *serverProvidersImpl) LookupCloud(ctx context.Context, regionID string) (types.Provider, error) {
	provider, err := p.lookup(ctx, regionID)
	if err != nil {
		return nil, err
	}

	cloudProvider, ok := provider.(types.Provider)
	if !ok {
		return nil, ErrRegionWrongKind
	}

	return cloudProvider, nil
}

func newServerProvider(ctx context.Context, c client.Client, region *unikornv1.Region) (types.CommonProvider, error) {
	switch region.Spec.Provider {
	case unikornv1.ProviderKubernetes:
		return kubernetes.New(ctx, c, region)
	case unikornv1.ProviderOpenstack:
		return openstack.New(ctx, c, region)
	}

	return nil, ErrRegionProviderUnimplemented
}

// NewCloud creates a provider factory for API server use.
func NewForServer(c client.Client, namespace string) ServerProviders {
	return &serverProvidersImpl{
		newProvidersImpl(c, namespace, newServerProvider),
	}
}
