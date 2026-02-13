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

type providersImpl struct {
	cache map[string]types.CommonProvider
}

func New(ctx context.Context, c client.Client, namespace string, withCaches bool) (Providers, error) {
	var regions unikornv1.RegionList

	if err := c.List(ctx, &regions, &client.ListOptions{Namespace: namespace}); err != nil {
		return nil, err
	}

	cache := map[string]types.CommonProvider{}

	// TODO: we can avoid long warm ups in future by doing this concurrently
	// if it becomes too slow.
	for i := range regions.Items {
		provider, err := newProvider(ctx, c, &regions.Items[i], withCaches)
		if err != nil {
			return nil, err
		}

		cache[regions.Items[i].Name] = provider
	}

	providers := &providersImpl{
		cache: cache,
	}

	return providers, nil
}

// newProvider a new Provider.
func newProvider(ctx context.Context, client client.Client, region *unikornv1.Region, withCaches bool) (types.CommonProvider, error) {
	switch region.Spec.Provider {
	case unikornv1.ProviderKubernetes:
		return kubernetes.New(ctx, client, region)
	case unikornv1.ProviderOpenstack:
		return openstack.New(ctx, client, region, withCaches)
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

// lookup returns a provider for the given region.
func (p *providersImpl) lookup(regionID string) (types.CommonProvider, error) {
	provider, ok := p.cache[regionID]
	if !ok {
		return nil, ErrRegionNotFound
	}

	return provider, nil
}
