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

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/kubernetes"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrRegionNotFound is raised when a region doesn't exist.
	ErrRegionNotFound = errors.New("region doesn't exist")

	// ErrRegionProviderUnimplemented is raised when you haven't written
	// it yet!
	ErrRegionProviderUnimplemented = errors.New("region provider unimplemented")
)

//nolint:gochecknoglobals
var cache = map[string]types.Provider{}

// newProvider a new Provider.
func newProvider(ctx context.Context, client client.Client, region *unikornv1.Region) (types.Provider, error) {
	switch region.Spec.Provider {
	case unikornv1.ProviderKubernetes:
		return kubernetes.New(ctx, client, region)
	case unikornv1.ProviderOpenstack:
		return openstack.New(ctx, client, region)
	}

	return nil, ErrRegionProviderUnimplemented
}

// New returns a new provider for the given region.
func New(ctx context.Context, c client.Client, namespace, regionID string) (types.Provider, error) {
	if provider, ok := cache[regionID]; ok {
		return provider, nil
	}

	var regions unikornv1.RegionList

	if err := c.List(ctx, &regions, &client.ListOptions{Namespace: namespace}); err != nil {
		return nil, err
	}

	matchRegionID := func(region unikornv1.Region) bool {
		return region.Name == regionID
	}

	index := slices.IndexFunc(regions.Items, matchRegionID)
	if index < 0 {
		return nil, ErrRegionNotFound
	}

	provider, err := newProvider(ctx, c, &regions.Items[index])
	if err != nil {
		return nil, err
	}

	cache[regionID] = provider

	return provider, nil
}
