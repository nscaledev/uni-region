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

package openstack

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/v2/openstack/placement/v1/resourceproviders"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

const (
	placementAPIMicroversion = "1.18"

	placementResourceExtraSpecPrefix = "resources:"
	customPlacementResourcePrefix    = "CUSTOM_"
)

var errPlacementResourceClassRequired = errors.New("placement resource class is required")

// PlacementResourceProviderQuery scopes an OpenStack Placement provider lookup.
type PlacementResourceProviderQuery struct {
	InfrastructureRef string
	ResourceClass     string
	RequiredTraits    []string
}

// PlacementClient queries OpenStack Placement for provider availability.
type PlacementClient struct {
	client *gophercloud.ServiceClient
}

// NewPlacementClient creates a Placement API client.
func NewPlacementClient(ctx context.Context, provider CredentialProvider) (*PlacementClient, error) {
	providerClient, err := provider.Client(ctx)
	if err != nil {
		return nil, err
	}

	client, err := openstack.NewPlacementV1(providerClient, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}

	client.Microversion = placementAPIMicroversion

	return &PlacementClient{client: client}, nil
}

// ResourceProviderAvailable reports whether the pinned provider currently has
// available inventory and required traits.
func (c *PlacementClient) ResourceProviderAvailable(ctx context.Context, query PlacementResourceProviderQuery) (bool, error) {
	ref := strings.TrimSpace(query.InfrastructureRef)
	if ref == "" {
		return false, nil
	}

	providers, err := c.listResourceProviders(ctx, query)
	if err != nil {
		return false, err
	}

	for _, provider := range providers {
		if provider.UUID == ref || provider.Name == ref {
			return true, nil
		}
	}

	return false, nil
}

func (c *PlacementClient) listResourceProviders(ctx context.Context, query PlacementResourceProviderQuery) ([]resourceproviders.ResourceProvider, error) {
	resourceClass := strings.TrimSpace(query.ResourceClass)
	if resourceClass == "" {
		return nil, errPlacementResourceClassRequired
	}

	page, err := resourceproviders.List(c.client, resourceproviders.ListOpts{
		Resources: placementResourceQuery(resourceClass),
		Required:  placementRequiredTraitsQuery(query.RequiredTraits),
	}).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	return resourceproviders.ExtractResourceProviders(page)
}

func placementResourceQuery(resourceClass string) string {
	return customPlacementResourceClass(resourceClass) + ":1"
}

func customPlacementResourceClass(resourceClass string) string {
	upper := strings.ToUpper(strings.TrimSpace(resourceClass))
	if strings.HasPrefix(upper, customPlacementResourcePrefix) {
		return upper
	}

	normalized := strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		default:
			return '_'
		}
	}, upper)

	return customPlacementResourcePrefix + strings.Trim(normalized, "_")
}

func placementPreflightRequiredTraits(preflight *unikornv1.PlacementPreflightSpec) []string {
	if preflight == nil || len(preflight.RequiredTraits) == 0 {
		return nil
	}

	return normalizePlacementRequiredTraits(preflight.RequiredTraits)
}

func placementRequiredTraitsQuery(traits []string) string {
	return strings.Join(normalizePlacementRequiredTraits(traits), ",")
}

func normalizePlacementRequiredTraits(traits []string) []string {
	required := make([]string, 0, len(traits))
	seen := map[string]struct{}{}

	for _, trait := range traits {
		normalized := strings.ToUpper(strings.TrimSpace(trait))
		if normalized == "" {
			continue
		}

		if _, ok := seen[normalized]; ok {
			continue
		}

		seen[normalized] = struct{}{}

		required = append(required, normalized)
	}

	return required
}

type serverCreatePreflight func(context.Context, *unikornv1.Server) error

type placementClientFactory func(context.Context, *unikornv1.Server) (PlacementInterface, error)

type serverCreatePlacementPreflight struct {
	config                 func() *unikornv1.PlacementPreflightSpec
	flavorClient           FlavorInterface
	placementClientFactory placementClientFactory
}

func (p serverCreatePlacementPreflight) check(ctx context.Context, server *unikornv1.Server) error {
	config := p.config()
	if config == nil || !config.Enabled || server.Spec.InfrastructureRef == nil {
		return nil
	}

	resourceClass, err := p.flavorPlacementResourceClass(ctx, server.Spec.FlavorID)
	if err != nil {
		return err
	}

	placementClient, err := p.placementClientFactory(ctx, server)
	if err != nil {
		return err
	}

	available, err := placementClient.ResourceProviderAvailable(ctx, PlacementResourceProviderQuery{
		InfrastructureRef: *server.Spec.InfrastructureRef,
		ResourceClass:     resourceClass,
		RequiredTraits:    placementPreflightRequiredTraits(config),
	})
	if err != nil {
		return err
	}

	if !available {
		return fmt.Errorf("%w: openstack placement resource provider %q is not ready for flavor %q", provisioners.ErrYield, *server.Spec.InfrastructureRef, server.Spec.FlavorID)
	}

	return nil
}

func (p serverCreatePlacementPreflight) flavorPlacementResourceClass(ctx context.Context, flavorID string) (string, error) {
	flavors, err := p.flavorClient.GetFlavors(ctx)
	if err != nil {
		return "", err
	}

	return serverFlavorPlacementResourceClass(flavors, flavorID)
}

func serverFlavorPlacementResourceClass(openstackFlavors []flavors.Flavor, flavorID string) (string, error) {
	index := slices.IndexFunc(openstackFlavors, func(flavor flavors.Flavor) bool {
		return flavor.ID == flavorID
	})
	if index < 0 {
		return "", fmt.Errorf("%w: flavor %q not found", coreerrors.ErrConsistency, flavorID)
	}

	return flavorPlacementResourceClass(openstackFlavors[index])
}

func flavorPlacementResourceClass(flavor flavors.Flavor) (string, error) {
	classes := []string{}

	for key, value := range flavor.ExtraSpecs {
		resourceClass, ok, err := placementResourceClassFromExtraSpec(key, value)
		if err != nil {
			return "", fmt.Errorf("%w: flavor %q placement resource class: %w", coreerrors.ErrConsistency, flavor.ID, err)
		}

		if !ok || slices.Contains(classes, resourceClass) {
			continue
		}

		classes = append(classes, resourceClass)
	}

	switch len(classes) {
	case 1:
		return classes[0], nil
	case 0:
		return "", fmt.Errorf("%w: flavor %q has no positive custom placement resource class", coreerrors.ErrConsistency, flavor.ID)
	default:
		return "", fmt.Errorf("%w: flavor %q has multiple positive custom placement resource classes: %s", coreerrors.ErrConsistency, flavor.ID, strings.Join(classes, ", "))
	}
}

func placementResourceClassFromExtraSpec(key, value string) (string, bool, error) {
	if !strings.HasPrefix(strings.ToLower(key), placementResourceExtraSpecPrefix) {
		return "", false, nil
	}

	amount, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return "", false, fmt.Errorf("%q amount %q: %w", key, value, err)
	}

	if amount <= 0 {
		return "", false, nil
	}

	resourceClass := strings.ToUpper(strings.TrimSpace(key[len(placementResourceExtraSpecPrefix):]))
	if !strings.HasPrefix(resourceClass, customPlacementResourcePrefix) {
		return "", false, nil
	}

	return resourceClass, true, nil
}

func placementPreflightConfig(region *unikornv1.Region) *unikornv1.PlacementPreflightSpec {
	if region == nil || region.Spec.Openstack == nil || region.Spec.Openstack.Compute == nil {
		return nil
	}

	return region.Spec.Openstack.Compute.PlacementPreflight
}

func (p *Provider) serverCreatePlacementPreflight(identity *unikornv1.Identity, compute FlavorInterface) serverCreatePreflight {
	preflight := serverCreatePlacementPreflight{
		config: func() *unikornv1.PlacementPreflightSpec {
			region, _ := p.openstack.regionSnapshot()

			return placementPreflightConfig(region)
		},
		flavorClient: compute,
		placementClientFactory: func(ctx context.Context, server *unikornv1.Server) (PlacementInterface, error) {
			return p.placementForServerCreate(ctx, identity, server)
		},
	}

	return preflight.check
}

func (p *Provider) placementForServerCreate(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) (PlacementInterface, error) {
	provider, err := p.providerForServerCreate(ctx, identity, server)
	if err != nil {
		return nil, err
	}

	return NewPlacementClient(ctx, provider)
}
