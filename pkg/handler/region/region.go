/*
Copyright 2024-2025 the Unikorn Authors.
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

package region

import (
	"cmp"
	"context"
	goerrors "errors"
	"fmt"
	"slices"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/conversion"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	kerrors "k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrResource is raised when a resource is in a bad state.
	ErrResource = goerrors.New("resource error")

	// ErrRegionNotFound is raised when a region doesn't exist.
	ErrRegionNotFound = goerrors.New("region doesn't exist")
)

type Client struct {
	common.ClientArgs
}

func NewClient(clientArgs common.ClientArgs) *Client {
	return &Client{
		ClientArgs: clientArgs,
	}
}

func FilterRegions(ctx context.Context, regions *unikornv1.RegionList) {
	regions.Items = slices.DeleteFunc(regions.Items, func(region unikornv1.Region) bool {
		// Regions without security constraints are free to use.
		if region.Spec.Security == nil || region.Spec.Security.Organizations == nil {
			return false
		}

		// Anyone with super cow powers can see everything (platform admin, services).
		if rbac.AllowGlobalScope(ctx, "region:regions", identityapi.Read) == nil {
			return false
		}

		// Thankfully, user roles cannot define globals so fall into this bucket.
		// Presently if the ACL contains an allowed organization, the region can
		// be seen.
		organizationIDs := rbac.OrganizationIDs(ctx)

		for _, organization := range region.Spec.Security.Organizations {
			if slices.Contains(organizationIDs, organization.ID) {
				return false
			}
		}

		return true
	})
}

func (c *Client) List(ctx context.Context) (openapi.Regions, error) {
	regions := &unikornv1.RegionList{}

	if err := c.Client.List(ctx, regions, &client.ListOptions{Namespace: c.Namespace}); err != nil {
		return nil, err
	}

	FilterRegions(ctx, regions)

	return convertList(regions), nil
}

func (c *Client) GetDetail(ctx context.Context, regionID string) (*openapi.RegionDetailRead, error) {
	result := &unikornv1.Region{}

	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: regionID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: unable to lookup region", err)
	}

	return c.convertDetail(ctx, result)
}

func (c *Client) ListFlavors(ctx context.Context, organizationID, regionID string) (openapi.Flavors, error) {
	provider, err := c.Providers.LookupCommon(ctx, regionID)
	if err != nil {
		return nil, providers.ProviderToServerError(err)
	}

	result, err := provider.Flavors(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to list flavors", err)
	}

	// Apply ordering guarantees, ascending order with GPUs taking precedence over
	// CPUs and memory.
	slices.SortStableFunc(result, func(a, b types.Flavor) int {
		if v := cmp.Compare(a.GPUCount(), b.GPUCount()); v != 0 {
			return v
		}

		if v := cmp.Compare(a.CPUs, b.CPUs); v != 0 {
			return v
		}

		return cmp.Compare(a.Memory.Value(), b.Memory.Value())
	})

	return conversion.ConvertFlavors(result), nil
}

func convertExternalNetwork(in types.ExternalNetwork) openapi.ExternalNetwork {
	out := openapi.ExternalNetwork{
		Id:   in.ID,
		Name: in.Name,
	}

	return out
}

func convertExternalNetworks(in types.ExternalNetworks) openapi.ExternalNetworks {
	out := make(openapi.ExternalNetworks, len(in))

	for i := range in {
		out[i] = convertExternalNetwork(in[i])
	}

	return out
}

func (c *Client) ListExternalNetworks(ctx context.Context, regionID string) (openapi.ExternalNetworks, error) {
	provider, err := c.Providers.LookupCloud(ctx, regionID)
	if err != nil {
		return nil, providers.ProviderToServerError(err)
	}

	result, err := provider.ListExternalNetworks(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to list external networks", err)
	}

	return convertExternalNetworks(result), nil
}
