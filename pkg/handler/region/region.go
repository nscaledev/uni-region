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
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/conversion"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
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

const volumeClassReadEndpoint = "region:volumeclasses:v2"

type Client struct {
	common.ClientArgs
}

func NewClient(clientArgs common.ClientArgs) *Client {
	return &Client{
		ClientArgs: clientArgs,
	}
}

// checkAccess applies the region ACL to an already-fetched region object.
// It returns HTTPNotFound rather than HTTPForbidden to avoid leaking information
// about the existence of regions the caller cannot see.
func checkAccess(ctx context.Context, resource *unikornv1.Region) error {
	// Regions without security constraints are free to use.
	if resource.Spec.Security == nil || resource.Spec.Security.Organizations == nil {
		return nil
	}

	// Anyone with super cow powers can access everything (platform admin, services).
	if rbac.AllowGlobalScope(ctx, "region:regions", identityapi.Read) == nil {
		return nil
	}

	// Under impersonation the ACL is scoped to the user's organizations, so
	// OrganizationIDs returns only what the user can see.
	organizationIDs := rbac.OrganizationIDs(ctx)

	for _, organization := range resource.Spec.Security.Organizations {
		if slices.Contains(organizationIDs, organization.ID) {
			return nil
		}
	}

	return errors.HTTPNotFound()
}

func (c *Client) getRegion(ctx context.Context, regionID regionids.RegionID) (*unikornv1.Region, error) {
	resource := &unikornv1.Region{}

	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: regionID.String()}, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: unable to lookup region", err)
	}

	return resource, nil
}

// CheckAccess fetches the region by ID and verifies the caller's organization is
// allowed to use it.  Returns HTTPNotFound for both missing and inaccessible regions
// to avoid confirming region existence to unauthorized callers.
func (c *Client) CheckAccess(ctx context.Context, regionID regionids.RegionID) error {
	resource, err := c.getRegion(ctx, regionID)
	if err != nil {
		return err
	}

	return checkAccess(ctx, resource)
}

func FilterRegions(ctx context.Context, regions *unikornv1.RegionList) {
	regions.Items = slices.DeleteFunc(regions.Items, func(region unikornv1.Region) bool {
		return checkAccess(ctx, &region) != nil
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

func (c *Client) GetDetail(ctx context.Context, regionID regionids.RegionID) (*openapi.RegionDetailRead, error) {
	result := &unikornv1.Region{}

	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: regionID.String()}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: unable to lookup region", err)
	}

	if err := checkAccess(ctx, result); err != nil {
		return nil, err
	}

	return c.convertDetail(ctx, result)
}

func (c *Client) ListFlavors(ctx context.Context, organizationID identityids.OrganizationID, regionID regionids.RegionID) (openapi.Flavors, error) {
	if err := c.CheckAccess(ctx, regionID); err != nil {
		return nil, err
	}

	provider, err := c.Providers.LookupCommon(regionID.String())
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

func (c *Client) ListVolumeClasses(ctx context.Context, params openapi.GetApiV2VolumeclassesParams) (openapi.VolumeClassListV2Read, error) {
	regionIDs, err := c.volumeClassRegionIDs(ctx, params.RegionID)
	if err != nil {
		return nil, err
	}

	result := openapi.VolumeClassListV2Read{}

	for _, regionID := range regionIDs {
		provider, err := c.Providers.LookupCommon(regionID.String())
		if err != nil {
			return nil, providers.ProviderToServerError(err)
		}

		volumeClasses, err := provider.VolumeClasses(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to list volume classes", err)
		}

		result = append(result, conversion.ConvertVolumeClasses(regionID, volumeClasses)...)
	}

	slices.SortStableFunc(result, func(a, b openapi.VolumeClassV2Read) int {
		if value := cmp.Compare(a.Spec.RegionId.String(), b.Spec.RegionId.String()); value != 0 {
			return value
		}

		if value := cmp.Compare(a.Metadata.Name, b.Metadata.Name); value != 0 {
			return value
		}

		return cmp.Compare(a.Metadata.Id, b.Metadata.Id)
	})

	return result, nil
}

func checkVolumeClassAccess(ctx context.Context, resource *unikornv1.Region) error {
	if err := checkAccess(ctx, resource); err != nil {
		return err
	}

	if rbac.AllowGlobalScope(ctx, volumeClassReadEndpoint, identityapi.Read) == nil {
		return nil
	}

	organizationIDs := rbac.OrganizationIDs(ctx)
	if resource.Spec.Security != nil && resource.Spec.Security.Organizations != nil {
		organizationIDs = make([]string, len(resource.Spec.Security.Organizations))

		for i := range resource.Spec.Security.Organizations {
			organizationIDs[i] = resource.Spec.Security.Organizations[i].ID
		}
	}

	for _, value := range organizationIDs {
		organizationID, err := identityids.ParseOrganizationID(value)
		if err != nil {
			continue
		}

		if rbac.AllowOrganizationScopeID(ctx, volumeClassReadEndpoint, identityapi.Read, organizationID) == nil {
			return nil
		}
	}

	return errors.HTTPNotFound()
}

func (c *Client) checkVolumeClassAccessForRegion(ctx context.Context, regionID regionids.RegionID) error {
	resource, err := c.getRegion(ctx, regionID)
	if err != nil {
		return err
	}

	return checkVolumeClassAccess(ctx, resource)
}

func (c *Client) volumeClassRegionIDs(ctx context.Context, query *openapi.RegionIDQueryParameter) ([]regionids.RegionID, error) {
	if query != nil {
		result := make([]regionids.RegionID, 0, len(*query))
		seen := map[regionids.RegionID]struct{}{}

		for _, value := range *query {
			regionID, err := regionids.ParseRegionID(value)
			if err != nil {
				return nil, errors.OAuth2InvalidRequest("invalid region ID").WithError(err)
			}

			if _, ok := seen[regionID]; ok {
				continue
			}

			if err := c.checkVolumeClassAccessForRegion(ctx, regionID); err != nil {
				return nil, err
			}

			seen[regionID] = struct{}{}

			result = append(result, regionID)
		}

		sortRegionIDs(result)

		return result, nil
	}

	regions := &unikornv1.RegionList{}

	if err := c.Client.List(ctx, regions, &client.ListOptions{Namespace: c.Namespace}); err != nil {
		return nil, fmt.Errorf("%w: unable to list regions", err)
	}

	regions.Items = slices.DeleteFunc(regions.Items, func(resource unikornv1.Region) bool {
		return checkVolumeClassAccess(ctx, &resource) != nil
	})

	result := make([]regionids.RegionID, len(regions.Items))

	for i := range regions.Items {
		regionID, err := regionids.ParseRegionID(regions.Items[i].Name)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid region ID", err)
		}

		result[i] = regionID
	}

	sortRegionIDs(result)

	return result, nil
}

func sortRegionIDs(regionIDs []regionids.RegionID) {
	slices.SortFunc(regionIDs, func(a, b regionids.RegionID) int {
		return cmp.Compare(a.String(), b.String())
	})
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

func (c *Client) ListExternalNetworks(ctx context.Context, regionID regionids.RegionID) (openapi.ExternalNetworks, error) {
	if err := c.CheckAccess(ctx, regionID); err != nil {
		return nil, err
	}

	provider, err := c.Providers.LookupCloud(regionID.String())
	if err != nil {
		return nil, providers.ProviderToServerError(err)
	}

	result, err := provider.ListExternalNetworks(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to list external networks", err)
	}

	return convertExternalNetworks(result), nil
}
