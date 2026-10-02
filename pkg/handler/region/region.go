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
	"sigs.k8s.io/controller-runtime/pkg/log"
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

// checkAccess applies the region ACL to an already-fetched region object on
// behalf of the given organizations, which MUST be ones the caller acts for: the
// RBAC-checked request organization, or the caller's own organizations where no
// organization is in scope. It returns HTTPNotFound rather than HTTPForbidden to avoid leaking
// information about the existence of regions the caller cannot see.
func checkAccess(ctx context.Context, resource *unikornv1.Region, organizationIDs []string) error {
	// Regions without security constraints are free to use.
	if resource.Spec.Security == nil || resource.Spec.Security.Organizations == nil {
		return nil
	}

	// Anyone with super cow powers can access everything (platform admin, services).
	if rbac.AllowGlobalScope(ctx, "region:regions", identityapi.Read) == nil {
		return nil
	}

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

// checkRegionAccess fetches the region and applies checkAccess to it.
func (c *Client) checkRegionAccess(ctx context.Context, regionID regionids.RegionID, organizationIDs []string) (*unikornv1.Region, error) {
	resource, err := c.getRegion(ctx, regionID)
	if err != nil {
		return nil, err
	}

	if err := checkAccess(ctx, resource, organizationIDs); err != nil {
		return nil, err
	}

	return resource, nil
}

// CheckAccess fetches the region by ID and verifies the organization is allowed
// to use it. Returns HTTPNotFound for both missing and inaccessible regions
// to avoid confirming region existence to unauthorized callers.
func (c *Client) CheckAccess(ctx context.Context, organizationID identityids.OrganizationID, regionID regionids.RegionID) error {
	_, err := c.Get(ctx, organizationID, regionID)

	return err
}

// Get is CheckAccess for callers that also need the region's configuration.
func (c *Client) Get(ctx context.Context, organizationID identityids.OrganizationID, regionID regionids.RegionID) (*unikornv1.Region, error) {
	return c.checkRegionAccess(ctx, regionID, []string{organizationID.String()})
}

// CheckAccessAnyOrganization is CheckAccess for APIs with no organization in
// scope, allowing access via any organization the caller belongs to.
func (c *Client) CheckAccessAnyOrganization(ctx context.Context, regionID regionids.RegionID) error {
	_, err := c.checkRegionAccess(ctx, regionID, rbac.OrganizationIDs(ctx))

	return err
}

// AllowedOrganizations returns those of the organizations, which the caller MUST
// already be authorized for, that may use the region. Returns HTTPNotFound if
// the region is missing or none of them may use it.
func (c *Client) AllowedOrganizations(ctx context.Context, regionID regionids.RegionID, organizationIDs []identityids.OrganizationID) ([]identityids.OrganizationID, error) {
	resource, err := c.checkRegionAccess(ctx, regionID, types.OrganizationIDStrings(organizationIDs))
	if err != nil {
		return nil, err
	}

	return slices.DeleteFunc(slices.Clone(organizationIDs), func(organizationID identityids.OrganizationID) bool {
		return checkAccess(ctx, resource, []string{organizationID.String()}) != nil
	}), nil
}

func filterRegions(ctx context.Context, regions *unikornv1.RegionList, organizationIDs []string) {
	regions.Items = slices.DeleteFunc(regions.Items, func(region unikornv1.Region) bool {
		return checkAccess(ctx, &region, organizationIDs) != nil
	})
}

// listRegions returns Regions in the configured namespace that are visible to
// the given organizations.
func (c *Client) listRegions(ctx context.Context, organizationIDs []string) (*unikornv1.RegionList, error) {
	regions := &unikornv1.RegionList{}

	if err := c.Client.List(ctx, regions, &client.ListOptions{Namespace: c.Namespace}); err != nil {
		return nil, err
	}

	filterRegions(ctx, regions, organizationIDs)

	return regions, nil
}

func (c *Client) List(ctx context.Context, organizationID identityids.OrganizationID) (openapi.Regions, error) {
	regions, err := c.listRegions(ctx, []string{organizationID.String()})
	if err != nil {
		return nil, err
	}

	return convertList(regions), nil
}

func (c *Client) GetDetail(ctx context.Context, organizationID identityids.OrganizationID, regionID regionids.RegionID) (*openapi.RegionDetailRead, error) {
	result, err := c.Get(ctx, organizationID, regionID)
	if err != nil {
		return nil, err
	}

	return c.convertDetail(ctx, result)
}

func (c *Client) ListFlavors(ctx context.Context, organizationID identityids.OrganizationID, regionID regionids.RegionID) (openapi.Flavors, error) {
	if err := c.CheckAccess(ctx, organizationID, regionID); err != nil {
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

const volumeClassReadEndpoint = "region:volumeclasses:v2"

func hasVolumeClassReadAccess(ctx context.Context) bool {
	if rbac.AllowGlobalScope(ctx, volumeClassReadEndpoint, identityapi.Read) == nil {
		return true
	}

	for _, value := range rbac.OrganizationIDs(ctx) {
		organizationID, err := identityids.ParseOrganizationID(value)
		if err != nil {
			continue
		}

		if rbac.AllowOrganizationScopeID(ctx, volumeClassReadEndpoint, identityapi.Read, organizationID) == nil {
			return true
		}
	}

	return false
}

func (c *Client) listRegionVolumeClasses(ctx context.Context, regionID string) (types.VolumeClassList, error) {
	provider, err := c.Providers.LookupCommon(regionID)
	if err != nil {
		return nil, providers.ProviderToServerError(err)
	}

	volumeClasses, err := provider.VolumeClasses(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to list volume classes", err)
	}

	return volumeClasses, nil
}

func (c *Client) ListVolumeClasses(ctx context.Context, params openapi.GetApiV2VolumeclassesParams) (openapi.VolumeClassListV2Read, error) {
	regions, err := c.listRegions(ctx, rbac.OrganizationIDs(ctx))
	if err != nil {
		return nil, err
	}

	if params.RegionID != nil {
		// Filter regions based on the query parameter
		regions.Items = slices.DeleteFunc(regions.Items, func(region unikornv1.Region) bool {
			return !slices.Contains(*params.RegionID, region.Name)
		})
	}

	result := openapi.VolumeClassListV2Read{}

	for _, region := range regions.Items {
		if !hasVolumeClassReadAccess(ctx) {
			continue
		}

		volumeClasses, err := c.listRegionVolumeClasses(ctx, region.Name)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}

			if params.RegionID == nil {
				log.FromContext(ctx).Error(err, "volume class discovery failed, skipping region", "region", region.Name)

				continue
			}

			return nil, err
		}

		regionID, err := regionids.ParseRegionID(region.Name)
		if err != nil {
			continue
		}

		result = append(result, conversion.ConvertVolumeClasses(regionID, volumeClasses)...)
	}

	slices.SortStableFunc(result, func(a, b openapi.VolumeClassV2Read) int {
		return cmp.Or(
			cmp.Compare(a.Spec.RegionId.String(), b.Spec.RegionId.String()),
			cmp.Compare(a.Metadata.Name, b.Metadata.Name),
			cmp.Compare(a.Metadata.Id, b.Metadata.Id),
		)
	})

	return result, nil
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

func (c *Client) ListExternalNetworks(ctx context.Context, organizationID identityids.OrganizationID, regionID regionids.RegionID) (openapi.ExternalNetworks, error) {
	if err := c.CheckAccess(ctx, organizationID, regionID); err != nil {
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
