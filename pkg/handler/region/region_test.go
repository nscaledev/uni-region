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

package region_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/region"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	globalRegionName   = "earth"
	privateRegionName1 = "restricted"
	privateRegionName2 = "super-secret"
	privateRegionName3 = "really-secret"

	organizationID1 = "foo"
	organizationID2 = "bar"
	organizationID3 = "baz"
	organizationID4 = "none"
)

func regionsFixture() *regionv1.RegionList {
	return &regionv1.RegionList{
		Items: []regionv1.Region{
			// I am a global region.
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: globalRegionName,
				},
			},
			// I am limited to a few organizations.
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: privateRegionName1,
				},
				Spec: regionv1.RegionSpec{
					Security: &regionv1.RegionSecuritySpec{
						Organizations: []regionv1.RegionSecurityOrganizationSpec{
							{
								ID: organizationID1,
							},
							{
								ID: organizationID2,
							},
						},
					},
				},
			},
			// I am limited to a single organization.
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: privateRegionName2,
				},
				Spec: regionv1.RegionSpec{
					Security: &regionv1.RegionSecuritySpec{
						Organizations: []regionv1.RegionSecurityOrganizationSpec{
							{
								ID: organizationID2,
							},
						},
					},
				},
			},
			// I am limited to a different single organization.
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: privateRegionName3,
				},
				Spec: regionv1.RegionSpec{
					Security: &regionv1.RegionSecuritySpec{
						Organizations: []regionv1.RegionSecurityOrganizationSpec{
							{
								ID: organizationID3,
							},
						},
					},
				},
			},
		},
	}
}

func aclFixture(t *testing.T, global bool, organizationIDs ...string) context.Context {
	t.Helper()

	var acl identityapi.Acl

	if global {
		acl.Global = &identityapi.AclEndpoints{
			{
				Name: "region:regions",
				Operations: identityapi.AclOperations{
					identityapi.Read,
				},
			},
		}
	}

	if len(organizationIDs) > 0 {
		organizations := make(identityapi.AclOrganizationList, len(organizationIDs))

		acl.Organizations = &organizations

		for i, id := range organizationIDs {
			organizations[i].Id = id
		}
	}

	return rbac.NewContext(t.Context(), &acl)
}

// TestRegionFilteringGlobal tests users with global region read can see everything.
func TestRegionFilteringGlobal(t *testing.T) {
	t.Parallel()

	ctx := aclFixture(t, true)
	regions := regionsFixture()

	region.FilterRegions(ctx, regions)
	require.Len(t, regions.Items, 4)
}

// TestRegionFilteringSinglePrivate tests users can see a single private region and
// all public ones.
func TestRegionFilteringSinglePrivate(t *testing.T) {
	t.Parallel()

	ctx := aclFixture(t, false, organizationID1)
	regions := regionsFixture()

	region.FilterRegions(ctx, regions)
	require.Len(t, regions.Items, 2)
	require.Equal(t, globalRegionName, regions.Items[0].Name)
	require.Equal(t, privateRegionName1, regions.Items[1].Name)
}

// TestRegionFilteringMultiplePrivate tests users can see multiple private regions
// and all public ones.
func TestRegionFilteringMultiplePrivate(t *testing.T) {
	t.Parallel()

	ctx := aclFixture(t, false, organizationID2)
	regions := regionsFixture()

	region.FilterRegions(ctx, regions)
	require.Len(t, regions.Items, 3)
	require.Equal(t, globalRegionName, regions.Items[0].Name)
	require.Equal(t, privateRegionName1, regions.Items[1].Name)
	require.Equal(t, privateRegionName2, regions.Items[2].Name)
}

// TestRegionFilteringMultiplePrivateMultipleOrganizations can see multiple private
// regions beloning to multiple organizations when they have access to those organizations
// and all public ones.
func TestRegionFilteringMultiplePrivateMultipleOrganizations(t *testing.T) {
	t.Parallel()

	ctx := aclFixture(t, false, organizationID1, organizationID3)
	regions := regionsFixture()

	region.FilterRegions(ctx, regions)
	require.Len(t, regions.Items, 3)
	require.Equal(t, globalRegionName, regions.Items[0].Name)
	require.Equal(t, privateRegionName1, regions.Items[1].Name)
	require.Equal(t, privateRegionName3, regions.Items[2].Name)
}

// TestRegionFilteringNoPrivate tests users with no private regions cannot see any
// and just public ones.
func TestRegionFilteringNoPrivate(t *testing.T) {
	t.Parallel()

	ctx := aclFixture(t, false, organizationID4)
	regions := regionsFixture()

	region.FilterRegions(ctx, regions)
	require.Len(t, regions.Items, 1)
	require.Equal(t, globalRegionName, regions.Items[0].Name)
}
