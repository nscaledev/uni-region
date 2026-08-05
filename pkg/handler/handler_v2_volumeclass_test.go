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

//nolint:testpackage
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/openapi"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	mockprovider "github.com/unikorn-cloud/region/pkg/providers/types/mock"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// errVolumeClassProvider is returned by provider mocks to exercise error handling.
var errVolumeClassProvider = errors.New("volume class provider failed")

const (
	volumeClassTestNamespace       = "volume-class-test"
	volumeClassReadEndpoint        = "region:volumeclasses:v2"
	volumeClassTestOrganizationID  = "10101010-1010-4010-a010-101010101010"
	volumeClassOtherOrganizationID = "20202020-2020-4020-a020-202020202020"
)

func volumeClassReadContext(ctx context.Context) context.Context {
	return newOrganisationACLBuilder(volumeClassTestOrganizationID).
		addEndpoint(volumeClassReadEndpoint, identityapi.Read).
		buildContext(ctx)
}

type volumeClassV2TestFixture struct {
	t         *testing.T
	ctrl      *gomock.Controller
	providers *mockproviders.MockProviders
	handler   *Handler
}

func newVolumeClassV2TestFixture(t *testing.T, regions ...*regionv1.Region) *volumeClassV2TestFixture {
	t.Helper()

	objects := make([]client.Object, len(regions))
	for i := range regions {
		objects[i] = regions[i]
	}

	ctrl := gomock.NewController(t)
	providers := mockproviders.NewMockProviders(ctrl)

	return &volumeClassV2TestFixture{
		t:         t,
		ctrl:      ctrl,
		providers: providers,
		handler: &Handler{
			ClientArgs: common.ClientArgs{
				Client:    fakeClientWithSchema(t, objects...),
				Namespace: volumeClassTestNamespace,
				Providers: providers,
			},
		},
	}
}

func newVolumeClassTestSecurity(organizationIDs ...string) *regionv1.RegionSecuritySpec {
	organizations := make([]regionv1.RegionSecurityOrganizationSpec, len(organizationIDs))
	for i := range organizationIDs {
		organizations[i].ID = organizationIDs[i]
	}

	return &regionv1.RegionSecuritySpec{
		Organizations: organizations,
	}
}

func newVolumeClassTestRegion(regionID string, security *regionv1.RegionSecuritySpec) *regionv1.Region {
	return &regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      regionID,
			Namespace: volumeClassTestNamespace,
		},
		Spec: regionv1.RegionSpec{
			Security: security,
		},
	}
}

func (f *volumeClassV2TestFixture) expectVolumeClasses(regionID string, result types.VolumeClassList, err error) {
	f.t.Helper()

	provider := mockprovider.NewMockCommonProvider(f.ctrl)
	provider.EXPECT().VolumeClasses(gomock.Any()).Return(result, err)
	f.providers.EXPECT().LookupCommon(regionID).Return(provider, nil)
}

func (f *volumeClassV2TestFixture) expectProviderLookupError(regionID string, err error) {
	f.t.Helper()

	f.providers.EXPECT().LookupCommon(regionID).Return(nil, err)
}

func (f *volumeClassV2TestFixture) get(ctx context.Context, params openapi.GetApiV2VolumeclassesParams) *httptest.ResponseRecorder {
	f.t.Helper()

	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v2/volumeclasses", nil)
	response := httptest.NewRecorder()

	f.handler.GetApiV2Volumeclasses(response, request, params)

	return response
}

func requireVolumeClassListResponse(t *testing.T, response *httptest.ResponseRecorder) openapi.VolumeClassListV2Response {
	t.Helper()

	require.Equal(t, http.StatusOK, response.Code)

	var result openapi.VolumeClassListV2Response

	requireDeserialiseBody(t, response.Body, &result)
	require.NotNil(t, result)

	return result
}

func requireVolumeClassErrorResponse(t *testing.T, response *httptest.ResponseRecorder) coreapi.Error {
	t.Helper()

	require.Equal(t, http.StatusInternalServerError, response.Code)

	var result coreapi.Error

	requireDeserialiseBody(t, response.Body, &result)

	return result
}

func TestVolumeClassV2ReturnsEmptyListWithoutRegions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		context func(context.Context) context.Context
	}{
		{
			name:    "with endpoint permission",
			context: volumeClassReadContext,
		},
		{
			name: "without endpoint permission",
			context: newOrganisationACLBuilder(volumeClassTestOrganizationID).
				buildContext,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newVolumeClassV2TestFixture(t)
			response := fixture.get(test.context(t.Context()), openapi.GetApiV2VolumeclassesParams{})
			result := requireVolumeClassListResponse(t, response)

			require.Empty(t, result)
		})
	}
}

func TestVolumeClassV2ReturnsServerErrorForProviderFailures(t *testing.T) {
	t.Parallel()

	const regionID = "88888888-8888-4888-a888-888888888888"

	tests := []struct {
		name  string
		setup func(*volumeClassV2TestFixture)
	}{
		{
			name: "provider lookup fails",
			setup: func(fixture *volumeClassV2TestFixture) {
				fixture.expectProviderLookupError(regionID, errVolumeClassProvider)
			},
		},
		{
			name: "provider inventory fails",
			setup: func(fixture *volumeClassV2TestFixture) {
				fixture.expectVolumeClasses(regionID, nil, errVolumeClassProvider)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newVolumeClassV2TestFixture(t, newVolumeClassTestRegion(regionID, nil))
			test.setup(fixture)

			response := fixture.get(volumeClassReadContext(t.Context()), openapi.GetApiV2VolumeclassesParams{})
			result := requireVolumeClassErrorResponse(t, response)

			require.Equal(t, coreapi.ServerError, result.Error)
		})
	}
}

func TestVolumeClassV2MapsProviderInventory(t *testing.T) {
	t.Parallel()

	const (
		regionID      = "11111111-1111-4111-a111-111111111111"
		volumeClassID = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
	)

	maxIOPS := 25000
	maxThroughput := 500
	minimumSizeGiB := int64(10)
	maximumSizeGiB := int64(2048)
	fixture := newVolumeClassV2TestFixture(t, newVolumeClassTestRegion(regionID, nil))
	fixture.expectVolumeClasses(regionID, types.VolumeClassList{
		{
			ID:             volumeClassID,
			Name:           "fast-nvme",
			Description:    "Latency-sensitive encrypted block storage",
			MinimumSizeGiB: &minimumSizeGiB,
			MaximumSizeGiB: &maximumSizeGiB,
			Media:          types.VolumeClassMediaNVMe,
			Performance: &types.VolumeClassPerformance{
				MaxIOPS:       &maxIOPS,
				MaxThroughput: &maxThroughput,
			},
			Encrypted: true,
		},
	}, nil)

	response := fixture.get(volumeClassReadContext(t.Context()), openapi.GetApiV2VolumeclassesParams{})
	result := requireVolumeClassListResponse(t, response)

	require.Len(t, result, 1)
	require.Equal(t, volumeClassID, result[0].Metadata.Id)
	require.Equal(t, "fast-nvme", result[0].Metadata.Name)
	require.NotNil(t, result[0].Metadata.Description)
	require.Equal(t, "Latency-sensitive encrypted block storage", *result[0].Metadata.Description)
	require.Equal(t, regionID, result[0].Spec.RegionId.String())
	require.Equal(t, &minimumSizeGiB, result[0].Spec.MinimumSizeGiB)
	require.Equal(t, &maximumSizeGiB, result[0].Spec.MaximumSizeGiB)
	require.NotNil(t, result[0].Spec.Media)
	require.Equal(t, openapi.VolumeClassV2MediaNvme, *result[0].Spec.Media)
	require.NotNil(t, result[0].Spec.Performance)
	require.Equal(t, &maxIOPS, result[0].Spec.Performance.MaxIOPS)
	require.Equal(t, &maxThroughput, result[0].Spec.Performance.MaxThroughputMiBps)
	require.True(t, result[0].Spec.Encrypted)
}

func TestVolumeClassV2OmitsAbsentCapacityBounds(t *testing.T) {
	t.Parallel()

	const (
		regionID      = "11111111-1111-4111-a111-111111111111"
		volumeClassID = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
	)

	fixture := newVolumeClassV2TestFixture(t, newVolumeClassTestRegion(regionID, nil))
	fixture.expectVolumeClasses(regionID, types.VolumeClassList{
		{
			ID:   volumeClassID,
			Name: "unbounded",
		},
	}, nil)

	response := fixture.get(volumeClassReadContext(t.Context()), openapi.GetApiV2VolumeclassesParams{})
	require.Equal(t, http.StatusOK, response.Code)

	var result []struct {
		Spec map[string]json.RawMessage `json:"spec"`
	}

	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
	require.Len(t, result, 1)
	require.NotContains(t, result[0].Spec, "minimumSizeGiB")
	require.NotContains(t, result[0].Spec, "maximumSizeGiB")
}

func TestVolumeClassV2ReturnsEmptyListForFilteredRegions(t *testing.T) {
	t.Parallel()

	const (
		inaccessibleRegionID = "22222222-2222-4222-a222-222222222222"
		missingRegionID      = "23232323-2323-4232-a323-232323232323"
		globalPermissionID   = "30303030-3030-4030-a030-303030303030"
	)

	globalVolumeClassReadContext := func(ctx context.Context) context.Context {
		return rbac.NewContext(ctx, &identityapi.Acl{
			Global: &identityapi.AclEndpoints{
				{
					Name:       volumeClassReadEndpoint,
					Operations: identityapi.AclOperations{identityapi.Read},
				},
			},
		})
	}

	tests := []struct {
		name     string
		context  func(context.Context) context.Context
		regionID string
		regions  []*regionv1.Region
	}{
		{
			name:     "explicit Region is inaccessible",
			context:  volumeClassReadContext,
			regionID: inaccessibleRegionID,
			regions: []*regionv1.Region{
				newVolumeClassTestRegion(
					inaccessibleRegionID,
					newVolumeClassTestSecurity(volumeClassOtherOrganizationID),
				),
			},
		},
		{
			name:     "explicit Region does not exist",
			context:  volumeClassReadContext,
			regionID: missingRegionID,
		},
		{
			name:     "global endpoint permission does not bypass Region visibility",
			context:  globalVolumeClassReadContext,
			regionID: globalPermissionID,
			regions: []*regionv1.Region{
				newVolumeClassTestRegion(
					globalPermissionID,
					newVolumeClassTestSecurity(volumeClassOtherOrganizationID),
				),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newVolumeClassV2TestFixture(t, test.regions...)
			params := openapi.GetApiV2VolumeclassesParams{
				RegionID: ptr.To(openapi.RegionIDQueryParameter{test.regionID}),
			}
			response := fixture.get(test.context(t.Context()), params)
			result := requireVolumeClassListResponse(t, response)

			require.Empty(t, result)
		})
	}
}

func TestVolumeClassV2DiscoversVisibleRegionWithGlobalPermissionAndNoOrganizations(t *testing.T) {
	t.Parallel()

	const (
		regionID      = "30303030-3030-4030-a030-303030303030"
		volumeClassID = "31313131-3131-4131-a131-313131313131"
	)

	fixture := newVolumeClassV2TestFixture(
		t,
		newVolumeClassTestRegion(
			regionID,
			newVolumeClassTestSecurity(volumeClassOtherOrganizationID),
		),
	)
	fixture.expectVolumeClasses(regionID, types.VolumeClassList{
		{ID: volumeClassID, Name: "globally-visible-class"},
	}, nil)

	ctx := rbac.NewContext(t.Context(), &identityapi.Acl{
		Global: &identityapi.AclEndpoints{
			{Name: "region:regions", Operations: identityapi.AclOperations{identityapi.Read}},
			{Name: volumeClassReadEndpoint, Operations: identityapi.AclOperations{identityapi.Read}},
		},
	})
	params := openapi.GetApiV2VolumeclassesParams{
		RegionID: ptr.To(openapi.RegionIDQueryParameter{regionID}),
	}

	response := fixture.get(ctx, params)
	result := requireVolumeClassListResponse(t, response)

	require.Len(t, result, 1)
	require.Equal(t, volumeClassID, result[0].Metadata.Id)
	require.Equal(t, regionID, result[0].Spec.RegionId.String())
}

func TestVolumeClassV2ReturnsEmptyProviderInventory(t *testing.T) {
	t.Parallel()

	const regionID = "25252525-2525-4252-a525-252525252525"

	fixture := newVolumeClassV2TestFixture(t, newVolumeClassTestRegion(regionID, nil))
	fixture.expectVolumeClasses(regionID, nil, nil)

	response := fixture.get(volumeClassReadContext(t.Context()), openapi.GetApiV2VolumeclassesParams{})
	result := requireVolumeClassListResponse(t, response)

	require.Empty(t, result)
}

func TestVolumeClassV2SkipsProviderDiscoveryWithoutEndpointPermission(t *testing.T) {
	t.Parallel()

	const (
		organizationID = "24242424-2424-4242-a424-242424242424"
		regionID       = "25252525-2525-4252-a525-252525252525"
	)

	tests := []struct {
		name     string
		params   openapi.GetApiV2VolumeclassesParams
		security *regionv1.RegionSecuritySpec
	}{
		{
			name: "unrestricted Region",
		},
		{
			name: "Region restricted to caller organization",
			params: openapi.GetApiV2VolumeclassesParams{
				RegionID: ptr.To(openapi.RegionIDQueryParameter{regionID}),
			},
			security: newVolumeClassTestSecurity(organizationID),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newVolumeClassV2TestFixture(t, newVolumeClassTestRegion(regionID, test.security))
			fixture.providers.EXPECT().LookupCommon(regionID).Times(0)

			ctx := newOrganisationACLBuilder(organizationID).buildContext(t.Context())
			response := fixture.get(ctx, test.params)
			result := requireVolumeClassListResponse(t, response)

			require.Empty(t, result)
		})
	}
}

func TestVolumeClassV2FiltersInaccessibleRegions(t *testing.T) {
	t.Parallel()

	const (
		accessibleRegionID = "33333333-3333-4333-a333-333333333333"
		restrictedRegionID = "44444444-4444-4444-a444-444444444444"
		volumeClassID      = "bbbbbbbb-bbbb-4bbb-abbb-bbbbbbbbbbbb"
	)

	fixture := newVolumeClassV2TestFixture(
		t,
		newVolumeClassTestRegion(accessibleRegionID, nil),
		newVolumeClassTestRegion(
			restrictedRegionID,
			newVolumeClassTestSecurity(volumeClassOtherOrganizationID),
		),
	)
	fixture.expectVolumeClasses(accessibleRegionID, types.VolumeClassList{
		{
			ID:   volumeClassID,
			Name: "visible-class",
		},
	}, nil)

	response := fixture.get(volumeClassReadContext(t.Context()), openapi.GetApiV2VolumeclassesParams{})
	result := requireVolumeClassListResponse(t, response)

	require.Len(t, result, 1)
	require.Equal(t, volumeClassID, result[0].Metadata.Id)
	require.Equal(t, accessibleRegionID, result[0].Spec.RegionId.String())
}

func TestVolumeClassV2FiltersAndDeduplicatesExplicitRegions(t *testing.T) {
	t.Parallel()

	const (
		unselectedRegion = "55555555-5555-4555-a555-555555555555"
		selectedRegion   = "66666666-6666-4666-a666-666666666666"
	)

	fixture := newVolumeClassV2TestFixture(
		t,
		newVolumeClassTestRegion(unselectedRegion, nil),
		newVolumeClassTestRegion(
			selectedRegion,
			newVolumeClassTestSecurity(volumeClassTestOrganizationID),
		),
	)
	fixture.expectVolumeClasses(selectedRegion, types.VolumeClassList{
		{ID: "cccccccc-cccc-4ccc-accc-cccccccccccc", Name: "selected-class"},
	}, nil)

	params := openapi.GetApiV2VolumeclassesParams{
		RegionID: ptr.To(openapi.RegionIDQueryParameter{
			"98989898-9898-4989-a989-989898989898",
			selectedRegion,
			selectedRegion,
		}),
	}

	response := fixture.get(volumeClassReadContext(t.Context()), params)
	result := requireVolumeClassListResponse(t, response)

	require.Len(t, result, 1)
	require.Equal(t, selectedRegion, result[0].Spec.RegionId.String())
}

func TestVolumeClassV2SortsProviderInventoryByNameThenID(t *testing.T) {
	t.Parallel()

	const regionID = "aaaaaaaa-1111-4111-a111-111111111111"

	fixture := newVolumeClassV2TestFixture(t, newVolumeClassTestRegion(regionID, nil))
	fixture.expectVolumeClasses(regionID, types.VolumeClassList{
		{ID: "dddddddd-dddd-4ddd-addd-dddddddddddd", Name: "zonal"},
		{ID: "ffffffff-ffff-4fff-afff-ffffffffffff", Name: "balanced"},
		{ID: "eeeeeeee-eeee-4eee-aeee-eeeeeeeeeeee", Name: "balanced"},
	}, nil)

	response := fixture.get(volumeClassReadContext(t.Context()), openapi.GetApiV2VolumeclassesParams{})
	result := requireVolumeClassListResponse(t, response)

	require.Len(t, result, 3)
	require.Equal(t, "eeeeeeee-eeee-4eee-aeee-eeeeeeeeeeee", result[0].Metadata.Id)
	require.Equal(t, "ffffffff-ffff-4fff-afff-ffffffffffff", result[1].Metadata.Id)
	require.Equal(t, "dddddddd-dddd-4ddd-addd-dddddddddddd", result[2].Metadata.Id)
}
