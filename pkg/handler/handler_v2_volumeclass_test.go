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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/openapi"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	mockprovider "github.com/unikorn-cloud/region/pkg/providers/types/mock"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// errVolumeClassProvider is returned by provider mocks to exercise error handling.
var errVolumeClassProvider = errors.New("volume class provider failed")

func TestVolumeClassV2ReturnsEmptyListWhenNoRegionsExist(t *testing.T) {
	t.Parallel()

	const namespace = "volume-class-test"

	ctrl := gomock.NewController(t)
	providerSet := mockproviders.NewMockProviders(ctrl)
	handler := &Handler{
		ClientArgs: common.ClientArgs{
			Client:    fakeClientWithSchema(t),
			Namespace: namespace,
			Providers: providerSet,
		},
	}

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v2/volumeclasses", nil)
	response := httptest.NewRecorder()

	handler.GetApiV2Volumeclasses(response, request, openapi.GetApiV2VolumeclassesParams{})

	require.Equal(t, http.StatusOK, response.Code)

	var result openapi.VolumeClassListV2Response

	requireDeserialiseBody(t, response.Body, &result)
	require.NotNil(t, result)
	require.Empty(t, result)
}

func TestVolumeClassV2ReturnsServerErrorWhenProviderInventoryFails(t *testing.T) {
	t.Parallel()

	const (
		namespace = "volume-class-test"
		regionID  = "88888888-8888-4888-a888-888888888888"
	)

	ctrl := gomock.NewController(t)
	provider := mockprovider.NewMockCommonProvider(ctrl)
	provider.EXPECT().VolumeClasses(gomock.Any()).Return(nil, errVolumeClassProvider)

	providerSet := mockproviders.NewMockProviders(ctrl)
	providerSet.EXPECT().LookupCommon(regionID).Return(provider, nil)

	region := &regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      regionID,
			Namespace: namespace,
		},
	}
	handler := &Handler{
		ClientArgs: common.ClientArgs{
			Client:    fakeClientWithSchema(t, region),
			Namespace: namespace,
			Providers: providerSet,
		},
	}

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v2/volumeclasses", nil)
	response := httptest.NewRecorder()

	handler.GetApiV2Volumeclasses(response, request, openapi.GetApiV2VolumeclassesParams{})

	require.Equal(t, http.StatusInternalServerError, response.Code)

	var result coreapi.Error

	requireDeserialiseBody(t, response.Body, &result)
	require.Equal(t, coreapi.ServerError, result.Error)
}

func TestVolumeClassV2ReturnsServerErrorWhenProviderLookupFails(t *testing.T) {
	t.Parallel()

	const (
		namespace = "volume-class-test"
		regionID  = "99999999-9999-4999-a999-999999999999"
	)

	ctrl := gomock.NewController(t)
	providerSet := mockproviders.NewMockProviders(ctrl)
	providerSet.EXPECT().LookupCommon(regionID).Return(nil, errVolumeClassProvider)

	region := &regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      regionID,
			Namespace: namespace,
		},
	}
	handler := &Handler{
		ClientArgs: common.ClientArgs{
			Client:    fakeClientWithSchema(t, region),
			Namespace: namespace,
			Providers: providerSet,
		},
	}

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v2/volumeclasses", nil)
	response := httptest.NewRecorder()

	handler.GetApiV2Volumeclasses(response, request, openapi.GetApiV2VolumeclassesParams{})

	require.Equal(t, http.StatusInternalServerError, response.Code)

	var result coreapi.Error

	requireDeserialiseBody(t, response.Body, &result)
	require.Equal(t, coreapi.ServerError, result.Error)
}

func TestVolumeClassV2MapsProviderInventory(t *testing.T) {
	t.Parallel()

	const (
		namespace     = "volume-class-test"
		regionID      = "11111111-1111-4111-a111-111111111111"
		volumeClassID = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
	)

	maxIOPS := 25000
	maxThroughput := 500
	ctrl := gomock.NewController(t)
	provider := mockprovider.NewMockCommonProvider(ctrl)
	provider.EXPECT().VolumeClasses(gomock.Any()).Return(types.VolumeClassList{
		{
			ID:          volumeClassID,
			Name:        "fast-nvme",
			Description: "Latency-sensitive encrypted block storage",
			Media:       types.VolumeClassMediaNVMe,
			Performance: &types.VolumeClassPerformance{
				MaxIOPS:       &maxIOPS,
				MaxThroughput: &maxThroughput,
			},
			Encrypted: true,
		},
	}, nil)

	providerSet := mockproviders.NewMockProviders(ctrl)
	providerSet.EXPECT().LookupCommon(regionID).Return(provider, nil)

	region := &regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      regionID,
			Namespace: namespace,
		},
	}
	handler := &Handler{
		ClientArgs: common.ClientArgs{
			Client:    fakeClientWithSchema(t, region),
			Namespace: namespace,
			Providers: providerSet,
		},
	}

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v2/volumeclasses", nil)
	response := httptest.NewRecorder()

	handler.GetApiV2Volumeclasses(response, request, openapi.GetApiV2VolumeclassesParams{})

	require.Equal(t, http.StatusOK, response.Code)

	var result openapi.VolumeClassListV2Response

	requireDeserialiseBody(t, response.Body, &result)
	require.Len(t, result, 1)
	require.Equal(t, volumeClassID, result[0].Metadata.Id)
	require.Equal(t, "fast-nvme", result[0].Metadata.Name)
	require.Equal(t, time.Unix(0, 0).UTC(), result[0].Metadata.CreationTime)
	require.NotNil(t, result[0].Metadata.Description)
	require.Equal(t, "Latency-sensitive encrypted block storage", *result[0].Metadata.Description)
	require.Equal(t, regionID, result[0].Spec.RegionId.String())
	require.NotNil(t, result[0].Spec.Media)
	require.Equal(t, openapi.VolumeClassV2MediaNvme, *result[0].Spec.Media)
	require.NotNil(t, result[0].Spec.Performance)
	require.Equal(t, &maxIOPS, result[0].Spec.Performance.MaxIOPS)
	require.Equal(t, &maxThroughput, result[0].Spec.Performance.MaxThroughputMiBps)
	require.True(t, result[0].Spec.Encrypted)
}

func TestVolumeClassV2ValidatesExplicitRegionAccess(t *testing.T) {
	t.Parallel()

	const (
		namespace = "volume-class-test"
		regionID  = "22222222-2222-4222-a222-222222222222"
	)

	ctrl := gomock.NewController(t)
	providerSet := mockproviders.NewMockProviders(ctrl)
	restrictedRegion := &regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      regionID,
			Namespace: namespace,
		},
		Spec: regionv1.RegionSpec{
			Security: &regionv1.RegionSecuritySpec{
				Organizations: []regionv1.RegionSecurityOrganizationSpec{
					{ID: "allowed-organization"},
				},
			},
		},
	}
	handler := &Handler{
		ClientArgs: common.ClientArgs{
			Client:    fakeClientWithSchema(t, restrictedRegion),
			Namespace: namespace,
			Providers: providerSet,
		},
	}

	ctx := newOrganisationACLBuilder("different-organization").buildContext(t.Context())
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v2/volumeclasses", nil)
	response := httptest.NewRecorder()
	params := openapi.GetApiV2VolumeclassesParams{
		RegionID: ptr.To(openapi.RegionIDQueryParameter{regionID}),
	}

	handler.GetApiV2Volumeclasses(response, request, params)

	require.Equal(t, http.StatusNotFound, response.Code)
}

func TestVolumeClassV2ReturnsNotFoundForMissingExplicitRegion(t *testing.T) {
	t.Parallel()

	const (
		namespace = "volume-class-test"
		regionID  = "23232323-2323-4232-a323-232323232323"
	)

	ctrl := gomock.NewController(t)
	providerSet := mockproviders.NewMockProviders(ctrl)
	handler := &Handler{
		ClientArgs: common.ClientArgs{
			Client:    fakeClientWithSchema(t),
			Namespace: namespace,
			Providers: providerSet,
		},
	}

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v2/volumeclasses", nil)
	response := httptest.NewRecorder()
	params := openapi.GetApiV2VolumeclassesParams{
		RegionID: ptr.To(openapi.RegionIDQueryParameter{regionID}),
	}

	handler.GetApiV2Volumeclasses(response, request, params)

	require.Equal(t, http.StatusNotFound, response.Code)
}

func TestVolumeClassV2FiltersInaccessibleRegions(t *testing.T) {
	t.Parallel()

	const (
		namespace          = "volume-class-test"
		accessibleRegionID = "33333333-3333-4333-a333-333333333333"
		restrictedRegionID = "44444444-4444-4444-a444-444444444444"
		volumeClassID      = "bbbbbbbb-bbbb-4bbb-abbb-bbbbbbbbbbbb"
	)

	ctrl := gomock.NewController(t)
	provider := mockprovider.NewMockCommonProvider(ctrl)
	provider.EXPECT().VolumeClasses(gomock.Any()).Return(types.VolumeClassList{
		{ID: volumeClassID, Name: "visible-class"},
	}, nil)

	providerSet := mockproviders.NewMockProviders(ctrl)
	providerSet.EXPECT().LookupCommon(accessibleRegionID).Return(provider, nil)

	accessibleRegion := &regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      accessibleRegionID,
			Namespace: namespace,
		},
	}
	restrictedRegion := &regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      restrictedRegionID,
			Namespace: namespace,
		},
		Spec: regionv1.RegionSpec{
			Security: &regionv1.RegionSecuritySpec{
				Organizations: []regionv1.RegionSecurityOrganizationSpec{
					{ID: "allowed-organization"},
				},
			},
		},
	}
	handler := &Handler{
		ClientArgs: common.ClientArgs{
			Client:    fakeClientWithSchema(t, accessibleRegion, restrictedRegion),
			Namespace: namespace,
			Providers: providerSet,
		},
	}

	ctx := newOrganisationACLBuilder("different-organization").buildContext(t.Context())
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v2/volumeclasses", nil)
	response := httptest.NewRecorder()

	handler.GetApiV2Volumeclasses(response, request, openapi.GetApiV2VolumeclassesParams{})

	require.Equal(t, http.StatusOK, response.Code)

	var result openapi.VolumeClassListV2Response

	requireDeserialiseBody(t, response.Body, &result)
	require.Len(t, result, 1)
	require.Equal(t, volumeClassID, result[0].Metadata.Id)
	require.Equal(t, accessibleRegionID, result[0].Spec.RegionId.String())
}

func TestVolumeClassV2FiltersAndDeduplicatesExplicitRegions(t *testing.T) {
	t.Parallel()

	const (
		namespace        = "volume-class-test"
		unselectedRegion = "55555555-5555-4555-a555-555555555555"
		selectedRegion   = "66666666-6666-4666-a666-666666666666"
	)

	ctrl := gomock.NewController(t)
	provider := mockprovider.NewMockCommonProvider(ctrl)
	provider.EXPECT().VolumeClasses(gomock.Any()).Return(types.VolumeClassList{
		{ID: "cccccccc-cccc-4ccc-accc-cccccccccccc", Name: "selected-class"},
	}, nil)

	providerSet := mockproviders.NewMockProviders(ctrl)
	providerSet.EXPECT().LookupCommon(selectedRegion).Return(provider, nil)

	firstRegion := &regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      unselectedRegion,
			Namespace: namespace,
		},
	}
	secondRegion := &regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      selectedRegion,
			Namespace: namespace,
		},
	}
	handler := &Handler{
		ClientArgs: common.ClientArgs{
			Client:    fakeClientWithSchema(t, firstRegion, secondRegion),
			Namespace: namespace,
			Providers: providerSet,
		},
	}

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v2/volumeclasses", nil)
	response := httptest.NewRecorder()
	params := openapi.GetApiV2VolumeclassesParams{
		RegionID: ptr.To(openapi.RegionIDQueryParameter{selectedRegion, selectedRegion}),
	}

	handler.GetApiV2Volumeclasses(response, request, params)

	require.Equal(t, http.StatusOK, response.Code)

	var result openapi.VolumeClassListV2Response

	requireDeserialiseBody(t, response.Body, &result)
	require.Len(t, result, 1)
	require.Equal(t, selectedRegion, result[0].Spec.RegionId.String())
}

func TestVolumeClassV2ReturnsEmptyListForEmptyProviderInventory(t *testing.T) {
	t.Parallel()

	const (
		namespace = "volume-class-test"
		regionID  = "77777777-7777-4777-a777-777777777777"
	)

	ctrl := gomock.NewController(t)
	provider := mockprovider.NewMockCommonProvider(ctrl)
	provider.EXPECT().VolumeClasses(gomock.Any()).Return(nil, nil)

	providerSet := mockproviders.NewMockProviders(ctrl)
	providerSet.EXPECT().LookupCommon(regionID).Return(provider, nil)

	region := &regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      regionID,
			Namespace: namespace,
		},
	}
	handler := &Handler{
		ClientArgs: common.ClientArgs{
			Client:    fakeClientWithSchema(t, region),
			Namespace: namespace,
			Providers: providerSet,
		},
	}

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v2/volumeclasses", nil)
	response := httptest.NewRecorder()

	handler.GetApiV2Volumeclasses(response, request, openapi.GetApiV2VolumeclassesParams{})

	require.Equal(t, http.StatusOK, response.Code)

	var result openapi.VolumeClassListV2Response

	requireDeserialiseBody(t, response.Body, &result)
	require.NotNil(t, result)
	require.Empty(t, result)
}

func TestVolumeClassV2SortsProviderInventoryByNameThenID(t *testing.T) {
	t.Parallel()

	const (
		namespace = "volume-class-test"
		regionID  = "aaaaaaaa-1111-4111-a111-111111111111"
	)

	ctrl := gomock.NewController(t)
	provider := mockprovider.NewMockCommonProvider(ctrl)
	provider.EXPECT().VolumeClasses(gomock.Any()).Return(types.VolumeClassList{
		{ID: "dddddddd-dddd-4ddd-addd-dddddddddddd", Name: "zonal"},
		{ID: "ffffffff-ffff-4fff-afff-ffffffffffff", Name: "balanced"},
		{ID: "eeeeeeee-eeee-4eee-aeee-eeeeeeeeeeee", Name: "balanced"},
	}, nil)

	providerSet := mockproviders.NewMockProviders(ctrl)
	providerSet.EXPECT().LookupCommon(regionID).Return(provider, nil)

	region := &regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      regionID,
			Namespace: namespace,
		},
	}
	handler := &Handler{
		ClientArgs: common.ClientArgs{
			Client:    fakeClientWithSchema(t, region),
			Namespace: namespace,
			Providers: providerSet,
		},
	}

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v2/volumeclasses", nil)
	response := httptest.NewRecorder()

	handler.GetApiV2Volumeclasses(response, request, openapi.GetApiV2VolumeclassesParams{})

	require.Equal(t, http.StatusOK, response.Code)

	var result openapi.VolumeClassListV2Response

	requireDeserialiseBody(t, response.Body, &result)
	require.Len(t, result, 3)
	require.Equal(t, "eeeeeeee-eeee-4eee-aeee-eeeeeeeeeeee", result[0].Metadata.Id)
	require.Equal(t, "ffffffff-ffff-4fff-afff-ffffffffffff", result[1].Metadata.Id)
	require.Equal(t, "dddddddd-dddd-4ddd-addd-dddddddddddd", result[2].Metadata.Id)
}
