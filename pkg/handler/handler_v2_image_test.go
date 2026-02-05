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

//nolint:testpackage
package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/unikorn-cloud/region/pkg/handler/common"
	imagemock "github.com/unikorn-cloud/region/pkg/handler/image/mock"
	"github.com/unikorn-cloud/region/pkg/openapi"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	mockprovider "github.com/unikorn-cloud/region/pkg/providers/types/mock"

	"k8s.io/utils/ptr"
)

func Test_Imagev2_List(t *testing.T) {
	t.Parallel()

	const (
		namespace = "test-org-images"
		regionID  = "region-1"
		orgID     = "cats"
	)

	// All the test cases assume the caller will have permissions for the org identified by `orgID`.

	testcases := map[string]struct {
		setupQuery func(*imagemock.MockImageQuery)
		params     openapi.GetApiV2RegionsRegionIDImagesParams
	}{
		// All these should call the expected query methods and return 200

		"available to org": {
			setupQuery: func(query *imagemock.MockImageQuery) {
				query.EXPECT().AvailableToOrganization(orgID).Return(query)
				query.EXPECT().List(gomock.Any()).Return(nil, nil)
			},
			params: openapi.GetApiV2RegionsRegionIDImagesParams{
				OrganizationID: ptr.To([]string{orgID}),
			},
		},
		"filter by status": {
			setupQuery: func(query *imagemock.MockImageQuery) {
				query.EXPECT().AvailableToOrganization(orgID).Return(query)
				query.EXPECT().StatusIn(types.ImageStatusReady).Return(query)
				query.EXPECT().List(gomock.Any()).Return(nil, nil)
			},
			params: openapi.GetApiV2RegionsRegionIDImagesParams{
				OrganizationID: ptr.To([]string{orgID}),
				Status:         ptr.To([]openapi.ImageState{openapi.ImageStateReady}),
			},
		},
		"owned by org": {
			setupQuery: func(query *imagemock.MockImageQuery) {
				query.EXPECT().OwnedByOrganization(orgID).Return(query)
				query.EXPECT().List(gomock.Any()).Return(nil, nil)
			},
			params: openapi.GetApiV2RegionsRegionIDImagesParams{
				OrganizationID: ptr.To([]string{orgID}),
				Scope:          ptr.To(openapi.GetApiV2RegionsRegionIDImagesParamsScopeOwned),
			},
		},
		"available, ready images": {
			setupQuery: func(query *imagemock.MockImageQuery) {
				query.EXPECT().AvailableToOrganization(orgID).Return(query)
				query.EXPECT().StatusIn(types.ImageStatusReady).Return(query)
				query.EXPECT().List(gomock.Any()).Return(nil, nil)
			},
			params: openapi.GetApiV2RegionsRegionIDImagesParams{
				OrganizationID: ptr.To([]string{orgID}),
				Status:         ptr.To([]openapi.ImageState{openapi.ImageStateReady}),
				Scope:          ptr.To(openapi.GetApiV2RegionsRegionIDImagesParamsScopeAvailable),
			},
		},
		"orgs with no permission": {
			setupQuery: func(query *imagemock.MockImageQuery) {
				// This must be called even though the caller has no permission to the org,
				// to get global images, since those are counted as available.
				query.EXPECT().AvailableToOrganization().Return(query)
				query.EXPECT().List(gomock.Any()).Return(nil, nil)
			},
			params: openapi.GetApiV2RegionsRegionIDImagesParams{
				OrganizationID: ptr.To([]string{"NOT" + orgID}),
			},
		},
		"no filters": { // when asking without giving an organization, you don't need org permissions.
			setupQuery: func(query *imagemock.MockImageQuery) {
				query.EXPECT().AvailableToOrganization().Return(query)
				query.EXPECT().List(gomock.Any()).Return(nil, nil)
			},
		},
	}

	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx := newOrganisationACLBuilder(orgID).
				addEndpoint("region:images", "read").
				buildContext(t.Context())

			ctrl := gomock.NewController(t)
			provider := mockprovider.NewMockProvider(ctrl)
			querier := imagemock.NewMockImageQuery(ctrl)

			// Expect to get asked for an image querier.
			provider.EXPECT().QueryImages().Return(querier, nil)

			providers := mockproviders.NewMockProviders(ctrl)
			providers.EXPECT().LookupCloud(gomock.Any(), gomock.Any()).Return(provider, nil)

			if setupQuery := tc.setupQuery; setupQuery != nil {
				setupQuery(querier)
			}

			c := fakeClientWithSchema(t)

			clientArgs := common.ClientArgs{
				Namespace: namespace,
				Client:    c,
				Providers: providers,
			}

			handler := NewImageV2Handler(clientArgs, &Options{})

			path := fmt.Sprintf("/api/v2/region/%s/images", regionID)
			request := httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
			response := httptest.NewRecorder()

			handler.GetApiV2RegionsRegionIDImages(response, request, regionID, tc.params)

			require.Equal(t, http.StatusOK, response.Result().StatusCode)
		})
	}
}
