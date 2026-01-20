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
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/image"
	imagemock "github.com/unikorn-cloud/region/pkg/handler/image/mock"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Test_Imagev2_List(t *testing.T) {
	t.Parallel()

	const (
		namespace = "test-org-images"
		regionID  = "region-1"
	)

	testcases := map[string]struct {
		setupQuery func(*imagemock.MockImageQuery)
		params     openapi.GetApiV2RegionsRegionIDImagesParams
	}{
		"no filters": {
			setupQuery: func(*imagemock.MockImageQuery) {},
		},
		"filter by org": {
			setupQuery: func(query *imagemock.MockImageQuery) {
				query.EXPECT().AvailableToOrganization("cats").Return(query)
			},
			params: openapi.GetApiV2RegionsRegionIDImagesParams{
				OrganizationID: ptr.To([]string{"cats"}),
			},
		},
		"filter by status": {
			setupQuery: func(query *imagemock.MockImageQuery) {
				query.EXPECT().StatusIn(types.ImageStatusReady).Return(query)
			},
			params: openapi.GetApiV2RegionsRegionIDImagesParams{
				Status: ptr.To([]openapi.ImageState{"ready"}),
			},
		},
		"filter to owned images": {
			setupQuery: func(query *imagemock.MockImageQuery) {
				query.EXPECT().OwnedByOrganization("cats").Return(query)
			},
			params: openapi.GetApiV2RegionsRegionIDImagesParams{
				OrganizationID: ptr.To([]string{"cats"}),
				Scope:          ptr.To(openapi.GetApiV2RegionsRegionIDImagesParamsScopeOwned),
			},
		},
		"filter to available, ready images": {
			setupQuery: func(query *imagemock.MockImageQuery) {
				query.EXPECT().AvailableToOrganization("cats").Return(query)
				query.EXPECT().StatusIn(types.ImageStatusReady).Return(query)
			},
			params: openapi.GetApiV2RegionsRegionIDImagesParams{
				OrganizationID: ptr.To([]string{"cats"}),
				Status:         ptr.To([]openapi.ImageState{"ready"}),
				Scope:          ptr.To(openapi.GetApiV2RegionsRegionIDImagesParamsScopeAvailable),
			},
		},
	}

	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			provider, ctrl := imagemock.NewTestMockProviderAndController(t)
			querier := imagemock.NewMockImageQuery(ctrl)

			// Expect to get asked for an image querier.
			provider.EXPECT().QueryImages().Return(querier, nil)

			tc.setupQuery(querier)
			querier.EXPECT().List(gomock.Any()).Return(nil, nil)

			c := fakeClientWithSchema(t)

			clientArgs := common.ClientArgs{
				Namespace: namespace,
				Client:    c,
			}

			handler := NewImageV2Handler(clientArgs, &Options{})
			handler.getProviderFunc = func(_ context.Context, _ client.Client, _, _ string) (image.Provider, error) {
				return provider, nil
			}

			path := fmt.Sprintf("/api/v2/region/%s/images", regionID)
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
			response := httptest.NewRecorder()

			handler.GetApiV2RegionsRegionIDImages(response, request, regionID, tc.params)

			require.Equal(t, http.StatusOK, response.Result().StatusCode)
		})
	}
}
