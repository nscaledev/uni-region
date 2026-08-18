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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	regionconstants "github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/openapi"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	providertypes "github.com/unikorn-cloud/region/pkg/providers/types"
	mockprovider "github.com/unikorn-cloud/region/pkg/providers/types/mock"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	volumeHandlerNamespace      = "volume-handler-test"
	volumeHandlerOrganizationID = "81111111-1111-4111-a111-111111111111"
	volumeHandlerProjectID      = "82222222-2222-4222-a222-222222222222"
	volumeHandlerRegionID       = "83333333-3333-4333-a333-333333333333"
	volumeHandlerIdentityID     = "84444444-4444-4444-a444-444444444444"
	volumeHandlerNetworkID      = "85555555-5555-4555-a555-555555555555"
	volumeHandlerClassID        = "fast"
)

func volumeHandlerContext(ctx context.Context) context.Context {
	ctx = rbac.NewContext(ctx, &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{{
			Id: volumeHandlerOrganizationID,
			Projects: &identityapi.AclProjectList{{
				Id: volumeHandlerProjectID,
				Endpoints: identityapi.AclEndpoints{
					{Name: "region:networks:v2", Operations: identityapi.AclOperations{identityapi.Read}},
					{Name: "region:volumes:v2", Operations: identityapi.AclOperations{identityapi.Read, identityapi.Create, identityapi.Update, identityapi.Delete}},
				},
			}},
		}},
	})

	return withPrincipal(ctx)
}

func volumeHandlerRequest(ctx context.Context, t *testing.T, method, target string, body any) *http.Request {
	t.Helper()

	var data []byte

	if body != nil {
		var err error
		data, err = json.Marshal(body)
		require.NoError(t, err)
	}

	return httptest.NewRequestWithContext(ctx, method, target, bytes.NewReader(data))
}

func TestVolumeV2Handlers(t *testing.T) {
	t.Parallel()

	network := &regionv1.Network{ObjectMeta: metav1.ObjectMeta{
		Name:      volumeHandlerNetworkID,
		Namespace: volumeHandlerNamespace,
		Labels: map[string]string{
			coreconstants.OrganizationLabel:         volumeHandlerOrganizationID,
			coreconstants.ProjectLabel:              volumeHandlerProjectID,
			regionconstants.RegionLabel:             volumeHandlerRegionID,
			regionconstants.IdentityLabel:           volumeHandlerIdentityID,
			regionconstants.ResourceAPIVersionLabel: regionconstants.MarshalAPIVersion(2),
		},
	}}

	ctrl := gomock.NewController(t)
	providers := mockproviders.NewMockProviders(ctrl)
	provider := mockprovider.NewMockCommonProvider(ctrl)
	providers.EXPECT().LookupCommon(volumeHandlerRegionID).Return(provider, nil)
	provider.EXPECT().VolumeClasses(gomock.Any()).Return(providertypes.VolumeClassList{{ID: volumeHandlerClassID}}, nil)

	handler := &Handler{ClientArgs: common.ClientArgs{
		Client:    fakeClientWithSchema(t, network),
		Namespace: volumeHandlerNamespace,
		Providers: providers,
	}}
	ctx := volumeHandlerContext(t.Context())

	create := openapi.VolumeV2Create{
		Metadata: coreapi.ResourceWriteMetadata{Name: "data"},
		Spec: openapi.VolumeV2Spec{
			NetworkId:     idstest.MustParseNetworkID(volumeHandlerNetworkID),
			VolumeClassId: volumeHandlerClassID,
			SizeGiB:       20,
		},
	}
	response := httptest.NewRecorder()
	handler.PostApiV2Volumes(response, volumeHandlerRequest(ctx, t, http.MethodPost, "/api/v2/volumes", create))
	require.Equal(t, http.StatusAccepted, response.Code)

	var created openapi.VolumeV2Response

	requireDeserialiseBody(t, response.Body, &created)
	volumeID := idstest.MustParseVolumeID(created.Metadata.Id)

	response = httptest.NewRecorder()
	handler.GetApiV2Volumes(response, volumeHandlerRequest(ctx, t, http.MethodGet, "/api/v2/volumes", nil), openapi.GetApiV2VolumesParams{})
	require.Equal(t, http.StatusOK, response.Code)

	var listed openapi.VolumesV2Response

	requireDeserialiseBody(t, response.Body, &listed)
	require.Len(t, listed, 1)

	response = httptest.NewRecorder()
	handler.GetApiV2VolumesVolumeID(response, volumeHandlerRequest(ctx, t, http.MethodGet, "/api/v2/volumes/"+volumeID.String(), nil), volumeID)
	require.Equal(t, http.StatusOK, response.Code)

	response = httptest.NewRecorder()
	handler.PutApiV2VolumesVolumeID(response, volumeHandlerRequest(ctx, t, http.MethodPut, "/api/v2/volumes/"+volumeID.String(), openapi.VolumeV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: "renamed"},
	}), volumeID)
	require.Equal(t, http.StatusOK, response.Code)

	response = httptest.NewRecorder()
	handler.DeleteApiV2VolumesVolumeID(response, volumeHandlerRequest(ctx, t, http.MethodDelete, "/api/v2/volumes/"+volumeID.String(), nil), volumeID)
	require.Equal(t, http.StatusAccepted, response.Code)
}
