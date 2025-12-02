/*
Copyright 2025 the Unikorn Authors.

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
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	idopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/region/pkg/handler/image"
	"github.com/unikorn-cloud/region/pkg/handler/image/mock"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace      = "test-ns"
	testOrganizationID = "3d84f1f2-4a41-44d5-98ab-8b282d00abb9"
	testRegionID       = "test-region"
	testImageID        = "b3796b32-57d3-40cf-b43e-d227c0c5a70b"
)

// expectedReaderBytes creates a gomock matcher that compares reader contents.
func expectedReaderBytes(content []byte) gomock.Matcher {
	return gomock.Cond(func(reader io.Reader) bool {
		actual, err := io.ReadAll(reader)
		if err != nil {
			return false
		}

		return bytes.Equal(actual, content)
	})
}

// newTestImageHandler creates an ImageHandler with a mock provider injected.
func newTestImageHandler(t *testing.T, mockProvider *mock.MockProvider) *ImageHandler {
	t.Helper()

	c := fake.NewClientBuilder().Build()
	handler := NewImageHandler(c, testNamespace, &Options{ImageUploadSizeLimit: 10 << 30})

	// Inject the mock provider
	handler.getProvider = func(context.Context, client.Client, string, string) (image.Provider, error) {
		return mockProvider, nil
	}

	return handler
}

// createMultipartRequest creates an HTTP request with multipart form data.
func createMultipartRequest(t *testing.T, data io.Reader) *http.Request {
	t.Helper()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", "disk.tar.gz")
	require.NoError(t, err)

	_, err = io.Copy(part, data)
	require.NoError(t, err)

	err = writer.Close()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+testOrganizationID+"/regions/"+testRegionID+"/images/"+testImageID+"/data", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	return req
}

func contextWithCreateImagePermission(t *testing.T) context.Context {
	t.Helper()

	return rbac.NewContext(t.Context(), &idopenapi.Acl{
		Global: &idopenapi.AclEndpoints{
			idopenapi.AclEndpoint{Name: "region:images", Operations: []idopenapi.AclOperation{"create"}},
		},
	})
}

func TestImageHandler_ProviderResponses(t *testing.T) {
	t.Parallel()

	// Create test image data. This is used for all the tests.
	rawFileContent := make([]byte, 512)
	rawFileContent[510], rawFileContent[511] = 0x55, 0xAA

	testcases := map[string]struct {
		setupMock          func(*mock.MockProvider)
		expectedStatusCode int
	}{
		"success": {
			setupMock: func(mockProvider *mock.MockProvider) {
				// Create the provider image that will be returned by GetImage
				providerImage := mock.NewTestProviderImage(types.ImageStatusPending)

				// Set up expectations
				mockProvider.EXPECT().
					GetImage(gomock.Any(), testOrganizationID, testImageID).
					Return(providerImage, nil)

				mockProvider.EXPECT().
					UploadImageData(gomock.Any(), testImageID, expectedReaderBytes(rawFileContent)).
					Return(nil)
			},
			expectedStatusCode: http.StatusOK,
		},
		"not found": {
			setupMock: func(mockProvider *mock.MockProvider) {
				mockProvider.EXPECT().
					GetImage(gomock.Any(), testOrganizationID, testImageID).
					Return(nil, types.ErrResourceNotFound)
			},
			expectedStatusCode: http.StatusNotFound,
		},
		"image not pending": {
			setupMock: func(mockProvider *mock.MockProvider) {
				// Create test image with READY status (not pending)
				providerImage := mock.NewTestProviderImage(types.ImageStatusReady)

				mockProvider.EXPECT().
					GetImage(gomock.Any(), testOrganizationID, testImageID).
					Return(providerImage, nil)
			},
			expectedStatusCode: http.StatusConflict,
		},
		"wrong organization": {
			setupMock: func(mockProvider *mock.MockProvider) {
				providerImage := mock.NewTestProviderImage(types.ImageStatusPending)
				differentOrgID := "different-org-id"
				providerImage.OrganizationID = &differentOrgID

				mockProvider.EXPECT().
					GetImage(gomock.Any(), testOrganizationID, testImageID).
					Return(providerImage, nil)
			},
			expectedStatusCode: http.StatusNotFound,
		},
		"conflict from provider": {
			setupMock: func(mockProvider *mock.MockProvider) {
				providerImage := mock.NewTestProviderImage(types.ImageStatusPending)

				mockProvider.EXPECT().
					GetImage(gomock.Any(), testOrganizationID, testImageID).
					Return(providerImage, nil)

				// Simulate upload conflict (already uploaded)
				mockProvider.EXPECT().
					UploadImageData(gomock.Any(), testImageID, expectedReaderBytes(rawFileContent)).
					Return(types.ErrImageNotReadyForUpload)
			},
			expectedStatusCode: http.StatusConflict,
		},
	}

	for name, testcase := range testcases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mockProvider := mock.NewTestMockProvider(t)
			testcase.setupMock(mockProvider)

			tarGzData := mock.TarballedReader(mock.Files{"disk.raw": rawFileContent})(t)
			req := createMultipartRequest(t, tarGzData)

			// Add a fake context with authorization (normally added by middleware)
			// For this test we skip RBAC checks by using a minimal context
			req = req.WithContext(contextWithCreateImagePermission(t))

			w := httptest.NewRecorder()

			handler := newTestImageHandler(t, mockProvider)
			handler.PostApiV1OrganizationsOrganizationIDRegionsRegionIDImagesImageIDData(
				w, req, testOrganizationID, testRegionID, testImageID,
			)

			// Verify response
			require.Equal(t, testcase.expectedStatusCode, w.Code)
		})
	}
}

func TestImageHandler_BadRequests(t *testing.T) {
	t.Parallel()

	testcases := map[string]struct {
		invalidData io.Reader
	}{
		"invalid gzip": {
			// Create request with invalid gzip data
			invalidData: bytes.NewBufferString("this is not valid gzip data"),
		},
	}

	for name, testcase := range testcases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockProvider := mock.NewMockProvider(mockCtrl)

			providerImage := mock.NewTestProviderImage(types.ImageStatusPending)

			mockProvider.EXPECT().
				GetImage(gomock.Any(), testOrganizationID, testImageID).
				Return(providerImage, nil)

			// Create handler
			handler := newTestImageHandler(t, mockProvider)

			req := createMultipartRequest(t, testcase.invalidData)
			req = req.WithContext(contextWithCreateImagePermission(t))

			w := httptest.NewRecorder()

			handler.PostApiV1OrganizationsOrganizationIDRegionsRegionIDImagesImageIDData(
				w, req, testOrganizationID, testRegionID, testImageID,
			)

			// Verify server error response
			require.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}
