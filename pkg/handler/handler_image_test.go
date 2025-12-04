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
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	idopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/region/pkg/handler/image"
	"github.com/unikorn-cloud/region/pkg/handler/image/mock"
	"github.com/unikorn-cloud/region/pkg/openapi"
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

func urlForPost() string {
	return fmt.Sprintf("/api/v1/organizations/%s/regions/%s/images/%s/data",
		testOrganizationID, testRegionID, testImageID)
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

	req := httptest.NewRequest(http.MethodPost, urlForPost(), body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	return req
}

func createBytesRequest(t *testing.T, contentType string, data []byte) *http.Request {
	t.Helper()

	body := bytes.NewBuffer(data)
	req := httptest.NewRequest(http.MethodPost, urlForPost(), body)
	req.Header.Set("Content-Type", contentType)

	return req
}

func createGzipRequest(t *testing.T, contentType string, data []byte) *http.Request {
	t.Helper()

	body := &bytes.Buffer{}
	gzipWriter := gzip.NewWriter(body)
	_, err := gzipWriter.Write(data)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, urlForPost(), body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Content-Encoding", "gzip")

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

func rawFileBytes() []byte {
	rawFileContent := make([]byte, 512)
	rawFileContent[510], rawFileContent[511] = 0x55, 0xAA

	return rawFileContent
}

func qcow2FileBytes() []byte {
	return []byte{'Q', 'F', 'I', 0xfb}
}

func tarGzippedFile(t *testing.T, filename string, data []byte) io.Reader {
	t.Helper()

	return mock.TarballedReader(mock.Files{filename: data})(t)
}

func TestImageHandler_Upload_ProviderResponses(t *testing.T) {
	t.Parallel()

	rawFileContent := rawFileBytes()

	// Create test image data. This is used for all the tests.

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

			// This is a known good request (as verified below), so the result
			// will depend on the provider's response.
			tarGzData := tarGzippedFile(t, "disk.raw", rawFileContent)
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

func TestImageHandler_Upload_BadRequests(t *testing.T) {
	t.Parallel()

	testcases := map[string]struct {
		invalidData io.Reader
	}{
		"invalid gzip": {
			invalidData: bytes.NewBufferString("this is not valid gzip data"),
		},
		"wrong disk file": {
			invalidData: tarGzippedFile(t, "disk.qcow2", qcow2FileBytes()), // the filename is the wrong one
		},
		"invalid disk file": {
			invalidData: tarGzippedFile(t, "disk.raw", qcow2FileBytes()), // the filename is right, but not the contents
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

func TestImageHandler_Upload_GoodRequests(t *testing.T) {
	t.Parallel()

	testcases := map[string]struct {
		imageFormat   types.ImageDiskFormat
		expectedBytes []byte
		requestFunc   func(t *testing.T) *http.Request
	}{
		"raw disk tarball form POST": {
			imageFormat:   types.ImageDiskFormatRaw,
			expectedBytes: rawFileBytes(),
			// Create request with invalid gzip data
			requestFunc: func(t *testing.T) *http.Request { //nolint:thelper
				return createMultipartRequest(t, tarGzippedFile(t, "disk.raw", rawFileBytes()))
			},
		},
		"qcow2 disk tarball form POST": {
			imageFormat:   types.ImageDiskFormatQCOW2,
			expectedBytes: qcow2FileBytes(),
			requestFunc: func(t *testing.T) *http.Request { //nolint:thelper
				return createMultipartRequest(t, tarGzippedFile(t, "disk.qcow2", qcow2FileBytes()))
			},
		},
		"raw disk POST": {
			imageFormat:   types.ImageDiskFormatRaw,
			expectedBytes: rawFileBytes(),
			requestFunc: func(t *testing.T) *http.Request { //nolint:thelper
				return createBytesRequest(t, "application/octet-stream", rawFileBytes())
			},
		},
		"gzipped POST": {
			imageFormat:   types.ImageDiskFormatRaw,
			expectedBytes: rawFileBytes(),
			requestFunc: func(t *testing.T) *http.Request { //nolint:thelper
				return createGzipRequest(t, "application/octet-stream", rawFileBytes())
			},
		},
	}

	for name, testcase := range testcases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockProvider := mock.NewMockProvider(mockCtrl)

			providerImage := mock.NewTestProviderImage(types.ImageStatusPending)
			providerImage.DiskFormat = testcase.imageFormat

			mockProvider.EXPECT().
				GetImage(gomock.Any(), testOrganizationID, testImageID).
				Return(providerImage, nil)
			mockProvider.EXPECT().
				UploadImageData(gomock.Any(), providerImage.ID, expectedReaderBytes(testcase.expectedBytes)).
				Return(nil) // i.e., no error

			handler := newTestImageHandler(t, mockProvider)

			req := testcase.requestFunc(t)
			req = req.WithContext(contextWithCreateImagePermission(t))

			w := httptest.NewRecorder()

			handler.PostApiV1OrganizationsOrganizationIDRegionsRegionIDImagesImageIDData(
				w, req, testOrganizationID, testRegionID, testImageID,
			)

			require.Equal(t, http.StatusOK, w.Code)
		})
	}
}

func waitForChannel[T any](t *testing.T, c chan T) T {
	t.Helper()

	var result T

	assert.Eventually(t, func() bool {
		select {
		case result = <-c:
			return true
		default:
			return false
		}
	}, 2*time.Second, time.Second/4)

	return result
}

func TestImageHandler_Fetch_Good(t *testing.T) {
	t.Parallel()

	testcases := map[string]struct {
		imageFormat   types.ImageDiskFormat
		expectedBytes []byte
		responseFunc  func(*testing.T) io.Reader
	}{
		"raw disk tarball": {
			imageFormat:   types.ImageDiskFormatRaw,
			expectedBytes: rawFileBytes(),
			responseFunc:  mock.TarballedReader(mock.Files{"disk.raw": rawFileBytes()}),
		},
		"qcow2 disk tarball": {
			imageFormat:   types.ImageDiskFormatQCOW2,
			expectedBytes: qcow2FileBytes(),
			responseFunc:  mock.TarballedReader(mock.Files{"disk.qcow2": qcow2FileBytes()}),
		},
	}

	for name, testcase := range testcases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockProvider := mock.NewMockProvider(mockCtrl)

			providerImage := mock.NewTestProviderImage(types.ImageStatusPending)
			providerImage.DiskFormat = testcase.imageFormat

			mockProvider.EXPECT().
				CreateImageForUpload(gomock.Any(), gomock.AssignableToTypeOf(providerImage)).
				Return(providerImage, nil)

			uploadCalled := make(chan struct{})

			mockProvider.EXPECT().
				UploadImageData(gomock.Any(), providerImage.ID, expectedReaderBytes(testcase.expectedBytes)).
				DoAndReturn(func(context.Context, string, io.Reader) error {
					close(uploadCalled)
					return nil
				}) // i.e., no error

			handler := newTestImageHandler(t, mockProvider)

			responseBody := testcase.responseFunc(t)
			serverCalled := make(chan error)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, err := io.Copy(w, responseBody)
				serverCalled <- err
			}))
			t.Cleanup(server.Close)

			u := fmt.Sprintf("/api/v1/organizations/%s/regions/%s/images", testOrganizationID, testRegionID)

			createRequest := &openapi.ImageCreateRequest{
				Spec: openapi.ImageCreateSpec{
					SourceURL: &server.URL,
				},
			}

			requestBody, err := json.Marshal(createRequest)
			require.NoError(t, err)

			req, err := http.NewRequest(http.MethodPost, u, bytes.NewBuffer(requestBody))
			require.NoError(t, err)

			req = req.WithContext(contextWithCreateImagePermission(t))

			w := httptest.NewRecorder()

			handler.PostApiV1OrganizationsOrganizationIDRegionsRegionIDImages(
				w, req, testOrganizationID, testRegionID,
			)

			require.Equal(t, http.StatusOK, w.Code)

			require.NoError(t, waitForChannel(t, serverCalled))
			waitForChannel(t, uploadCalled)
		})
	}
}
