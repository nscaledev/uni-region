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
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/unikorn-cloud/region/pkg/handler/util/unit"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace      = "test-ns"
	testOrganizationID = "3d84f1f2-4a41-44d5-98ab-8b282d00abb9"
	testRegionID       = "test-region"
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
	handler := NewImageHandler(c, testNamespace, &Options{ImageUploadSizeLimit: unit.GiBToBytes(10)})

	// Inject the mock provider
	handler.getProvider = func(context.Context, client.Client, string, string) (image.Provider, error) {
		return mockProvider, nil
	}

	return handler
}

func contextWithImagePermissions(t *testing.T) context.Context {
	t.Helper()

	return rbac.NewContext(t.Context(), &idopenapi.Acl{
		Global: &idopenapi.AclEndpoints{
			idopenapi.AclEndpoint{Name: "region:images", Operations: []idopenapi.AclOperation{"create", "read", "delete"}},
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

func requireParseJSON[T any](t *testing.T, body io.Reader, out T) {
	t.Helper()

	bytes, err := io.ReadAll(body)
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(bytes, out))
}

func TestImageHandler_List_Active(t *testing.T) {
	t.Parallel()

	activeImage := *mock.NewTestProviderImage(types.ImageStatusReady)
	activeImage.Name = "good"

	inactiveImages := []types.Image{
		*mock.NewTestProviderImage(types.ImageStatusPending),
		*mock.NewTestProviderImage(types.ImageStatusCreating),
		*mock.NewTestProviderImage(types.ImageStatusFailed),
	}

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockProvider := mock.NewMockProvider(mockCtrl)
	mockProvider.EXPECT().ListImages(gomock.Any(), testOrganizationID).Return(
		append(inactiveImages, activeImage), nil,
	)

	handler := newTestImageHandler(t, mockProvider)

	u := fmt.Sprintf("/api/v1/organizations/%s/regions/%s/images", testOrganizationID, testRegionID)
	req := httptest.NewRequest(http.MethodGet, u, nil)
	req = req.WithContext(contextWithImagePermissions(t))

	res := httptest.NewRecorder()
	handler.GetApiV1OrganizationsOrganizationIDRegionsRegionIDImages(res, req, testOrganizationID, testRegionID)

	require.Equal(t, http.StatusOK, res.Result().StatusCode)

	var response openapi.ImagesResponse

	requireParseJSON(t, res.Result().Body, &response)
	require.Len(t, response, 1)
	assert.Equal(t, "good", response[0].Metadata.Name)
}

func TestImageHandler_Fetch_Good(t *testing.T) {
	t.Parallel()

	testcases := map[string]struct {
		imageFormat   openapi.ImageDiskFormat
		expectedBytes []byte
		responseFunc  func(*testing.T) io.Reader
	}{
		"raw disk tarball": {
			imageFormat:   openapi.ImageDiskFormatRaw,
			expectedBytes: rawFileBytes(),
			responseFunc:  mock.TarballedReader(mock.Files{"disk.raw": rawFileBytes()}),
		},
		"qcow2 disk tarball": {
			imageFormat:   openapi.ImageDiskFormatQcow2,
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
				w.Header().Set("Content-Type", "application/tar+gzip")
				w.WriteHeader(http.StatusOK)
				_, err := io.Copy(w, responseBody)
				serverCalled <- err
			}))
			t.Cleanup(server.Close)

			u := fmt.Sprintf("/api/v1/organizations/%s/regions/%s/images", testOrganizationID, testRegionID)

			createRequest := &openapi.ImageCreateRequest{
				Spec: openapi.ImageCreateSpec{
					SourceURL:    server.URL,
					SourceFormat: &testcase.imageFormat,
				},
			}

			requestBody, err := json.Marshal(createRequest)
			require.NoError(t, err)

			req, err := http.NewRequest(http.MethodPost, u, bytes.NewBuffer(requestBody))
			require.NoError(t, err)

			req = req.WithContext(contextWithImagePermissions(t))

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
