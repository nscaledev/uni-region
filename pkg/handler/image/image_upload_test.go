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
package image

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/unikorn-cloud/core/pkg/server/saga"
	"github.com/unikorn-cloud/region/pkg/handler/image/mock"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"
)

const (
	testOrganizationID = "test-org-id"
	testRegionID       = "test-region-id"
)

func newTestUploadSaga(provider Provider, sourceURL string) *createImageForUploadSaga {
	diskFormat := openapi.ImageDiskFormatRaw

	return &createImageForUploadSaga{
		organizationID: testOrganizationID,
		regionID:       testRegionID,
		sourceFormat:   &diskFormat,
		sourceURL:      sourceURL,
		image: &types.Image{
			Name: "test-image",
		},
		provider: provider,
	}
}

func TestUploadFromURL_Success(t *testing.T) {
	t.Parallel()

	providerImage := mock.NewTestProviderImage(types.ImageStatusReady)

	rawFileContent := make([]byte, 512)
	rawFileContent[510], rawFileContent[511] = 0x55, 0xAA

	// Create a valid tar.gz containing a raw disk image
	tarGzData := mock.TarballedReader(mock.Files{"disk.raw": rawFileContent})(t)
	tarGzBytes, err := io.ReadAll(tarGzData)
	require.NoError(t, err)

	// Channel to signal when the upload completes
	uploadComplete := make(chan struct{})

	// Set up httptest server to serve the tar.gz file
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/tar+gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(tarGzBytes)
	}))
	t.Cleanup(server.Close)

	mockProvider := mock.NewTestMockProvider(t)

	// Expect CreateImageForUpload to be called during saga execution
	mockProvider.EXPECT().
		CreateImageForUpload(gomock.Any(), gomock.Any()).
		Return(providerImage, nil)

	// Expect provider calls from the async goroutine
	mockProvider.EXPECT().
		UploadImageData(gomock.Any(), providerImage.ID, expectedReaderBytes(rawFileContent)).
		DoAndReturn(func(ctx context.Context, imageID string, reader io.Reader) error {
			defer close(uploadComplete)
			return nil
		})

	ctx := t.Context()

	// Create saga with the test URL
	s := newTestUploadSaga(mockProvider, server.URL)

	// Run the saga
	err = saga.Run(ctx, s)
	require.NoError(t, err)

	// Verify the saga completed and created the image
	result, err := s.Result()
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, providerImage.ID, result.ID)

	// Wait for the async upload to complete
	select {
	case <-uploadComplete:
		// Success
	case <-time.After(5 * time.Minute): // <-- FIXME seconds for the automated test
		t.Fatal("timeout waiting for upload to complete")
	}
}

func testServerWithStatus(t *testing.T, code int) func(request chan struct{}) *httptest.Server {
	t.Helper()

	return func(requested chan struct{}) *httptest.Server {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(requested)
			w.WriteHeader(code)
		}))
		t.Cleanup(server.Close)

		return server
	}
}

func TestUploadFromURL_FetchFailures(t *testing.T) {
	t.Parallel()

	table := map[string]func(chan struct{}) *httptest.Server{
		"not found":    testServerWithStatus(t, http.StatusNotFound),
		"server error": testServerWithStatus(t, http.StatusInternalServerError),
		"unreachable": func(requested chan struct{}) *httptest.Server {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			// close it right away, so it won't answer.
			server.Close()
			// also close this, so we don't fail on waiting for it.
			close(requested)

			return server
		},
	}

	for name, createServer := range table {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			providerImage := mock.NewTestProviderImage(types.ImageStatusPending)

			// Channel to signal when the upload attempt completes
			uploadAttempted := make(chan struct{})

			server := createServer(uploadAttempted)

			mockProvider := mock.NewTestMockProvider(t)

			// Expect CreateImageForUpload to be called during saga execution
			mockProvider.EXPECT().
				CreateImageForUpload(gomock.Any(), gomock.Any()).
				Return(providerImage, nil)

			// UploadImage should NOT be called since HTTP fetch fails; the controller will report
			// it at the end, if it is called incorrectly.

			ctx := t.Context()

			// Create saga with the test URL
			s := newTestUploadSaga(mockProvider, server.URL)

			// Run the saga - it should complete successfully even though upload will fail
			err := saga.Run(ctx, s)
			require.NoError(t, err)

			// Verify the saga completed and created the image
			result, err := s.Result()
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, providerImage.ID, result.ID)

			// Wait for the HTTP request to be attempted
			select {
			case <-uploadAttempted:
				// Expected - Bad status was returned
			case <-time.After(5 * time.Second):
				t.Fatal("timeout waiting for upload attempt")
			}
		})
	}
}
