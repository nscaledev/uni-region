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

package mock

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/utils/ptr"
)

//go:generate mockgen -source=../image.go -destination=interfaces.go -package=mock

const (
	testImageID        = "b3796b32-57d3-40cf-b43e-d227c0c5a70b"
	testOrganizationID = "3d84f1f2-4a41-44d5-98ab-8b282d00abb9"
)

// newTestProviderImage creates a test provider image with the given parameters.
// If organizationID is empty, it uses testOrganizationID as the default.
func NewTestProviderImage(status types.ImageStatus) *types.Image {
	return &types.Image{
		ID:             testImageID,
		Name:           "test-image",
		OrganizationID: ptr.To(testOrganizationID),
		Created:        time.Date(2025, 10, 31, 12, 0, 0, 0, time.UTC),
		Modified:       time.Date(2025, 10, 31, 12, 0, 0, 0, time.UTC),
		SizeGiB:        25,
		Virtualization: types.Virtualized,
		DiskFormat:     types.ImageDiskFormatRaw,
		Status:         status,
	}
}

// newTestMockProvider creates a new mock provider with a gomock controller.
// The controller is automatically cleaned up when the test finishes.
func NewTestMockProvider(t *testing.T) *MockProvider {
	t.Helper()

	mockController := gomock.NewController(t)
	t.Cleanup(mockController.Finish)

	return NewMockProvider(mockController)
}

// StringReader returns a io.Reader-providing func that reads from the `content` given.
func StringReader(content string) func(t *testing.T) io.Reader {
	return func(t *testing.T) io.Reader {
		t.Helper()

		return bytes.NewBufferString(content)
	}
}

// Base64Reader returns an io.Reader of the bytes base64-decoded from `content`. It's convenient here for
// being able to supply "golden" image file data.
func Base64Reader(t *testing.T, content string) io.Reader {
	t.Helper()

	bs, err := base64.StdEncoding.DecodeString(content)
	require.NoError(t, err)

	return bytes.NewBuffer(bs)
}

// GzippedReader takes a reader of file content and returns a ReaderSetupFunc yielding gzipped file content.
func GzippedReader(content io.Reader) func(t *testing.T) io.Reader {
	return func(t *testing.T) io.Reader {
		t.Helper()

		var buf bytes.Buffer

		gzipWriter := gzip.NewWriter(&buf)

		if _, err := io.Copy(gzipWriter, content); err != nil {
			require.NoError(t, err)
		}

		if err := gzipWriter.Close(); err != nil {
			require.NoError(t, err)
		}

		return &buf
	}
}

type Files map[string][]byte

// TarballedReader takes a map of files, and returns a ReaderSetupFunc yielding a gzipped tarball.
func TarballedReader(fs Files) func(t *testing.T) io.Reader {
	return func(t *testing.T) io.Reader {
		t.Helper()

		var buf bytes.Buffer

		gzipWriter := gzip.NewWriter(&buf)

		tarWriter := tar.NewWriter(gzipWriter)

		for filename, content := range fs {
			tarHeader := &tar.Header{
				Name: filename,
				Mode: 0600,
				Size: int64(len(content)),
			}

			require.NoError(t, tarWriter.WriteHeader(tarHeader))

			_, err := tarWriter.Write(content)
			require.NoError(t, err)
		}

		require.NoError(t, tarWriter.Close())
		require.NoError(t, gzipWriter.Close())

		return &buf
	}
}
