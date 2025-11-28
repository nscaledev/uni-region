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
package image

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/handler/image/mock"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/utils/ptr"
)

func stringReader(content string) func(t *testing.T) io.Reader {
	return func(t *testing.T) io.Reader {
		t.Helper()

		return bytes.NewBufferString(content)
	}
}

func base64Reader(t *testing.T, content string) io.Reader {
	t.Helper()

	bs, err := base64.StdEncoding.DecodeString(content)
	require.NoError(t, err)

	return bytes.NewBuffer(bs)
}

// foo takes a reader of file content and returns a ReaderSetupFunc yielding gzipped file content.
func gzippedReader(content io.Reader) func(t *testing.T) io.Reader {
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

type files map[string][]byte

// tarballedReader takes a map of files, and returns a ReaderSetupFunc yielding a gzipped tarball.
func tarballedReader(fs files) func(t *testing.T) io.Reader {
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

func expectedReaderBytes(content []byte) gomock.Matcher {
	return gomock.Cond(func(reader io.Reader) bool {
		actual, err := io.ReadAll(reader)
		if err != nil {
			return false
		}

		return bytes.Equal(actual, content)
	})
}

func TestUploadImageData(t *testing.T) {
	t.Parallel()

	imageID := "b3796b32-57d3-40cf-b43e-d227c0c5a70b"

	expectedImage := &openapi.Image{
		Metadata: coreopenapi.StaticResourceMetadata{
			Id:           "b3796b32-57d3-40cf-b43e-d227c0c5a70b",
			Name:         "test-image",
			CreationTime: time.Date(2025, 10, 31, 12, 0, 0, 0, time.UTC),
		},
		Spec: openapi.ImageSpec{
			Gpu: &openapi.ImageGpu{
				Driver: "525.85.05",
				Models: ptr.To([]string{
					"A100",
					"H100",
					"H200",
				}),
				Vendor: openapi.GpuVendorNVIDIA,
			},
			Os: openapi.ImageOS{
				Codename: ptr.To("alpha"),
				Distro:   openapi.OsDistroUbuntu,
				Family:   openapi.OsFamilyDebian,
				Kernel:   openapi.OsKernelLinux,
				Variant:  ptr.To("server"),
				Version:  "0.1.0",
			},
			SizeGiB: 25,
			SoftwareVersions: ptr.To(openapi.SoftwareVersions{
				"kubernetes": "v1.25.6",
			}),
			Virtualization: openapi.ImageVirtualizationVirtualized,
		},
	}

	rawFileContent := make([]byte, 512)
	rawFileContent[510], rawFileContent[511] = 0x55, 0xAA
	fakeRawDiskReader := tarballedReader(files{"disk.raw": rawFileContent})

	qcow2FileContent := []byte("QFI\xfb")
	fakeQcow2Reader := tarballedReader(files{"disk.qcow2": qcow2FileContent})

	type TestCase struct {
		Name              string
		ContextMutateFunc func(ctx context.Context) context.Context
		ReaderSetupFunc   func(t *testing.T) io.Reader
		ProviderSetupFunc func(provider *mock.MockProvider)
		DiskFormat        types.ImageDiskFormat
		ExpectedError     bool
		ExpectedImage     *openapi.Image
	}

	testCases := []TestCase{
		{
			Name:            "fails to create gzip reader",
			ReaderSetupFunc: stringReader("this is not valid gzip data"),
			ExpectedError:   true,
			ExpectedImage:   nil,
		},
		{
			Name:            "fails to read invalid tar data",
			ReaderSetupFunc: gzippedReader(bytes.NewBuffer(([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}))),
			ExpectedError:   true,
			ExpectedImage:   nil,
		},
		{
			Name: "fails to parse tar header",
			ReaderSetupFunc: gzippedReader(
				base64Reader(t, "EwMwMBMDLTgyMTk1MDI5NnQTE4NzfINzEzAwcXfhZrsDMDAwAAAAEDAxMRNz9DEwMTAwdBMTg3N8g3NzADATc3yDc3P0eFMTc/QxMDEwMHQTE4NzfINzc/QwE3N8g3Nz9HFTMNR0MBMwMHEw9DAAAAAQMDGAABAwMTETc/QxMDH0MHQTMDBx1OFmuwMAAAD/gICAADExNTYyMQAgMBP///+AMTAwdHhTMDB0MBMwMHF3MDEwMTAwdBMTg3N8g3Nz9HhTMDB0MBMwMHF34Wa7AzAwMAAAABAwMTETc/QxMDEwMHQTE4NzfINzc/QwE3N8g3Nz9HhTE3P0MTAxMDB0ExODc3yDc3MwMBNzfINzczB4UzAwdDATMDBxMDAAgAAAEDAxc/QxMDEwMHQTAAAAIOFmuwMwNAAAABAwMTET////gDEwMHR4UzAwdDATMDBxd+FmuwMwMDAAAAAQMDExE3ODc3P0eFMTc/QxMDEwMHQTE4NzfINzc/QzMTEwMzM2MjQ4NDYxMjgzODBzfINzc/R4UzAwdDATMDBxMDAwAAAAEDAxAAAQMDExE3P0MTAxMDB0EzAwcdThZrsDMDQAAAAQg3N8g3Nz9DATc3yDc3P0eFMwMHQwEzAwcTAwMAAAABAwMQAAEDAxMRNz9DEwMTAwdBMwMHgw4Wa7AwAAEDA=")),
			ExpectedError: true,
			ExpectedImage: nil,
		},
		{
			Name: "fails to parse oversized tar header",
			ReaderSetupFunc: gzippedReader(
				bzip2.NewReader(base64Reader(t, "QlpoOTFBWSZTWcRfsUcAAFDfkOiQQAH/xgBASEBmQF5AAEAICCAAhBtRU9NNIPUaNPUeppo0PUCqVD1AaADEZNHiiS+Wdi697kCxx9qIT3GF8mQnSKvg2sFNkHGCdCG6MqN4zcKTytwhtItXKSj3rOWtbdRUbOOwCADGRCIAjQnVWdKV05Sa6fk0smrPvHAIAfxdyRThQkMRfsUc"))),
			ExpectedError: true,
			ExpectedImage: nil,
		},
		{
			Name: "fails to copy data into temporary file after context cancellation",
			ContextMutateFunc: func(ctx context.Context) context.Context {
				ctx, cancel := context.WithCancel(ctx)
				cancel()

				return ctx
			},
			ReaderSetupFunc: tarballedReader(files{"disk.raw": rawFileContent}),
			ExpectedError:   true,
			ExpectedImage:   nil,
		},
		{
			Name:            "fails to find disk file in tar archive",
			ReaderSetupFunc: tarballedReader(files{"randomfile.txt": []byte("file contents")}),
			ExpectedError:   true,
			ExpectedImage:   nil,
		},
		{
			Name:            "fails to upload image due to upload conflict",
			ReaderSetupFunc: fakeRawDiskReader,
			ProviderSetupFunc: func(provider *mock.MockProvider) {
				provider.EXPECT().
					UploadImageData(gomock.Any(), imageID, expectedReaderBytes(rawFileContent)).
					Return(gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusConflict})
			},
			ExpectedError: true,
			ExpectedImage: nil,
		},
		{
			Name:            "fails to upload image due to unexpected error",
			ReaderSetupFunc: fakeRawDiskReader,
			ProviderSetupFunc: func(provider *mock.MockProvider) {
				provider.EXPECT().
					UploadImageData(gomock.Any(), imageID, expectedReaderBytes(rawFileContent)).
					Return(gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusInternalServerError})
			},
			ExpectedError: true,
			ExpectedImage: nil,
		},
		{
			Name:            "succeeds in uploading raw image data",
			ReaderSetupFunc: fakeRawDiskReader,
			ProviderSetupFunc: func(provider *mock.MockProvider) {
				provider.EXPECT().
					UploadImageData(gomock.Any(), imageID, expectedReaderBytes(rawFileContent)).
					Return(nil)
			},
			ExpectedError: false,
			ExpectedImage: expectedImage,
		},
		{
			Name:            "succeeds in uploading qcow2 image data",
			ReaderSetupFunc: fakeQcow2Reader,
			ProviderSetupFunc: func(provider *mock.MockProvider) {
				provider.EXPECT().
					UploadImageData(gomock.Any(), imageID, expectedReaderBytes(qcow2FileContent)).
					Return(nil)
			},
			DiskFormat:    types.ImageDiskFormatQCOW2,
			ExpectedError: false,
			ExpectedImage: expectedImage,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			mockController := gomock.NewController(t)
			defer mockController.Finish()

			mockProvider := mock.NewMockProvider(mockController)
			if fn := testCase.ProviderSetupFunc; fn != nil {
				fn(mockProvider)
			}

			ctx := t.Context()

			if fn := testCase.ContextMutateFunc; fn != nil {
				ctx = fn(ctx)
			}

			reader := testCase.ReaderSetupFunc(t)

			diskFormat := types.ImageDiskFormatRaw
			if f := testCase.DiskFormat; f != "" {
				diskFormat = f
			}

			err := uploadImageData(ctx, imageID, diskFormat, reader, mockProvider)
			require.Equal(t, testCase.ExpectedError, err != nil, "got error %s", err)
		})
	}
}
