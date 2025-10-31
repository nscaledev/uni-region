package region_test

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

	"github.com/unikorn-cloud/region/pkg/handler/region"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	"github.com/unikorn-cloud/region/pkg/providers/types/mock"

	"k8s.io/utils/ptr"
)

//nolint:cyclop,gocyclo,gocognit,maintidx
func TestUploadImageData(t *testing.T) {
	t.Parallel()

	imageID := "b3796b32-57d3-40cf-b43e-d227c0c5a70b"

	providerImage := &types.Image{
		ID:             "b3796b32-57d3-40cf-b43e-d227c0c5a70b",
		Name:           "test-image",
		OrganizationID: ptr.To("3d84f1f2-4a41-44d5-98ab-8b282d00abb9"),
		Created:        time.Date(2025, 10, 31, 12, 0, 0, 0, time.UTC),
		Modified:       time.Date(2025, 10, 31, 12, 0, 0, 0, time.UTC),
		SizeGiB:        25,
		Virtualization: types.Virtualized,
		GPU: &types.ImageGPU{
			Vendor: types.Nvidia,
			Driver: "525.85.05",
			Models: []string{
				"A100",
				"H100",
				"H200",
			},
		},
		OS: types.ImageOS{
			Kernel:   types.Linux,
			Family:   types.Debian,
			Distro:   types.Ubuntu,
			Variant:  ptr.To("server"),
			Codename: ptr.To("alpha"),
			Version:  "0.1.0",
		},
		Packages: ptr.To(types.ImagePackages{
			"kubernetes": "v1.25.6",
		}),
		Active: false,
	}

	expectedImage := &openapi.Image{
		Metadata: openapi.ImageMetadata{
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
				Vendor: openapi.NVIDIA,
			},
			Os: openapi.ImageOS{
				Codename: ptr.To("alpha"),
				Distro:   openapi.Ubuntu,
				Family:   openapi.Debian,
				Kernel:   openapi.Linux,
				Variant:  ptr.To("server"),
				Version:  "0.1.0",
			},
			SizeGiB: 25,
			SoftwareVersions: ptr.To(openapi.SoftwareVersions{
				"kubernetes": "v1.25.6",
			}),
			Virtualization: openapi.Virtualized,
		},
	}

	noopContextMutateFunc := func(ctx context.Context) context.Context {
		return ctx
	}

	noopProviderSetupFunc := func(provider *mock.MockProvider) {

	}

	defaultReaderSetupFunc := func(t *testing.T) io.Reader {
		t.Helper()

		var buf bytes.Buffer

		gzipWriter := gzip.NewWriter(&buf)

		tarWriter := tar.NewWriter(gzipWriter)

		tarContent := []byte("this is a test disk image content")

		tarHeader := &tar.Header{
			Name: "disk.raw",
			Mode: 0600,
			Size: int64(len(tarContent)),
		}

		if err := tarWriter.WriteHeader(tarHeader); err != nil {
			require.NoError(t, err)
		}

		if _, err := tarWriter.Write(tarContent); err != nil {
			require.NoError(t, err)
		}

		if err := tarWriter.Close(); err != nil {
			require.NoError(t, err)
		}

		if err := gzipWriter.Close(); err != nil {
			require.NoError(t, err)
		}

		return &buf
	}

	type TestCase struct {
		Name              string
		ContextMutateFunc func(ctx context.Context) context.Context
		ReaderSetupFunc   func(t *testing.T) io.Reader
		ProviderSetupFunc func(provider *mock.MockProvider)
		ExpectedError     bool
		ExpectedImage     *openapi.Image
	}

	testCases := []TestCase{
		{
			Name:              "fails to create gzip reader",
			ContextMutateFunc: noopContextMutateFunc,
			ReaderSetupFunc: func(t *testing.T) io.Reader {
				t.Helper()

				data := []byte("this is not valid gzip data")

				return bytes.NewBuffer(data)
			},
			ProviderSetupFunc: noopProviderSetupFunc,
			ExpectedError:     true,
			ExpectedImage:     nil,
		},
		{
			Name:              "fails to read invalid tar data",
			ContextMutateFunc: noopContextMutateFunc,
			ReaderSetupFunc: func(t *testing.T) io.Reader {
				t.Helper()

				var buf bytes.Buffer

				gzipWriter := gzip.NewWriter(&buf)

				data := []byte("this is not valid tar data")
				if _, err := gzipWriter.Write(data); err != nil {
					require.NoError(t, err)
				}

				if err := gzipWriter.Close(); err != nil {
					require.NoError(t, err)
				}

				return &buf
			},
			ProviderSetupFunc: noopProviderSetupFunc,
			ExpectedError:     true,
			ExpectedImage:     nil,
		},
		{
			Name:              "fails to parse tar header",
			ContextMutateFunc: noopContextMutateFunc,
			ReaderSetupFunc: func(t *testing.T) io.Reader {
				t.Helper()

				base64Data := "EwMwMBMDLTgyMTk1MDI5NnQTE4NzfINzEzAwcXfhZrsDMDAwAAAAEDAxMRNz9DEwMTAwdBMTg3N8g3NzADATc3yDc3P0eFMTc/QxMDEwMHQTE4NzfINzc/QwE3N8g3Nz9HFTMNR0MBMwMHEw9DAAAAAQMDGAABAwMTETc/QxMDH0MHQTMDBx1OFmuwMAAAD/gICAADExNTYyMQAgMBP///+AMTAwdHhTMDB0MBMwMHF3MDEwMTAwdBMTg3N8g3Nz9HhTMDB0MBMwMHF34Wa7AzAwMAAAABAwMTETc/QxMDEwMHQTE4NzfINzc/QwE3N8g3Nz9HhTE3P0MTAxMDB0ExODc3yDc3MwMBNzfINzczB4UzAwdDATMDBxMDAAgAAAEDAxc/QxMDEwMHQTAAAAIOFmuwMwNAAAABAwMTET////gDEwMHR4UzAwdDATMDBxd+FmuwMwMDAAAAAQMDExE3ODc3P0eFMTc/QxMDEwMHQTE4NzfINzc/QzMTEwMzM2MjQ4NDYxMjgzODBzfINzc/R4UzAwdDATMDBxMDAwAAAAEDAxAAAQMDExE3P0MTAxMDB0EzAwcdThZrsDMDQAAAAQg3N8g3Nz9DATc3yDc3P0eFMwMHQwEzAwcTAwMAAAABAwMQAAEDAxMRNz9DEwMTAwdBMwMHgw4Wa7AwAAEDA="

				bs, err := base64.StdEncoding.DecodeString(base64Data)
				if err != nil {
					require.NoError(t, err)
				}

				var buf bytes.Buffer

				gzipWriter := gzip.NewWriter(&buf)

				if _, err := gzipWriter.Write(bs); err != nil {
					require.NoError(t, err)
				}

				if err := gzipWriter.Close(); err != nil {
					require.NoError(t, err)
				}

				return &buf
			},
			ProviderSetupFunc: noopProviderSetupFunc,
			ExpectedError:     true,
			ExpectedImage:     nil,
		},
		{
			Name:              "fails to parse oversized tar header",
			ContextMutateFunc: noopContextMutateFunc,
			ReaderSetupFunc: func(t *testing.T) io.Reader {
				t.Helper()

				base64Data := "QlpoOTFBWSZTWcRfsUcAAFDfkOiQQAH/xgBASEBmQF5AAEAICCAAhBtRU9NNIPUaNPUeppo0PUCqVD1AaADEZNHiiS+Wdi697kCxx9qIT3GF8mQnSKvg2sFNkHGCdCG6MqN4zcKTytwhtItXKSj3rOWtbdRUbOOwCADGRCIAjQnVWdKV05Sa6fk0smrPvHAIAfxdyRThQkMRfsUc"

				bs, err := base64.StdEncoding.DecodeString(base64Data)
				if err != nil {
					require.NoError(t, err)
				}

				data := bzip2.NewReader(bytes.NewReader(bs))

				var buf bytes.Buffer

				gzipWriter := gzip.NewWriter(&buf)

				//nolint:gosec
				if _, err := io.Copy(gzipWriter, data); err != nil {
					require.NoError(t, err)
				}

				if err := gzipWriter.Close(); err != nil {
					require.NoError(t, err)
				}

				return &buf
			},
			ProviderSetupFunc: noopProviderSetupFunc,
			ExpectedError:     true,
			ExpectedImage:     nil,
		},
		{
			Name:              "fails to process multiple disk files",
			ContextMutateFunc: noopContextMutateFunc,
			ReaderSetupFunc: func(t *testing.T) io.Reader {
				t.Helper()

				var buf bytes.Buffer

				gzipWriter := gzip.NewWriter(&buf)

				tarWriter := tar.NewWriter(gzipWriter)

				tarHeader := &tar.Header{
					Typeflag: tar.TypeDir,
					Name:     "empty-dir/",
					Mode:     0755,
				}

				if err := tarWriter.WriteHeader(tarHeader); err != nil {
					require.NoError(t, err)
				}

				files := map[string][]byte{
					"disk.raw":   []byte("abcdefg"),
					"disk.qcow2": []byte("xyz"),
				}

				for name, content := range files {
					tarHeader = &tar.Header{
						Name: name,
						Mode: 0600,
						Size: int64(len(content)),
					}

					if err := tarWriter.WriteHeader(tarHeader); err != nil {
						require.NoError(t, err)
					}

					if _, err := tarWriter.Write(content); err != nil {
						require.NoError(t, err)
					}
				}

				if err := tarWriter.Close(); err != nil {
					require.NoError(t, err)
				}

				if err := gzipWriter.Close(); err != nil {
					require.NoError(t, err)
				}

				return &buf
			},
			ProviderSetupFunc: noopProviderSetupFunc,
			ExpectedError:     true,
			ExpectedImage:     nil,
		},
		{
			Name: "fails to copy data into temporary file after context cancellation",
			ContextMutateFunc: func(ctx context.Context) context.Context {
				ctx, cancel := context.WithCancel(ctx)
				cancel()

				return ctx
			},
			ReaderSetupFunc: func(t *testing.T) io.Reader {
				t.Helper()

				var buf bytes.Buffer

				gzipWriter := gzip.NewWriter(&buf)

				tarWriter := tar.NewWriter(gzipWriter)

				tarContent := []byte("this is a test disk image content")

				tarHeader := &tar.Header{
					Name: "disk.raw",
					Mode: 0600,
					Size: int64(len(tarContent)),
				}

				if err := tarWriter.WriteHeader(tarHeader); err != nil {
					require.NoError(t, err)
				}

				if _, err := tarWriter.Write(tarContent); err != nil {
					require.NoError(t, err)
				}

				if err := tarWriter.Close(); err != nil {
					require.NoError(t, err)
				}

				if err := gzipWriter.Close(); err != nil {
					require.NoError(t, err)
				}

				return &buf
			},
			ProviderSetupFunc: noopProviderSetupFunc,
			ExpectedError:     true,
			ExpectedImage:     nil,
		},
		{
			Name:              "fails to find disk file in tar archive",
			ContextMutateFunc: noopContextMutateFunc,
			ReaderSetupFunc: func(t *testing.T) io.Reader {
				t.Helper()

				var buf bytes.Buffer

				gzipWriter := gzip.NewWriter(&buf)

				tarWriter := tar.NewWriter(gzipWriter)

				tarContent := []byte("this is some random file content")

				tarHeader := &tar.Header{
					Name: "random.txt",
					Mode: 0600,
					Size: int64(len(tarContent)),
				}

				if err := tarWriter.WriteHeader(tarHeader); err != nil {
					require.NoError(t, err)
				}

				if _, err := tarWriter.Write(tarContent); err != nil {
					require.NoError(t, err)
				}

				if err := tarWriter.Close(); err != nil {
					require.NoError(t, err)
				}

				if err := gzipWriter.Close(); err != nil {
					require.NoError(t, err)
				}

				return &buf
			},
			ProviderSetupFunc: noopProviderSetupFunc,
			ExpectedError:     true,
			ExpectedImage:     nil,
		},
		{
			Name:              "fails to upload image due to upload conflict",
			ContextMutateFunc: noopContextMutateFunc,
			ReaderSetupFunc:   defaultReaderSetupFunc,
			ProviderSetupFunc: func(provider *mock.MockProvider) {
				expectedReader := gomock.Cond[io.Reader](func(reader io.Reader) bool {
					actual, err := io.ReadAll(reader)
					if err != nil {
						return false
					}

					expected := []byte("this is a test disk image content")

					return bytes.Equal(actual, expected)
				})

				provider.EXPECT().
					UploadImage(gomock.Any(), imageID, expectedReader).
					Return(gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusConflict})
			},
			ExpectedError: true,
			ExpectedImage: nil,
		},
		{
			Name:              "fails to upload image due to unexpected error",
			ContextMutateFunc: noopContextMutateFunc,
			ReaderSetupFunc:   defaultReaderSetupFunc,
			ProviderSetupFunc: func(provider *mock.MockProvider) {
				expectedReader := gomock.Cond[io.Reader](func(reader io.Reader) bool {
					actual, err := io.ReadAll(reader)
					if err != nil {
						return false
					}

					expected := []byte("this is a test disk image content")

					return bytes.Equal(actual, expected)
				})

				provider.EXPECT().
					UploadImage(gomock.Any(), imageID, expectedReader).
					Return(gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusInternalServerError})
			},
			ExpectedError: true,
			ExpectedImage: nil,
		},
		{
			Name:              "fails to finalize image",
			ContextMutateFunc: noopContextMutateFunc,
			ReaderSetupFunc:   defaultReaderSetupFunc,
			ProviderSetupFunc: func(provider *mock.MockProvider) {
				expectedReader := gomock.Cond[io.Reader](func(reader io.Reader) bool {
					actual, err := io.ReadAll(reader)
					if err != nil {
						return false
					}

					expected := []byte("this is a test disk image content")

					return bytes.Equal(actual, expected)
				})

				provider.EXPECT().
					UploadImage(gomock.Any(), imageID, expectedReader).
					Return(nil)

				provider.EXPECT().
					FinalizeImage(gomock.Any(), imageID).
					Return(nil, gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusInternalServerError})
			},
			ExpectedError: true,
			ExpectedImage: nil,
		},
		{
			Name:              "succeeds in uploading image data",
			ContextMutateFunc: noopContextMutateFunc,
			ReaderSetupFunc:   defaultReaderSetupFunc,
			ProviderSetupFunc: func(provider *mock.MockProvider) {
				expectedReader := gomock.Cond[io.Reader](func(reader io.Reader) bool {
					actual, err := io.ReadAll(reader)
					if err != nil {
						return false
					}

					expected := []byte("this is a test disk image content")

					return bytes.Equal(actual, expected)
				})

				provider.EXPECT().
					UploadImage(gomock.Any(), imageID, expectedReader).
					Return(nil)

				provider.EXPECT().
					FinalizeImage(gomock.Any(), imageID).
					Return(providerImage, nil)
			},
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
			testCase.ProviderSetupFunc(mockProvider)

			ctx := testCase.ContextMutateFunc(t.Context())
			reader := testCase.ReaderSetupFunc(t)

			actualImage, err := region.UploadImageData(ctx, imageID, reader, mockProvider)
			require.Equal(t, testCase.ExpectedError, err != nil)
			require.Equal(t, testCase.ExpectedImage, actualImage)
		})
	}
}
