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

package image

import (
	"archive/tar"
	"compress/gzip"
	"context"
	goerrors "errors"
	"fmt"
	"io"
	"os"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

//nolint:cyclop // I consider this easy enough to grok.
func extractFileFromTarball(ctx context.Context, data io.Reader, format types.ImageDiskFormat) (*os.File, error) {
	var (
		expectedFilename     string
		validatingReaderFunc func(io.Reader) (io.Reader, error)
	)

	switch format {
	case types.ImageDiskFormatRaw:
		expectedFilename = "disk.raw"
		validatingReaderFunc = NewMasterBootRecordReader
	case types.ImageDiskFormatQCOW2:
		expectedFilename = "disk.qcow2"
		validatingReaderFunc = NewQCOW2Reader
	default:
		return nil, errors.OAuth2InvalidRequest("unhandled disk format").WithValues("disk_format", format)
	}

	var (
		tarReader = tar.NewReader(data)
	)

	var stagedFile *os.File

	for {
		// This gives the context a chance to be cancelled; potentially we're reading a lot of bytes here.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		header, err := tarReader.Next()

		if goerrors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return nil, err
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		if header.Name == expectedFilename {
			validatingReader, err := validatingReaderFunc(tarReader)
			if err != nil {
				return nil, err
			}

			tempFile, err := os.CreateTemp(os.TempDir(), "disk_")
			if err != nil {
				return nil, err
			}

			if _, err = io.Copy(tempFile, validatingReader); err != nil {
				return nil, err
			}

			// We've written to the end of the file; now reset to the beginning to read it.
			if _, err = tempFile.Seek(0, io.SeekStart); err != nil {
				return nil, err
			}

			stagedFile = tempFile
			// There should be only one entry in the tar file with the expected name. It's _possible_ for
			// tar files to have repeated names (see https://en.wikipedia.org/wiki/Tar_(computing)). For
			// simplicity, here I'm assuming that's not a legitimate use.
			break
		}
	}

	if stagedFile == nil {
		return nil, errors.OAuth2InvalidRequest("The provided file does not contain a valid disk image")
	}

	return stagedFile, nil
}

func uploadImageData(ctx context.Context, imageID string, diskFormat types.ImageDiskFormat, sourceReader io.Reader, provider provider) error {
	gzipReader, err := gzip.NewReader(sourceReader)
	if err != nil {
		return errors.OAuth2ServerError("The server encountered an unexpected error while receiving the image data").WithError(err)
	}

	sourceReader = gzipReader
	defer gzipReader.Close()

	// Stage the image upload into a temp file, so that we can close the request without
	// relying on our own upstream call completing.
	staged, err := extractFileFromTarball(ctx, sourceReader, diskFormat)
	if err != nil {
		return errors.OAuth2ServerError("The server encountered an unexpected error while receiving the image data").WithError(err)
	}

	defer func() {
		staged.Close()

		if err := os.Remove(staged.Name()); err != nil {
			log.FromContext(ctx).Error(err, "failed to remove temporary disk image file", "file", staged.Name())
		}
	}()

	if err = provider.UploadImageData(ctx, imageID, staged); err != nil {
		if goerrors.Is(err, types.ErrImageNotReadyForUpload) {
			err = fmt.Errorf("%w: image data has already been uploaded", ErrProviderResource)
			return errors.HTTPConflict().WithError(err)
		}

		return errors.OAuth2ServerError("The server encountered an unexpected error while uploading the image data").WithError(err)
	}

	return nil
}
