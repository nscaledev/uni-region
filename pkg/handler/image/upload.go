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
	"io"
	"os"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// uploadFileFunc is the common denominator for what to do with image file data,
// once it's been extracted from the request.
type uploadFileFunc func(context.Context, io.Reader) error

func dispatchUpload(ctx context.Context, contentType string, diskFormat types.ImageDiskFormat, data io.Reader, k uploadFileFunc) error {
	switch contentType {
	case "application/tar+gzip":
		return extractFileFromTarGzip(ctx, data, diskFormat, k)
	case "application/octet-stream":
		return k(ctx, data)
	}

	return errors.OAuth2InvalidRequest("unrecognized content type").WithValues("content-type", contentType)
}

// extractFileFromTarGzip finds the file in question in a .tar.gz, and passes it to the
// next stage `k`. It's done this way so that this func can do its own tidy-up.
func extractFileFromTarGzip(ctx context.Context, source io.Reader, format types.ImageDiskFormat, k uploadFileFunc) error {
	gzipReader, err := gzip.NewReader(source)
	if err != nil {
		return errors.OAuth2InvalidRequest("The request does not have valid image data").WithError(err)
	}
	defer gzipReader.Close()

	staged, err := extractFileFromTarball(ctx, gzipReader, format)
	if err != nil {
		return err
	}

	defer func() {
		staged.Close()

		if err := os.Remove(staged.Name()); err != nil {
			log.FromContext(ctx).Error(err, "failed to remove temporary disk image file", "file", staged.Name())
		}
	}()

	return k(ctx, staged)
}

// extractFileFromTarball is a special case of getting the image file contents from a request;
// it assumes the bytes to be read are a tar file containing a file, named either
// `disk.raw“ or `disk.qcow2` (as determined by the disk format given when the image record
// was created). This seems a bit unusual, but is supported by e.g., GCP:
//
//	https://docs.cloud.google.com/migrate/virtual-machines/docs/5.0/migrate/image_import)
//
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
				return nil, errors.OAuth2InvalidRequest("the file is not a valid image of the format given").WithError(err)
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
		return nil, errors.OAuth2InvalidRequest("The provided file does not contain a disk image of the expected format").WithValues("format", format)
	}

	return stagedFile, nil
}
