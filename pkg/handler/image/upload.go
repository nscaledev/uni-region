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

package image

import (
	"archive/tar"
	"compress/gzip"
	"context"
	goerrors "errors"
	"io"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/region/pkg/providers/types"
)

// uploadFileFunc is the common denominator for what to do with image file data,
// once it's been extracted from the request.
type uploadFileFunc func(context.Context, io.Reader) error

func dispatchUpload(ctx context.Context, contentType string, diskFormat types.ImageDiskFormat, data io.Reader, k uploadFileFunc) error {
	switch contentType {
	case "application/tar+gzip":
		// This one needs to know the filename to look for, so diskFormat is passed on.
		return extractFileFromTarGzip(ctx, data, diskFormat, k)
	case "application/octet-stream":
		return checkReaderFormat(ctx, diskFormat, data, k)
	}

	return errors.OAuth2InvalidRequest("unrecognized content type").WithValues("content-type", contentType)
}

// checkReaderFormat makes sure the given reader looks like the disk format specified, and calls `k` if it looks OK.
func checkReaderFormat(ctx context.Context, format types.ImageDiskFormat, data io.Reader, k uploadFileFunc) error {
	switch format {
	case types.ImageDiskFormatRaw:
		reader, err := NewMasterBootRecordReader(data)
		if err != nil {
			return err
		}

		return k(ctx, reader)
	case types.ImageDiskFormatQCOW2:
		reader, err := NewQCOW2Reader(data)
		if err != nil {
			return err
		}

		return k(ctx, reader)
	}

	return errors.OAuth2InvalidRequest("unhandled disk format").WithValues("disk_format", format)
}

// extractFileFromTarGzip finds the file in question in a .tar.gz, and passes it to the
// next stage `k`. It's done this way so that this func can do its own tidy-up.
func extractFileFromTarGzip(ctx context.Context, source io.Reader, format types.ImageDiskFormat, k uploadFileFunc) error {
	gzipReader, err := gzip.NewReader(source)
	if err != nil {
		return errors.OAuth2InvalidRequest("The request does not have valid image data").WithError(err)
	}
	defer gzipReader.Close()

	return extractFileFromTarball(ctx, gzipReader, format, k)
}

// extractFileFromTarball is a special case of getting the image file contents from a request;
// it assumes the bytes to be read are a tar file containing a file, named either
// `disk.raw“ or `disk.qcow2` (as determined by the disk format given when the image record
// was created). This seems a bit unusual, but is supported by e.g., GCP:
//
//	https://docs.cloud.google.com/migrate/virtual-machines/docs/5.0/migrate/image_import)
//
//nolint:cyclop // I consider this easy enough to grok.
func extractFileFromTarball(ctx context.Context, data io.Reader, format types.ImageDiskFormat, k uploadFileFunc) error {
	var (
		expectedFilename string
	)

	switch format {
	case types.ImageDiskFormatRaw:
		expectedFilename = "disk.raw"
	case types.ImageDiskFormatQCOW2:
		expectedFilename = "disk.qcow2"
	default:
		return errors.OAuth2InvalidRequest("unhandled disk format").WithValues("disk_format", format)
	}

	tarReader := tar.NewReader(data)

	for {
		// This gives the context a chance to be cancelled; potentially we're reading a lot of bytes here.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		header, err := tarReader.Next()

		if goerrors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return err
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		if header.Name == expectedFilename {
			return checkReaderFormat(ctx, format, tarReader, k)
		}
	}

	return errors.OAuth2InvalidRequest("The provided file does not contain a disk image of the expected format").WithValues("format", format)
}
