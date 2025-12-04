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

//nolint:revive // revive does not like the generated method name(s) that must be used below
package handler

import (
	"compress/gzip"
	goerrors "errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"slices"
	"strings"

	"github.com/go-logr/logr"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/region/pkg/handler/image"
	"github.com/unikorn-cloud/region/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type ImageHandler struct {
	client      client.Client
	namespace   string
	options     *Options
	getProvider image.GetProviderFunc
}

func NewImageHandler(client client.Client, namespace string, options *Options) *ImageHandler {
	return &ImageHandler{
		client:      client,
		namespace:   namespace,
		options:     options,
		getProvider: image.DefaultGetProvider,
	}
}

func (h *ImageHandler) imageClient() *image.Client {
	return image.NewClient(h.client, h.namespace, h.getProvider)
}

func (h *ImageHandler) GetApiV1OrganizationsOrganizationIDRegionsRegionIDImages(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, regionID openapi.RegionIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "region:images", identityapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.imageClient().ListImages(r.Context(), organizationID, regionID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.options.setCacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *ImageHandler) PostApiV1OrganizationsOrganizationIDRegionsRegionIDImages(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, regionID openapi.RegionIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "region:images", identityapi.Create, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	var request openapi.ImageCreateRequest
	if err := util.ReadJSONBody(r, &request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.imageClient().CreateImage(r.Context(), organizationID, regionID, &request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *ImageHandler) DeleteApiV1OrganizationsOrganizationIDRegionsRegionIDImagesImageID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, regionID openapi.RegionIDParameter, imageID openapi.ImageIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "region:images", identityapi.Delete, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.imageClient().DeleteImage(r.Context(), organizationID, regionID, imageID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *ImageHandler) PostApiV1OrganizationsOrganizationIDRegionsRegionIDImagesImageIDData(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, regionID openapi.RegionIDParameter, imageID openapi.ImageIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "region:images", identityapi.Create, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	// Limit the number of bytes we are prepared to read as an upload, as a defensive measure.
	r.Body = http.MaxBytesReader(w, r.Body, h.options.ImageUploadSizeLimit)

	if err := maybeDecompress(r); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	// In the following we are trying to determine how to proceed with the request, based on its content type and encoding.
	// We'll handle the request format here, and pass the bytes on to the client to process.
	var read func(*http.Request) (io.ReadCloser, string, error)

	contentType := mainHeaderValue(r.Header.Get("Content-Type"))

	switch contentType {
	case "multipart/form-data":
		read = parseMultipartFormData

		defer func(logger logr.Logger) {
			if err := r.MultipartForm.RemoveAll(); err != nil {
				logger.Error(err, "cleaning up after multipart/form-data parsing")
			}
		}(log.FromContext(r.Context()))
	case "application/octet-stream", "application/tar+gzip": // these can be left to the upload func to figure out
		read = func(*http.Request) (io.ReadCloser, string, error) {
			return r.Body, contentType, nil
		}
	default:
		errors.HandleError(w, r, fmt.Errorf("%w: Content-Type not handled by this endpoint", errors.ErrRequest))
		return
	}

	filedata, contentType, err := read(r)
	if err != nil {
		var e *http.MaxBytesError
		if goerrors.As(err, &e) {
			message := fmt.Sprintf("The request body exceeds the maximum allowed size of %d bytes", e.Limit)
			err = errors.HTTPRequestEntityTooLarge(message).WithError(err)
			errors.HandleError(w, r, err)

			return
		}

		err = errors.OAuth2ServerError("The server encountered an unexpected error while processing the request").WithError(err)
		errors.HandleError(w, r, err)

		return
	}

	defer filedata.Close()

	result, err := h.imageClient().UploadImage(r.Context(), organizationID, regionID, imageID, contentType, filedata)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func parseMultipartFormData(r *http.Request) (io.ReadCloser, string, error) {
	// The `0` here tells the multipart reader not to try and store any parts in memory, but to put them on disk.
	if err := r.ParseMultipartForm(0); err != nil {
		return nil, "", err
	}

	partReader, partHeader, err := r.FormFile("file")
	if err != nil {
		return nil, "", err
	}

	contentType := sniffContentType(partHeader)

	return partReader, contentType, nil
}

func mainHeaderValue(header string) string {
	before, _, _ := strings.Cut(header, ";")
	return before
}

func sniffContentType(partHeader *multipart.FileHeader) string {
	ct := partHeader.Header.Get("Content-Type")

	// Sometimes we'll get a pre-sniffed content type; sometimes we have to
	// have a guess ourselves.
	if ct == "application/octet-stream" {
		switch {
		case strings.HasSuffix(partHeader.Filename, ".tar.gz"):
			return "application/tar+gzip"
		case strings.HasSuffix(partHeader.Filename, ".tar"):
			return "application/tar"
		}
	}

	return ct
}

func maybeDecompress(r *http.Request) error {
	// It's non-standard to set this on a request -- you would usually set `Accept-Encoding` on a **request**
	// to indicate you can handle a compressed **response**, then the server can gzip it and set `Content-Encoding`
	// on its response. But it's helpful for CLIs to be able to save bandwidth by compressing image files,
	// so we support it.
	if slices.Contains(r.Header.Values("Content-Encoding"), "gzip") {
		gzipReader, err := gzip.NewReader(r.Body)
		if err != nil {
			httperr := fmt.Errorf("%w: Content-Encoding indicated gzipped content, but not a valid gzip", errors.ErrRequest)
			return httperr
		}

		r.Body = gzipReader
	}

	return nil
}
