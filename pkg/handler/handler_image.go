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
	goerrors "errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-logr/logr"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/region/pkg/handler/image"
	"github.com/unikorn-cloud/region/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

func (h *Handler) GetApiV1OrganizationsOrganizationIDRegionsRegionIDImages(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, regionID openapi.RegionIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "region:images", identityapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := image.NewClient(h.client, h.namespace).ListImages(r.Context(), organizationID, regionID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setCacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDRegionsRegionIDImages(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, regionID openapi.RegionIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "region:images", identityapi.Create, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	var request openapi.ImageCreateRequest
	if err := util.ReadJSONBody(r, &request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := image.NewClient(h.client, h.namespace).CreateImage(r.Context(), organizationID, regionID, &request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDRegionsRegionIDImagesImageID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, regionID openapi.RegionIDParameter, imageID openapi.ImageIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "region:images", identityapi.Delete, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := image.NewClient(h.client, h.namespace).DeleteImage(r.Context(), organizationID, regionID, imageID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDRegionsRegionIDImagesImageIDData(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, regionID openapi.RegionIDParameter, imageID openapi.ImageIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "region:images", identityapi.Create, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	// Limit the number of bytes we are prepared to read as an upload, as a defensive measure.
	body := http.MaxBytesReader(w, r.Body, h.options.ImageUploadSizeLimit)
	defer body.Close()

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

	result, err := image.NewClient(h.client, h.namespace).UploadImage(r.Context(), organizationID, regionID, imageID, contentType, filedata)
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

	return partReader, partHeader.Header.Get("Content-Type"), nil
}

func mainHeaderValue(header string) string {
	before, _, _ := strings.Cut(header, ";")
	return before
}
