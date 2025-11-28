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
	"net/http"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/region/pkg/handler/image"
	"github.com/unikorn-cloud/region/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
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
