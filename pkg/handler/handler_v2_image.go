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

//nolint:revive
package handler

import (
	"net/http"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/image"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

type ImageV2Handler struct {
	common.ClientArgs
	options *Options
}

func NewImageV2Handler(clientArgs common.ClientArgs, options *Options) *ImageV2Handler {
	return &ImageV2Handler{
		ClientArgs: clientArgs,
		options:    options,
	}
}

func (h *ImageV2Handler) imageClient() *image.Client {
	return image.NewClient(h.ClientArgs)
}

func (h *ImageV2Handler) GetApiV2RegionsRegionIDImages(w http.ResponseWriter, r *http.Request, regionID openapi.RegionIDParameter, params openapi.GetApiV2RegionsRegionIDImagesParams) {
	result, err := h.imageClient().QueryImages(r.Context(), regionID, params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.options.setCacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}
