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

	"github.com/unikorn-cloud/region/pkg/openapi"
)

type ImageV2Handler struct {
}

func NewImageV2Handler() *ImageV2Handler {
	return &ImageV2Handler{}
}

func (*ImageV2Handler) GetApiV2RegionsRegionIDImages(w http.ResponseWriter, r *http.Request, regionID openapi.RegionIDParameter, params openapi.GetApiV2RegionsRegionIDImagesParams) {
	w.WriteHeader(http.StatusInternalServerError)
}
