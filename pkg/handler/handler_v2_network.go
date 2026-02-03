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

//nolint:revive,dupl // dupl likes to say this is a duplicate of securitygroup_v2; which is not unreasonable, but hard to remedy.
package handler

import (
	"net/http"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

func (h *NetworkHandler) GetApiV2Networks(w http.ResponseWriter, r *http.Request, params openapi.GetApiV2NetworksParams) {
	result, err := h.networkClient().ListV2(r.Context(), params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *NetworkHandler) PostApiV2Networks(w http.ResponseWriter, r *http.Request) {
	request := &openapi.NetworkV2Create{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.networkClient().CreateV2(r.Context(), request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *NetworkHandler) GetApiV2NetworksNetworkID(w http.ResponseWriter, r *http.Request, networkID openapi.NetworkIDParameter) {
	result, err := h.networkClient().GetV2(r.Context(), networkID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *NetworkHandler) PutApiV2NetworksNetworkID(w http.ResponseWriter, r *http.Request, networkID openapi.NetworkIDParameter) {
	request := &openapi.NetworkV2Update{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.networkClient().Update(r.Context(), networkID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusAccepted, result)
}

func (h *NetworkHandler) DeleteApiV2NetworksNetworkID(w http.ResponseWriter, r *http.Request, networkID openapi.NetworkIDParameter) {
	if err := h.networkClient().DeleteV2(r.Context(), networkID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}
