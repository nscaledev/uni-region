/*
Copyright 2024-2025 the Unikorn Authors.
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

//nolint:revive,dupl // dupl likes to say this is a duplicate of network_v2; which is not unreasonable, but hard to remedy.
package handler

import (
	"net/http"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

func (h *SecurityGroupHandler) GetApiV2Securitygroups(w http.ResponseWriter, r *http.Request, params openapi.GetApiV2SecuritygroupsParams) {
	result, err := h.securityGroupClient().ListV2(r.Context(), params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *SecurityGroupHandler) PostApiV2Securitygroups(w http.ResponseWriter, r *http.Request) {
	request := &openapi.SecurityGroupV2Create{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.securityGroupClient().CreateV2(r.Context(), request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *SecurityGroupHandler) GetApiV2SecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, securityGroupID openapi.SecurityGroupIDParameter) {
	result, err := h.securityGroupClient().GetV2(r.Context(), securityGroupID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *SecurityGroupHandler) PutApiV2SecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, securityGroupID openapi.SecurityGroupIDParameter) {
	request := &openapi.SecurityGroupV2Update{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.securityGroupClient().UpdateV2(r.Context(), securityGroupID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusAccepted, result)
}

func (h *SecurityGroupHandler) DeleteApiV2SecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, securityGroupID openapi.SecurityGroupIDParameter) {
	if err := h.securityGroupClient().DeleteV2(r.Context(), securityGroupID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}
