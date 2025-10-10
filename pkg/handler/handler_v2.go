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
	"github.com/unikorn-cloud/region/pkg/handler/storage"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

func (h *Handler) GetApiV2Networks(w http.ResponseWriter, r *http.Request, params openapi.GetApiV2NetworksParams) {
	result, err := h.networkClient().ListV2(r.Context(), params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV2Networks(w http.ResponseWriter, r *http.Request) {
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

func (h *Handler) GetApiV2NetworksNetworkID(w http.ResponseWriter, r *http.Request, networkID openapi.NetworkIDParameter) {
	result, err := h.networkClient().GetV2(r.Context(), networkID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV2NetworksNetworkID(w http.ResponseWriter, r *http.Request, networkID openapi.NetworkIDParameter) {
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

func (h *Handler) DeleteApiV2NetworksNetworkID(w http.ResponseWriter, r *http.Request, networkID openapi.NetworkIDParameter) {
	if err := h.networkClient().DeleteV2(r.Context(), networkID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PutApiV2NetworksNetworkIDReferencesReference(w http.ResponseWriter, r *http.Request, networkID openapi.NetworkIDParameter, reference openapi.ReferenceParameter) {
	if err := h.networkClient().ReferenceCreateV2(r.Context(), networkID, reference); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) DeleteApiV2NetworksNetworkIDReferencesReference(w http.ResponseWriter, r *http.Request, networkID openapi.NetworkIDParameter, reference openapi.ReferenceParameter) {
	if err := h.networkClient().ReferenceDeleteV2(r.Context(), networkID, reference); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) GetApiV2Securitygroups(w http.ResponseWriter, r *http.Request, params openapi.GetApiV2SecuritygroupsParams) {
	result, err := h.securityGroupClient().ListV2(r.Context(), params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV2Securitygroups(w http.ResponseWriter, r *http.Request) {
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

func (h *Handler) GetApiV2SecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, securityGroupID openapi.SecurityGroupIDParameter) {
	result, err := h.securityGroupClient().GetV2(r.Context(), securityGroupID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV2SecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, securityGroupID openapi.SecurityGroupIDParameter) {
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

func (h *Handler) DeleteApiV2SecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, securityGroupID openapi.SecurityGroupIDParameter) {
	if err := h.securityGroupClient().DeleteV2(r.Context(), securityGroupID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) storageClient() *storage.Client {
	return storage.New(h.ClientArgs)
}

func (h *Handler) GetApiV2Filestorage(w http.ResponseWriter, r *http.Request, params openapi.GetApiV2FilestorageParams) {
	result, err := h.storageClient().ListV2(r.Context(), params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV2Filestorage(w http.ResponseWriter, r *http.Request) {
	request := &openapi.StorageV2Create{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.storageClient().CreateV2(r.Context(), request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) DeleteApiV2FilestorageFilestorageID(w http.ResponseWriter, r *http.Request, filestorageID openapi.FilestorageIDParameter) {
	if err := h.storageClient().Delete(r.Context(), filestorageID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV2FilestorageFilestorageID(w http.ResponseWriter, r *http.Request, filestorageID openapi.FilestorageIDParameter) {
	result, err := h.storageClient().Get(r.Context(), filestorageID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV2FilestorageFilestorageID(w http.ResponseWriter, r *http.Request, fileStorageID openapi.FilestorageIDParameter) {
	request := &openapi.StorageV2Update{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.storageClient().Update(r.Context(), fileStorageID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusAccepted, result)
}

func (h *Handler) GetApiV2Filestorageclasses(w http.ResponseWriter, r *http.Request, params openapi.GetApiV2FilestorageclassesParams) {
	result, err := h.storageClient().ListClasses(r.Context(), params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}
