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

func (h *Handler) GetApiV2Servers(w http.ResponseWriter, r *http.Request, params openapi.GetApiV2ServersParams) {
	result, err := h.serverClient().ListV2(r.Context(), params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV2Servers(w http.ResponseWriter, r *http.Request) {
	request := &openapi.ServerV2Create{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serverClient().CreateV2(r.Context(), request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) GetApiV2ServersServerID(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	result, err := h.serverClient().GetV2(r.Context(), serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV2ServersServerID(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	request := &openapi.ServerV2Update{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serverClient().UpdateV2(r.Context(), serverID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusAccepted, result)
}

func (h *Handler) DeleteApiV2ServersServerID(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	err := h.serverClient().DeleteV2(r.Context(), serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV2ServersServerIDSshkey(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	result, err := h.serverClient().SSHKey(r.Context(), serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV2ServersServerIDStart(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	if err := h.serverClient().StartV2(r.Context(), serverID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PostApiV2ServersServerIDStop(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	if err := h.serverClient().StopV2(r.Context(), serverID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PostApiV2ServersServerIDSoftreboot(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	if err := h.serverClient().RebootV2(r.Context(), serverID, false); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PostApiV2ServersServerIDHardreboot(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	if err := h.serverClient().RebootV2(r.Context(), serverID, true); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV2ServersServerIDConsoleoutput(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter, params openapi.GetApiV2ServersServerIDConsoleoutputParams) {
	result, err := h.serverClient().ConsoleOutputV2(r.Context(), serverID, params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV2ServersServerIDConsolesessions(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	result, err := h.serverClient().ConsoleSessionV2(r.Context(), serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

// todo(schristoff): logic for identity has been re-wrangled
// between v1 and v2. figure it out ¯\_(ツ)_/¯
func (h *Handler) storageClient() *storage.Client {
	return storage.New(h.client, h.namespace, h.getIdentityAPIClient)
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
func (h *Handler) DeleteApiV2StorageFilestorageFilestorageID(w http.ResponseWriter, r *http.Request, filestorageID openapi.FilestorageIDParameter) {
	if err := h.storageClient().Delete(r.Context(), filestorageID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}
func (h *Handler) GetApiV2StorageFilestorageFilestorageID(w http.ResponseWriter, r *http.Request, filestorageID openapi.FilestorageIDParameter) {
	result, err := h.storageClient().Get(r.Context(), filestorageID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}
func (h *Handler) PutApiV2StorageFilestorageFilestorageID(w http.ResponseWriter, r *http.Request, fileStorageID openapi.FilestorageIDParameter) {
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

	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}
