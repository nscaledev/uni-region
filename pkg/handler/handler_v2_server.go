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
	"github.com/unikorn-cloud/region/pkg/openapi"
)

func (h *ServerHandler) GetApiV2Servers(w http.ResponseWriter, r *http.Request, params openapi.GetApiV2ServersParams) {
	result, err := h.serverClient().ListV2(r.Context(), params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *ServerHandler) PostApiV2Servers(w http.ResponseWriter, r *http.Request) {
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

func (h *ServerHandler) GetApiV2ServersServerID(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	result, err := h.serverClient().GetV2(r.Context(), serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *ServerHandler) PutApiV2ServersServerID(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
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

func (h *ServerHandler) DeleteApiV2ServersServerID(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	err := h.serverClient().DeleteV2(r.Context(), serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *ServerHandler) GetApiV2ServersServerIDSshkey(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	result, err := h.serverClient().SSHKey(r.Context(), serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *ServerHandler) PostApiV2ServersServerIDStart(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	if err := h.serverClient().StartV2(r.Context(), serverID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *ServerHandler) PostApiV2ServersServerIDStop(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	if err := h.serverClient().StopV2(r.Context(), serverID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *ServerHandler) PostApiV2ServersServerIDSoftreboot(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	if err := h.serverClient().RebootV2(r.Context(), serverID, false); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *ServerHandler) PostApiV2ServersServerIDHardreboot(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	if err := h.serverClient().RebootV2(r.Context(), serverID, true); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *ServerHandler) GetApiV2ServersServerIDConsoleoutput(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter, params openapi.GetApiV2ServersServerIDConsoleoutputParams) {
	result, err := h.serverClient().ConsoleOutputV2(r.Context(), serverID, params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *ServerHandler) GetApiV2ServersServerIDConsolesessions(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	result, err := h.serverClient().ConsoleSessionV2(r.Context(), serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *ServerHandler) PostApiV2ServersServerIDSnapshot(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	c := h.serverClient()

	var req openapi.SnapshotCreate
	if err := util.ReadJSONBody(r, &req); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	img, err := c.CreateV2Snapshot(r.Context(), serverID, &req)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusCreated, img)
}
