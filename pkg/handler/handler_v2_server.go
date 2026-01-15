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
	"github.com/unikorn-cloud/region/pkg/handler/server"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

type ServerV2Handler struct {
	common.ClientArgs
	getProvider server.GetProviderFunc
}

func NewServerV2Handler(clientArgs common.ClientArgs) *ServerV2Handler {
	return &ServerV2Handler{
		ClientArgs:  clientArgs,
		getProvider: server.DefaultGetProvider,
	}
}

func (h *ServerV2Handler) serverV2Client() *server.ClientV2 {
	return server.NewClientV2(h.ClientArgs, h.getProvider)
}

func (h *ServerV2Handler) GetApiV2Servers(w http.ResponseWriter, r *http.Request, params openapi.GetApiV2ServersParams) {
	result, err := h.serverV2Client().ListV2(r.Context(), params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *ServerV2Handler) PostApiV2Servers(w http.ResponseWriter, r *http.Request) {
	request := &openapi.ServerV2Create{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serverV2Client().CreateV2(r.Context(), request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *ServerV2Handler) GetApiV2ServersServerID(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	result, err := h.serverV2Client().GetV2(r.Context(), serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *ServerV2Handler) PutApiV2ServersServerID(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	request := &openapi.ServerV2Update{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serverV2Client().UpdateV2(r.Context(), serverID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusAccepted, result)
}

func (h *ServerV2Handler) DeleteApiV2ServersServerID(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	err := h.serverV2Client().DeleteV2(r.Context(), serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *ServerV2Handler) GetApiV2ServersServerIDSshkey(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	result, err := h.serverV2Client().SSHKey(r.Context(), serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *ServerV2Handler) PostApiV2ServersServerIDStart(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	if err := h.serverV2Client().StartV2(r.Context(), serverID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *ServerV2Handler) PostApiV2ServersServerIDStop(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	if err := h.serverV2Client().StopV2(r.Context(), serverID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *ServerV2Handler) PostApiV2ServersServerIDSoftreboot(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	if err := h.serverV2Client().RebootV2(r.Context(), serverID, false); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *ServerV2Handler) PostApiV2ServersServerIDHardreboot(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	if err := h.serverV2Client().RebootV2(r.Context(), serverID, true); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *ServerV2Handler) GetApiV2ServersServerIDConsoleoutput(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter, params openapi.GetApiV2ServersServerIDConsoleoutputParams) {
	result, err := h.serverV2Client().ConsoleOutputV2(r.Context(), serverID, params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *ServerV2Handler) GetApiV2ServersServerIDConsolesessions(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	result, err := h.serverV2Client().ConsoleSessionV2(r.Context(), serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *ServerV2Handler) PostApiV2ServersServerIDSnapshot(w http.ResponseWriter, r *http.Request, serverID openapi.ServerIDParameter) {
	c := h.serverV2Client()

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
