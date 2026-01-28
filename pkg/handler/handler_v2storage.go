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
	"github.com/unikorn-cloud/region/pkg/handler/storage"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

type StorageHandler common.Handler

func NewStorageHandler(clientArgs common.ClientArgs) *StorageHandler {
	return &StorageHandler{
		ClientArgs: clientArgs,
	}
}

func (h *StorageHandler) storageClient() *storage.Client {
	return storage.New(h.ClientArgs)
}

func (h *StorageHandler) GetApiV2Filestorage(w http.ResponseWriter, r *http.Request, params openapi.GetApiV2FilestorageParams) {
	result, err := h.storageClient().ListV2(r.Context(), params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *StorageHandler) PostApiV2Filestorage(w http.ResponseWriter, r *http.Request) {
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

func (h *StorageHandler) DeleteApiV2FilestorageFilestorageID(w http.ResponseWriter, r *http.Request, filestorageID openapi.FilestorageIDParameter) {
	if err := h.storageClient().Delete(r.Context(), filestorageID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *StorageHandler) GetApiV2FilestorageFilestorageID(w http.ResponseWriter, r *http.Request, filestorageID openapi.FilestorageIDParameter) {
	result, err := h.storageClient().Get(r.Context(), filestorageID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *StorageHandler) PutApiV2FilestorageFilestorageID(w http.ResponseWriter, r *http.Request, fileStorageID openapi.FilestorageIDParameter) {
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

func (h *StorageHandler) GetApiV2Filestorageclasses(w http.ResponseWriter, r *http.Request, params openapi.GetApiV2FilestorageclassesParams) {
	result, err := h.storageClient().ListClasses(r.Context(), params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}
