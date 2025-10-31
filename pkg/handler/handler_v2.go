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
	"slices"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

func (h *Handler) GetApiV2OrganizationsOrganizationIDNetworks(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, params openapi.GetApiV2OrganizationsOrganizationIDNetworksParams) {
	ctx := r.Context()

	result, err := h.networkClient().ListV2Admin(ctx, organizationID, params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result = slices.DeleteFunc(result, func(resource openapi.NetworkV2Read) bool {
		return rbac.AllowProjectScope(ctx, "region:networks:v2", identityapi.Read, organizationID, resource.Metadata.ProjectId) != nil
	})

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV2OrganizationsOrganizationIDProjectsProjectIDNetworks(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, params openapi.GetApiV2OrganizationsOrganizationIDProjectsProjectIDNetworksParams) {
	if err := rbac.AllowProjectScope(r.Context(), "region:networks:v2", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.networkClient().ListV2(r.Context(), organizationID, projectID, params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV2OrganizationsOrganizationIDProjectsProjectIDNetworks(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:networks:v2", identityapi.Create, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.NetworkV2Write{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.networkClient().CreateV2(r.Context(), organizationID, projectID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) GetApiV2OrganizationsOrganizationIDProjectsProjectIDNetworksNetworkID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, networkID openapi.NetworkIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:networks:v2", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.networkClient().GetV2(r.Context(), organizationID, projectID, networkID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) DeleteApiV2OrganizationsOrganizationIDProjectsProjectIDNetworksNetworkID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, networkID openapi.NetworkIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:networks:v2", identityapi.Delete, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.networkClient().DeleteV2(r.Context(), organizationID, projectID, networkID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV2OrganizationsOrganizationIDSecuritygroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, params openapi.GetApiV2OrganizationsOrganizationIDSecuritygroupsParams) {
	ctx := r.Context()

	result, err := h.securityGroupClient().ListV2Admin(ctx, organizationID, params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result = slices.DeleteFunc(result, func(resource openapi.SecurityGroupV2Read) bool {
		return rbac.AllowProjectScope(ctx, "region:securitygroups:v2", identityapi.Read, organizationID, resource.Metadata.ProjectId) != nil
	})

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV2OrganizationsOrganizationIDProjectsProjectIDSecuritygroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, params openapi.GetApiV2OrganizationsOrganizationIDProjectsProjectIDSecuritygroupsParams) {
	if err := rbac.AllowProjectScope(r.Context(), "region:securitygroups:v2", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.securityGroupClient().ListV2(r.Context(), organizationID, projectID, params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV2OrganizationsOrganizationIDProjectsProjectIDSecuritygroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:securitygroups:v2", identityapi.Create, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.SecurityGroupV2Create{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.securityGroupClient().CreateV2(r.Context(), organizationID, projectID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) GetApiV2OrganizationsOrganizationIDProjectsProjectIDSecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, securityGroupID openapi.SecurityGroupIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:securitygroups:v2", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.securityGroupClient().GetV2(r.Context(), organizationID, projectID, securityGroupID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV2OrganizationsOrganizationIDProjectsProjectIDSecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, securityGroupID openapi.SecurityGroupIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:securitygroups:v2", identityapi.Update, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.SecurityGroupV2Update{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.securityGroupClient().UpdateV2(r.Context(), organizationID, projectID, securityGroupID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusAccepted, result)
}

func (h *Handler) DeleteApiV2OrganizationsOrganizationIDProjectsProjectIDSecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, securityGroupID openapi.SecurityGroupIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:securitygroups:v2", identityapi.Delete, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.securityGroupClient().DeleteV2(r.Context(), organizationID, projectID, securityGroupID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV2OrganizationsOrganizationIDServers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, params openapi.GetApiV2OrganizationsOrganizationIDServersParams) {
	ctx := r.Context()

	result, err := h.serverClient().ListV2Admin(ctx, organizationID, params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result = slices.DeleteFunc(result, func(resource openapi.ServerV2Read) bool {
		return rbac.AllowProjectScope(ctx, "region:servers", identityapi.Read, organizationID, resource.Metadata.ProjectId) != nil
	})

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV2OrganizationsOrganizationIDProjectsProjectIDServers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, params openapi.GetApiV2OrganizationsOrganizationIDProjectsProjectIDServersParams) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serverClient().ListV2(r.Context(), organizationID, projectID, params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV2OrganizationsOrganizationIDProjectsProjectIDServers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Create, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.ServerV2Create{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serverClient().CreateV2(r.Context(), organizationID, projectID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) GetApiV2OrganizationsOrganizationIDProjectsProjectIDServersServerID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, serverID openapi.ServerIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serverClient().GetV2(r.Context(), organizationID, projectID, serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV2OrganizationsOrganizationIDProjectsProjectIDServersServerID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, serverID openapi.ServerIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Update, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.ServerV2Update{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serverClient().UpdateV2(r.Context(), organizationID, projectID, serverID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusAccepted, result)
}

func (h *Handler) DeleteApiV2OrganizationsOrganizationIDProjectsProjectIDServersServerID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, serverID openapi.ServerIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Delete, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	err := h.serverClient().DeleteV2(r.Context(), organizationID, projectID, serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PostApiV2OrganizationsOrganizationIDProjectsProjectIDServersServerIDStart(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, serverID openapi.ServerIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.serverClient().StartV2(r.Context(), organizationID, projectID, serverID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PostApiV2OrganizationsOrganizationIDProjectsProjectIDServersServerIDStop(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, serverID openapi.ServerIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.serverClient().StopV2(r.Context(), organizationID, projectID, serverID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PostApiV2OrganizationsOrganizationIDProjectsProjectIDServersServerIDSoftreboot(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, serverID openapi.ServerIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.serverClient().RebootV2(r.Context(), organizationID, projectID, serverID, false); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PostApiV2OrganizationsOrganizationIDProjectsProjectIDServersServerIDHardreboot(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, serverID openapi.ServerIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.serverClient().RebootV2(r.Context(), organizationID, projectID, serverID, true); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV2OrganizationsOrganizationIDProjectsProjectIDServersServerIDConsoleoutput(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, serverID openapi.ServerIDParameter, params openapi.GetApiV2OrganizationsOrganizationIDProjectsProjectIDServersServerIDConsoleoutputParams) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serverClient().ConsoleOutputV2(r.Context(), organizationID, projectID, serverID, params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV2OrganizationsOrganizationIDProjectsProjectIDServersServerIDConsolesessions(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, serverID openapi.ServerIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serverClient().ConsoleSessionV2(r.Context(), organizationID, projectID, serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}
