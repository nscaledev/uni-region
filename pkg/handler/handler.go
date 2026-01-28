/*
Copyright 2022-2024 EscherCloud.
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

//nolint:revive
package handler

import (
	"net/http"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/securitygroup"
	"github.com/unikorn-cloud/region/pkg/handler/server"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

type Handler struct {
	// There are embedded so they can be their own structs
	*IdentityHandler
	*ImageHandler
	*NetworkHandler
	*RegionHandler
	*ServerV2Handler
	*ImageV2Handler

	// ClientArgs has the values needed to create the various handler clients.
	common.ClientArgs

	// options allows behaviour to be defined on the CLI.
	options *Options
}

func New(clientArgs common.ClientArgs, options *Options) (*Handler, error) {
	h := &Handler{
		ClientArgs:      clientArgs,
		options:         options,
		IdentityHandler: NewIdentityHandler(clientArgs),
		ImageHandler:    NewImageHandler(clientArgs, options),
		NetworkHandler:  NewNetworkHandler(clientArgs),
		RegionHandler:   NewRegionHandler(clientArgs, options),
		ServerV2Handler: NewServerV2Handler(clientArgs),
		ImageV2Handler:  NewImageV2Handler(clientArgs, options),
	}

	return h, nil
}

func (h *Handler) securityGroupClient() *securitygroup.Client {
	return securitygroup.New(h.ClientArgs)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDSecuritygroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, params openapi.GetApiV1OrganizationsOrganizationIDSecuritygroupsParams) {
	if err := rbac.AllowOrganizationScope(r.Context(), "region:securitygroups", identityapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.securityGroupClient().List(r.Context(), organizationID, params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:securitygroups", identityapi.Create, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.SecurityGroupWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.securityGroupClient().Create(r.Context(), organizationID, projectID, identityID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, securityGroupID openapi.SecurityGroupIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:securitygroups", identityapi.Delete, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.securityGroupClient().Delete(r.Context(), organizationID, projectID, securityGroupID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, securityGroupID openapi.SecurityGroupIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:securitygroups", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.securityGroupClient().Get(r.Context(), organizationID, projectID, securityGroupID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, securityGroupID openapi.SecurityGroupIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:securitygroups", identityapi.Update, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.SecurityGroupWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.securityGroupClient().Update(r.Context(), organizationID, projectID, identityID, securityGroupID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusAccepted, result)
}

func (h *Handler) serverClient() *server.Client {
	return server.NewClient(h.ClientArgs)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDServers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, params openapi.GetApiV1OrganizationsOrganizationIDServersParams) {
	if err := rbac.AllowOrganizationScope(r.Context(), "region:servers", identityapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serverClient().List(r.Context(), organizationID, params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Create, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.ServerWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serverClient().Create(r.Context(), organizationID, projectID, identityID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Delete, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	err := h.serverClient().Delete(r.Context(), organizationID, projectID, serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serverClient().Get(r.Context(), organizationID, projectID, serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Create, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.ServerWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serverClient().Update(r.Context(), organizationID, projectID, identityID, serverID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusAccepted, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDConsoleoutput(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter, params openapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDConsoleoutputParams) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serverClient().GetConsoleOutput(r.Context(), organizationID, projectID, identityID, serverID, params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDConsolesessions(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serverClient().CreateConsoleSession(r.Context(), organizationID, projectID, identityID, serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDHardreboot(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Update, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.serverClient().Reboot(r.Context(), organizationID, projectID, identityID, serverID, true); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDSoftreboot(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Update, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.serverClient().Reboot(r.Context(), organizationID, projectID, identityID, serverID, false); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDStart(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Update, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.serverClient().Start(r.Context(), organizationID, projectID, identityID, serverID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDStop(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Update, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.serverClient().Stop(r.Context(), organizationID, projectID, identityID, serverID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}
