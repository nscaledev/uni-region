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
	"github.com/unikorn-cloud/region/pkg/openapi"
)

type SecurityGroupHandler common.Handler

func NewSecurityGroupHandler(clientArgs common.ClientArgs) *SecurityGroupHandler {
	return &SecurityGroupHandler{
		ClientArgs: clientArgs,
	}
}

func (h *SecurityGroupHandler) securityGroupClient() *securitygroup.Client {
	return securitygroup.New(h.ClientArgs)
}

func (h *SecurityGroupHandler) GetApiV1OrganizationsOrganizationIDSecuritygroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, params openapi.GetApiV1OrganizationsOrganizationIDSecuritygroupsParams) {
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

func (h *SecurityGroupHandler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter) {
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

func (h *SecurityGroupHandler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, securityGroupID openapi.SecurityGroupIDParameter) {
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

func (h *SecurityGroupHandler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, securityGroupID openapi.SecurityGroupIDParameter) {
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

func (h *SecurityGroupHandler) PutApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, securityGroupID openapi.SecurityGroupIDParameter) {
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
