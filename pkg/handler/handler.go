/*
Copyright 2022-2024 EscherCloud.
Copyright 2024-2025 the Unikorn Authors.

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
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/unikorn-cloud/core/pkg/server/v2/httputil"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/region/pkg/handler/identity"
	"github.com/unikorn-cloud/region/pkg/handler/network"
	"github.com/unikorn-cloud/region/pkg/handler/region"
	"github.com/unikorn-cloud/region/pkg/handler/securitygroup"
	"github.com/unikorn-cloud/region/pkg/handler/server"
	"github.com/unikorn-cloud/region/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Handler struct {
	// client gives cached access to Kubernetes.
	client client.Client

	// namespace is the namespace we are running in.
	namespace string

	// options allows behaviour to be defined on the CLI.
	options *Options

	// issuer provides privilege escalation for the API so the end user doesn't
	// have to be granted unnecessary privilege.
	issuer *identityclient.TokenIssuer

	// identity is an identity client for RBAC access.
	identity *identityclient.Client
}

func New(client client.Client, namespace string, options *Options, issuer *identityclient.TokenIssuer, identity *identityclient.Client) (*Handler, error) {
	h := &Handler{
		client:    client,
		namespace: namespace,
		options:   options,
		issuer:    issuer,
		identity:  identity,
	}

	return h, nil
}

// getIdentityAPIClient gets a client to talk to the identity service, this must not
// be cached as the token is only short-lived.  Said problem goes away when we use
// SPIFFE as a workload identity layer.
func (h *Handler) getIdentityAPIClient(ctx context.Context) (identityapi.ClientWithResponsesInterface, error) {
	token, err := h.issuer.Issue(ctx)
	if err != nil {
		return nil, err
	}

	client, err := h.identity.APIClient(ctx, token)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (h *Handler) setCacheable(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", fmt.Sprintf("max-age=%d", h.options.CacheMaxAge/time.Second))
	w.Header().Add("Cache-Control", "private")
}

func (h *Handler) setUncacheable(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", "no-cache")
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDRegions(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowOrganizationScope(ctx, "region:regions", identityapi.Read, organizationID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := region.NewClient(h.client, h.namespace).List(ctx)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	h.setUncacheable(w)
	httputil.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDRegionsRegionIDDetail(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, regionID openapi.RegionIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowOrganizationScope(ctx, "region:regions/detail", identityapi.Read, organizationID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := region.NewClient(h.client, h.namespace).GetDetail(ctx, regionID)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	h.setUncacheable(w)
	httputil.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDRegionsRegionIDExternalnetworks(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, regionID openapi.RegionIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowOrganizationScope(ctx, "region:externalnetworks", identityapi.Read, organizationID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := region.NewClient(h.client, h.namespace).ListExternalNetworks(ctx, regionID)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	h.setCacheable(w)
	httputil.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDRegionsRegionIDFlavors(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, regionID openapi.RegionIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowOrganizationScope(ctx, "region:flavors", identityapi.Read, organizationID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := region.NewClient(h.client, h.namespace).ListFlavors(ctx, organizationID, regionID)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	h.setCacheable(w)
	httputil.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDRegionsRegionIDImages(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, regionID openapi.RegionIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowOrganizationScope(ctx, "region:images", identityapi.Read, organizationID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := region.NewClient(h.client, h.namespace).ListImages(ctx, organizationID, regionID)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	h.setCacheable(w)
	httputil.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDIdentities(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowOrganizationScope(ctx, "region:identities", identityapi.Read, organizationID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := identity.New(h.client, h.namespace).List(ctx, organizationID)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	httputil.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentities(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:identities", identityapi.Create, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	request, err := httputil.ReadJSONRequestBody[openapi.IdentityWrite](r.Body)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := identity.New(h.client, h.namespace).Create(ctx, organizationID, projectID, request)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	httputil.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:identities", identityapi.Read, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := identity.New(h.client, h.namespace).Get(ctx, organizationID, projectID, identityID)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	httputil.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:identities", identityapi.Delete, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	if err := identity.New(h.client, h.namespace).Delete(ctx, organizationID, projectID, identityID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) networkClient() *network.Client {
	return network.New(h.client, h.namespace, h.getIdentityAPIClient)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDNetworks(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowOrganizationScope(ctx, "region:networks", identityapi.Read, organizationID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := h.networkClient().List(ctx, organizationID)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	httputil.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDNetworks(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:networks", identityapi.Create, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	request, err := httputil.ReadJSONRequestBody[openapi.NetworkWrite](r.Body)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := h.networkClient().Create(ctx, organizationID, projectID, identityID, request)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	httputil.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDNetworksNetworkID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, networkID openapi.NetworkIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:networks", identityapi.Read, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := h.networkClient().Get(ctx, organizationID, projectID, networkID)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	httputil.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDNetworksNetworkID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, networkID openapi.NetworkIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:networks", identityapi.Delete, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	if err := h.networkClient().Delete(ctx, organizationID, projectID, networkID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) securityGroupClient() *securitygroup.Client {
	return securitygroup.New(h.client, h.namespace)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDSecuritygroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, params openapi.GetApiV1OrganizationsOrganizationIDSecuritygroupsParams) {
	ctx := r.Context()

	if err := rbac.AllowOrganizationScope(ctx, "region:securitygroups", identityapi.Read, organizationID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := h.securityGroupClient().List(ctx, organizationID, params)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	httputil.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:securitygroups", identityapi.Create, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	request, err := httputil.ReadJSONRequestBody[openapi.SecurityGroupWrite](r.Body)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := h.securityGroupClient().Create(ctx, organizationID, projectID, identityID, request)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	httputil.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, securityGroupID openapi.SecurityGroupIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:securitygroups", identityapi.Delete, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	if err := h.securityGroupClient().Delete(ctx, organizationID, projectID, securityGroupID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, securityGroupID openapi.SecurityGroupIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:securitygroups", identityapi.Read, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := h.securityGroupClient().Get(ctx, organizationID, projectID, securityGroupID)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	httputil.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, securityGroupID openapi.SecurityGroupIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:securitygroups", identityapi.Update, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	request, err := httputil.ReadJSONRequestBody[openapi.SecurityGroupWrite](r.Body)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := h.securityGroupClient().Update(ctx, organizationID, projectID, identityID, securityGroupID, request)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	httputil.WriteJSONResponse(w, r, http.StatusAccepted, result)
}

func (h *Handler) serverClient() *server.Client {
	return server.NewClient(h.client, h.namespace)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDServers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, params openapi.GetApiV1OrganizationsOrganizationIDServersParams) {
	ctx := r.Context()

	if err := rbac.AllowOrganizationScope(ctx, "region:servers", identityapi.Read, organizationID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := h.serverClient().List(ctx, organizationID, params)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	httputil.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:servers", identityapi.Create, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	request, err := httputil.ReadJSONRequestBody[openapi.ServerWrite](r.Body)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := h.serverClient().Create(ctx, organizationID, projectID, identityID, request)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	httputil.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:servers", identityapi.Delete, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	err := h.serverClient().Delete(ctx, organizationID, projectID, serverID)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:servers", identityapi.Read, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := h.serverClient().Get(ctx, organizationID, projectID, serverID)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	httputil.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:servers", identityapi.Create, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	request, err := httputil.ReadJSONRequestBody[openapi.ServerWrite](r.Body)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := h.serverClient().Update(ctx, organizationID, projectID, identityID, serverID, request)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	httputil.WriteJSONResponse(w, r, http.StatusAccepted, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDConsoleoutput(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter, params openapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDConsoleoutputParams) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:servers", identityapi.Read, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := h.serverClient().GetConsoleOutput(ctx, organizationID, projectID, identityID, serverID, params)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	httputil.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDConsolesessions(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:servers", identityapi.Read, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	result, err := h.serverClient().CreateConsoleSession(ctx, organizationID, projectID, identityID, serverID)
	if err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	httputil.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDHardreboot(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:servers", identityapi.Update, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	if err := h.serverClient().Reboot(ctx, organizationID, projectID, identityID, serverID, true); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDSoftreboot(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:servers", identityapi.Update, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	if err := h.serverClient().Reboot(ctx, organizationID, projectID, identityID, serverID, false); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDStart(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:servers", identityapi.Update, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	if err := h.serverClient().Start(ctx, organizationID, projectID, identityID, serverID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDStop(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter) {
	ctx := r.Context()

	if err := rbac.AllowProjectScope(ctx, "region:servers", identityapi.Update, organizationID, projectID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	if err := h.serverClient().Stop(ctx, organizationID, projectID, identityID, serverID); err != nil {
		httputil.WriteAPIErrorResponse(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}
