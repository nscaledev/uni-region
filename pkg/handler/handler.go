/*
Copyright 2022-2024 EscherCloud.
Copyright 2024 the Unikorn Authors.

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

//nolint:revive,stylecheck
package handler

import (
	"cmp"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/unikorn-cloud/core/pkg/authorization/constants"
	"github.com/unikorn-cloud/core/pkg/authorization/userinfo"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	coreutil "github.com/unikorn-cloud/core/pkg/util"
	"github.com/unikorn-cloud/identity/pkg/authorization"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/region"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/server/util"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Handler struct {
	// client gives cached access to Kubernetes.
	client client.Client

	// namespace is the namespace we are running in.
	namespace string

	// options allows behaviour to be defined on the CLI.
	options *Options

	// identity is an identity client for RBAC access.
	identity *identityclient.Client
}

func New(client client.Client, namespace string, options *Options, identity *identityclient.Client) (*Handler, error) {
	h := &Handler{
		client:   client,
		options:  options,
		identity: identity,
	}

	return h, nil
}

func (h *Handler) setCacheable(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", fmt.Sprintf("max-age=%d", h.options.CacheMaxAge/time.Second))
	w.Header().Add("Cache-Control", "private")
}

func (h *Handler) setUncacheable(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", "no-cache")
}

//nolint:unparam
func (h *Handler) checkRBAC(ctx context.Context, organizationID, scope string, permission constants.Permission) error {
	identity, err := h.identity.Client(ctx)
	if err != nil {
		return err
	}

	authorizer, err := userinfo.NewAuthorizer(ctx, authorization.NewIdentityACLGetter(identity, organizationID))
	if err != nil {
		return errors.HTTPForbidden("operation is not allowed by rbac").WithError(err)
	}

	if err := authorizer.Allow(ctx, scope, permission); err != nil {
		return errors.HTTPForbidden("operation is not allowed by rbac").WithError(err)
	}

	return nil
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDRegions(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	if err := h.checkRBAC(r.Context(), organizationID, "infrastructure", constants.Read); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := region.NewClient(h.client, h.namespace).List(r.Context())
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func convertGpuVendor(in providers.GPUVendor) openapi.GpuVendor {
	switch in {
	case providers.Nvidia:
		return openapi.NVIDIA
	case providers.AMD:
		return openapi.AMD
	}

	return ""
}

func convertFlavor(in providers.Flavor) openapi.Flavor {
	out := openapi.Flavor{
		Metadata: coreopenapi.StaticResourceMetadata{
			Id:   in.ID,
			Name: in.Name,
		},
		Spec: openapi.FlavorSpec{
			Cpus:      in.CPUs,
			CpuFamily: in.CPUFamily,
			Memory:    int(in.Memory.Value()) >> 30,
			Disk:      int(in.Disk.Value()) / 1000000000,
		},
	}

	if in.GPU != nil {
		out.Spec.Gpu = &openapi.GpuSpec{
			Vendor: convertGpuVendor(in.GPU.Vendor),
			Model:  in.GPU.Model,
			Memory: int(in.GPU.Memory.Value()) >> 30,
			Count:  in.GPU.Count,
		}
	}

	return out
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDRegionsRegionIDFlavors(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, regionID openapi.RegionIDParameter) {
	if err := h.checkRBAC(r.Context(), organizationID, "infrastructure", constants.Read); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	provider, err := region.NewClient(h.client, h.namespace).Provider(r.Context(), regionID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := provider.Flavors(r.Context())
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	// Apply ordering guarantees, ascending order with GPUs taking precedence over
	// CPUs and memory.
	slices.SortFunc(result, func(a, b providers.Flavor) int {
		if v := cmp.Compare(a.GPUCount(), b.GPUCount()); v != 0 {
			return v
		}

		if v := cmp.Compare(a.CPUs, b.CPUs); v != 0 {
			return v
		}

		return cmp.Compare(a.Memory.Value(), b.Memory.Value())
	})

	out := make(openapi.Flavors, len(result))

	for i := range result {
		out[i] = convertFlavor(result[i])
	}

	h.setCacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, out)
}

func convertImage(in providers.Image) openapi.Image {
	out := openapi.Image{
		Metadata: coreopenapi.StaticResourceMetadata{
			Id:           in.ID,
			Name:         in.Name,
			CreationTime: in.Created,
		},
		Spec: openapi.ImageSpec{
			SoftwareVersions: &openapi.SoftwareVersions{},
		},
	}

	if in.KubernetesVersion != "" {
		out.Spec.SoftwareVersions.Kubernetes = coreutil.ToPointer(in.KubernetesVersion)
	}

	return out
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDRegionsRegionIDImages(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, regionID openapi.RegionIDParameter) {
	if err := h.checkRBAC(r.Context(), organizationID, "infrastructure", constants.Read); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	provider, err := region.NewClient(h.client, h.namespace).Provider(r.Context(), regionID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := provider.Images(r.Context())
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	// Apply ordering guarantees, ordered by name.
	slices.SortFunc(result, func(a, b providers.Image) int {
		return cmp.Compare(a.Name, b.Name)
	})

	out := make(openapi.Images, len(result))

	for i := range result {
		out[i] = convertImage(result[i])
	}

	h.setCacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, out)
}

func convertTag(in unikornv1.Tag) openapi.Tag {
	out := openapi.Tag{
		Name:  in.Name,
		Value: in.Value,
	}

	return out
}

func convertTags(in unikornv1.TagList) openapi.TagList {
	if in == nil {
		return nil
	}

	out := make(openapi.TagList, len(in))

	for i := range in {
		out[i] = convertTag(in[i])
	}

	return out
}

func convertIdentity(identity *unikornv1.Identity, in *providers.CloudConfig) *openapi.IdentityRead {
	out := &openapi.IdentityRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(identity, coreopenapi.ResourceProvisioningStatusProvisioned),
	}

	if tags := convertTags(identity.Spec.Tags); tags != nil {
		out.Spec.Tags = &tags
	}

	switch in.Type {
	case providers.ProviderTypeOpenStack:
		out.Spec = openapi.IdentitySpec{
			Type: openapi.Openstack,
			Openstack: &openapi.IdentitySpecOpenStack{
				Cloud:       in.OpenStack.Credentials.Cloud,
				CloudConfig: base64.URLEncoding.EncodeToString(in.OpenStack.Credentials.CloudConfig),
				UserId:      in.OpenStack.State.UserID,
				ProjectId:   in.OpenStack.State.ProjectID,
			},
		}
	}

	return out
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDRegionsRegionIDIdentities(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, regionID openapi.RegionIDParameter) {
	if err := h.checkRBAC(r.Context(), organizationID, "infrastructure", constants.Create); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.IdentityWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	provider, err := region.NewClient(h.client, h.namespace).Provider(r.Context(), regionID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	identity, cloudconfig, err := provider.CreateIdentity(r.Context(), organizationID, projectID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setCacheable(w)
	util.WriteJSONResponse(w, r, http.StatusCreated, convertIdentity(identity, cloudconfig))
}

func convertPhysicalNetwork(in *unikornv1.PhysicalNetwork) *openapi.PhysicalNetworkRead {
	out := &openapi.PhysicalNetworkRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, coreopenapi.ResourceProvisioningStatusProvisioned),
	}

	if tags := convertTags(in.Spec.Tags); tags != nil {
		out.Spec.Tags = &tags
	}

	return out
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDRegionsRegionIDIdentitiesIdentityIDPhysicalNetworks(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, regionID openapi.RegionIDParameter, identityID openapi.IdentityIDParameter) {
	if err := h.checkRBAC(r.Context(), organizationID, "infrastructure", constants.Create); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.PhysicalNetworkWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	provider, err := region.NewClient(h.client, h.namespace).Provider(r.Context(), regionID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	network, err := provider.CreatePhysicalNetwork(r.Context(), organizationID, projectID, identityID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusCreated, convertPhysicalNetwork(network))
}

func convertExternalNetwork(in providers.ExternalNetwork) openapi.ExternalNetwork {
	out := openapi.ExternalNetwork{
		Id:   in.ID,
		Name: in.Name,
	}

	return out
}

func convertExternalNetworks(in providers.ExternalNetworks) openapi.ExternalNetworks {
	out := make(openapi.ExternalNetworks, len(in))

	for i := range in {
		out[i] = convertExternalNetwork(in[i])
	}

	return out
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDRegionsRegionIDExternalnetworks(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, regionID openapi.RegionIDParameter) {
	if err := h.checkRBAC(r.Context(), organizationID, "infrastructure", constants.Read); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	provider, err := region.NewClient(h.client, h.namespace).Provider(r.Context(), regionID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := provider.ListExternalNetworks(r.Context())
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setCacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, convertExternalNetworks(result))
}
