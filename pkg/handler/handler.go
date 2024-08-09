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

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	coreutil "github.com/unikorn-cloud/core/pkg/util"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/region"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/server/util"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

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
		client:    client,
		namespace: namespace,
		options:   options,
		identity:  identity,
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

func (h *Handler) getIdentity(ctx context.Context, id string) (*unikornv1.Identity, error) {
	identity := &unikornv1.Identity{}

	if err := h.client.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: id}, identity); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to lookup identity").WithError(err)
	}

	return identity, nil
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDRegions(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "regions", identityapi.Read, organizationID); err != nil {
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
		Metadata: coreapi.StaticResourceMetadata{
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

	if in.Baremetal {
		out.Spec.Baremetal = coreutil.ToPointer(true)
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

func (h *Handler) GetApiV1OrganizationsOrganizationIDRegionsRegionIDFlavors(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, regionID openapi.RegionIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "regions", identityapi.Read, organizationID); err != nil {
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
	slices.SortStableFunc(result, func(a, b providers.Flavor) int {
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

func convertImageVirtualization(in providers.ImageVirtualization) openapi.ImageVirtualization {
	switch in {
	case providers.Virtualized:
		return openapi.Virtualized
	case providers.Baremetal:
		return openapi.Baremetal
	case providers.Any:
		return openapi.Any
	}

	return ""
}

func convertImage(in providers.Image) openapi.Image {
	out := openapi.Image{
		Metadata: coreapi.StaticResourceMetadata{
			Id:           in.ID,
			Name:         in.Name,
			CreationTime: in.Created,
		},
		Spec: openapi.ImageSpec{
			Virtualization:   convertImageVirtualization(in.Virtualization),
			SoftwareVersions: &openapi.SoftwareVersions{},
		},
	}

	if in.KubernetesVersion != "" {
		out.Spec.SoftwareVersions.Kubernetes = coreutil.ToPointer(in.KubernetesVersion)
	}

	if in.GPU != nil {
		gpu := &openapi.ImageGpu{
			Vendor: convertGpuVendor(in.GPU.Vendor),
			Driver: in.GPU.Driver,
		}

		if len(in.GPU.Models) > 0 {
			gpu.Models = &in.GPU.Models
		}

		out.Spec.Gpu = gpu
	}

	return out
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDRegionsRegionIDImages(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, regionID openapi.RegionIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "regions", identityapi.Read, organizationID); err != nil {
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
	slices.SortStableFunc(result, func(a, b providers.Image) int {
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

func (h *Handler) convertIdentity(ctx context.Context, in *unikornv1.Identity) *openapi.IdentityRead {
	provisioningStatus := coreapi.ResourceProvisioningStatusUnknown

	if condition, err := in.StatusConditionRead(unikornv1core.ConditionAvailable); err == nil {
		provisioningStatus = conversion.ConvertStatusCondition(condition)
	}

	out := &openapi.IdentityRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, provisioningStatus),
		Spec: openapi.IdentitySpec{
			RegionId: in.Labels[constants.RegionLabel],
		},
	}

	if tags := convertTags(in.Spec.Tags); tags != nil {
		out.Spec.Tags = &tags
	}

	switch in.Spec.Provider {
	case unikornv1.ProviderOpenstack:
		out.Spec.Type = openapi.Openstack

		var openstackIdentity unikornv1.OpenstackIdentity

		if err := h.client.Get(ctx, client.ObjectKey{Namespace: in.Namespace, Name: in.Name}, &openstackIdentity); err == nil {
			out.Spec.Openstack = &openapi.IdentitySpecOpenStack{
				Cloud:         openstackIdentity.Spec.Cloud,
				UserId:        openstackIdentity.Spec.UserID,
				ProjectId:     openstackIdentity.Spec.ProjectID,
				ServerGroupId: openstackIdentity.Spec.ServerGroupID,
			}

			if openstackIdentity.Spec.CloudConfig != nil {
				cloudConfig := base64.URLEncoding.EncodeToString(openstackIdentity.Spec.CloudConfig)
				out.Spec.Openstack.CloudConfig = &cloudConfig
			}
		}
	}

	return out
}

func (h *Handler) convertIdentityList(ctx context.Context, in unikornv1.IdentityList) openapi.IdentitiesRead {
	out := make(openapi.IdentitiesRead, len(in.Items))

	for i := range in.Items {
		out[i] = *h.convertIdentity(ctx, &in.Items[i])
	}

	return out
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDIdentities(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identities", identityapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	var result unikornv1.IdentityList

	options := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			coreconstants.OrganizationLabel: organizationID,
		}),
	}

	if err := h.client.List(r.Context(), &result, options); err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to list identities").WithError(err))
		return
	}

	slices.SortStableFunc(result.Items, func(a, b unikornv1.Identity) int {
		return cmp.Compare(a.Name, b.Name)
	})

	util.WriteJSONResponse(w, r, http.StatusOK, h.convertIdentityList(r.Context(), result))
}

func generateTag(in openapi.Tag) unikornv1.Tag {
	out := unikornv1.Tag{
		Name:  in.Name,
		Value: in.Value,
	}

	return out
}

func generateTagList(in *openapi.TagList) unikornv1.TagList {
	if in == nil {
		return nil
	}

	out := make(unikornv1.TagList, len(*in))

	for i := range *in {
		out[i] = generateTag((*in)[i])
	}

	return out
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentities(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "identities", identityapi.Create, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.IdentityWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	provider, err := region.NewClient(h.client, h.namespace).Provider(r.Context(), request.Spec.RegionId)
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to get region provider").WithError(err))
		return
	}

	region, err := provider.Region(r.Context())
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to get region").WithError(err))
		return
	}

	userinfo, err := authorization.UserinfoFromContext(r.Context())
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to get userinfo").WithError(err))
		return
	}

	identity := &unikornv1.Identity{
		ObjectMeta: conversion.NewObjectMetadata(&request.Metadata, h.namespace, userinfo.Sub).WithOrganization(organizationID).WithProject(projectID).WithLabel(constants.RegionLabel, request.Spec.RegionId).Get(),
		Spec: unikornv1.IdentitySpec{
			Tags:     generateTagList(request.Spec.Tags),
			Provider: region.Spec.Provider,
		},
	}

	if err := h.client.Create(r.Context(), identity); err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to create identity").WithError(err))
		return
	}

	util.WriteJSONResponse(w, r, http.StatusCreated, h.convertIdentity(r.Context(), identity))
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "identities", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	identity, err := h.getIdentity(r.Context(), identityID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, h.convertIdentity(r.Context(), identity))
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "identities", identityapi.Delete, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	identity, err := h.getIdentity(r.Context(), identityID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.client.Delete(r.Context(), identity); err != nil {
		if kerrors.IsNotFound(err) {
			errors.HandleError(w, r, errors.HTTPNotFound().WithError(err))
			return
		}

		errors.HandleError(w, r, errors.OAuth2ServerError("unable to delete identity").WithError(err))
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func convertPhysicalNetwork(in *unikornv1.PhysicalNetwork) *openapi.PhysicalNetworkRead {
	out := &openapi.PhysicalNetworkRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, coreapi.ResourceProvisioningStatusProvisioned),
	}

	if tags := convertTags(in.Spec.Tags); tags != nil {
		out.Spec.Tags = &tags
	}

	return out
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDPhysicalNetworks(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "identities", identityapi.Create, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.PhysicalNetworkWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	identity, err := h.getIdentity(r.Context(), identityID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	provider, err := region.NewClient(h.client, h.namespace).Provider(r.Context(), identity.Labels[constants.RegionLabel])
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	network, err := provider.CreatePhysicalNetwork(r.Context(), identity, request)
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

func (h *Handler) GetApiV1OrganizationsOrganizationIDRegionsRegionIDExternalnetworks(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, regionID openapi.RegionIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "regions", identityapi.Read, organizationID); err != nil {
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
