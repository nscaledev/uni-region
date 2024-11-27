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
	"net"
	"net/http"
	"slices"
	"time"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/region"
	"github.com/unikorn-cloud/region/pkg/handler/server"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var (
	foregroundDeleteOptions = &client.DeleteOptions{
		PropagationPolicy: ptr.To(metav1.DeletePropagationForeground),
	}
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
	resource := &unikornv1.Identity{}

	if err := h.client.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: id}, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to lookup identity").WithError(err)
	}

	return resource, nil
}

func (h *Handler) getNetwork(ctx context.Context, id string) (*unikornv1.Network, error) {
	resource := &unikornv1.Network{}

	if err := h.client.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: id}, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to network identity").WithError(err)
	}

	return resource, nil
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDRegions(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "region:regions", identityapi.Read, organizationID); err != nil {
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
		out.Spec.Baremetal = ptr.To(true)
	}

	if in.GPU != nil {
		out.Spec.Gpu = &openapi.GpuSpec{
			Vendor:        convertGpuVendor(in.GPU.Vendor),
			Model:         in.GPU.Model,
			Memory:        int(in.GPU.Memory.Value()) >> 30,
			PhysicalCount: in.GPU.PhysicalCount,
			LogicalCount:  in.GPU.LogicalCount,
		}
	}

	return out
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDRegionsRegionIDFlavors(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, regionID openapi.RegionIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "region:flavors", identityapi.Read, organizationID); err != nil {
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
		out.Spec.SoftwareVersions.Kubernetes = ptr.To(in.KubernetesVersion)
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
	if err := rbac.AllowOrganizationScope(r.Context(), "region:images", identityapi.Read, organizationID); err != nil {
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

func (h *Handler) convertIdentity(ctx context.Context, in *unikornv1.Identity) *openapi.IdentityRead {
	provisioningStatus := coreapi.ResourceProvisioningStatusUnknown

	if condition, err := in.StatusConditionRead(unikornv1core.ConditionAvailable); err == nil {
		provisioningStatus = conversion.ConvertStatusCondition(condition)
	}

	out := &openapi.IdentityRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags, provisioningStatus),
		Spec: openapi.IdentitySpec{
			RegionId: in.Labels[constants.RegionLabel],
		},
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
				SshKeyName:    openstackIdentity.Spec.SSHKeyName,
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
	if err := rbac.AllowOrganizationScope(r.Context(), "region:identities", identityapi.Read, organizationID); err != nil {
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

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentities(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:identities", identityapi.Create, organizationID, projectID); err != nil {
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
			Tags:     conversion.GenerateTagList(request.Metadata.Tags),
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
	if err := rbac.AllowProjectScope(r.Context(), "region:identities", identityapi.Read, organizationID, projectID); err != nil {
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
	if err := rbac.AllowProjectScope(r.Context(), "region:identities", identityapi.Delete, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	identity, err := h.getIdentity(r.Context(), identityID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.client.Delete(r.Context(), identity, foregroundDeleteOptions); err != nil {
		if kerrors.IsNotFound(err) {
			errors.HandleError(w, r, errors.HTTPNotFound().WithError(err))
			return
		}

		errors.HandleError(w, r, errors.OAuth2ServerError("unable to delete identity").WithError(err))
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func convertIPv4List(in []unikornv1core.IPv4Address) openapi.Ipv4AddressList {
	out := make(openapi.Ipv4AddressList, len(in))

	for i, ip := range in {
		out[i] = ip.String()
	}

	return out
}

func (h *Handler) convertNetwork(ctx context.Context, in *unikornv1.Network) *openapi.NetworkRead {
	provisioningStatus := coreapi.ResourceProvisioningStatusUnknown

	if condition, err := in.StatusConditionRead(unikornv1core.ConditionAvailable); err == nil {
		provisioningStatus = conversion.ConvertStatusCondition(condition)
	}

	out := &openapi.NetworkRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags, provisioningStatus),
		Spec: openapi.NetworkReadSpec{
			RegionId:       in.Labels[constants.RegionLabel],
			Prefix:         in.Spec.Prefix.String(),
			DnsNameservers: convertIPv4List(in.Spec.DNSNameservers),
		},
	}

	switch in.Spec.Provider {
	case unikornv1.ProviderOpenstack:
		out.Spec.Type = openapi.Openstack

		var openstackNetwork unikornv1.OpenstackNetwork

		if err := h.client.Get(ctx, client.ObjectKey{Namespace: in.Namespace, Name: in.Name}, &openstackNetwork); err == nil {
			out.Spec.Openstack = &openapi.NetworkSpecOpenstack{
				VlanId:    openstackNetwork.Spec.VlanID,
				NetworkId: openstackNetwork.Spec.NetworkID,
				SubnetId:  openstackNetwork.Spec.SubnetID,
			}
		}
	}

	return out
}

func (h *Handler) convertNetworkList(ctx context.Context, in unikornv1.NetworkList) openapi.NetworksRead {
	out := make(openapi.NetworksRead, len(in.Items))

	for i := range in.Items {
		out[i] = *h.convertNetwork(ctx, &in.Items[i])
	}

	return out
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDNetworks(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "region:networks", identityapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	var result unikornv1.NetworkList

	options := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			coreconstants.OrganizationLabel: organizationID,
		}),
	}

	if err := h.client.List(r.Context(), &result, options); err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to list networks").WithError(err))
		return
	}

	slices.SortStableFunc(result.Items, func(a, b unikornv1.Network) int {
		return cmp.Compare(a.Name, b.Name)
	})

	util.WriteJSONResponse(w, r, http.StatusOK, h.convertNetworkList(r.Context(), result))
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDNetworks(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:networks", identityapi.Create, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.NetworkWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	identity, err := h.getIdentity(r.Context(), identityID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	userinfo, err := authorization.UserinfoFromContext(r.Context())
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to get userinfo").WithError(err))
		return
	}

	_, prefix, err := net.ParseCIDR(request.Spec.Prefix)
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2InvalidRequest("unable to parse prefix").WithError(err))
		return
	}

	dnsNameservers := make([]unikornv1core.IPv4Address, len(request.Spec.DnsNameservers))

	for i, ip := range request.Spec.DnsNameservers {
		temp := net.ParseIP(ip)
		if temp == nil {
			errors.HandleError(w, r, errors.OAuth2InvalidRequest("unable to parse dns nameserver"))
			return
		}

		dnsNameservers[i] = unikornv1core.IPv4Address{
			IP: temp,
		}
	}

	network := &unikornv1.Network{
		ObjectMeta: conversion.NewObjectMetadata(&request.Metadata, h.namespace, userinfo.Sub).WithOrganization(organizationID).WithProject(projectID).WithLabel(constants.RegionLabel, identity.Labels[constants.RegionLabel]).WithLabel(constants.IdentityLabel, identityID).Get(),
		Spec: unikornv1.NetworkSpec{
			Tags:     conversion.GenerateTagList(request.Metadata.Tags),
			Provider: identity.Spec.Provider,
			Prefix: &unikornv1core.IPv4Prefix{
				IPNet: *prefix,
			},
			DNSNameservers: dnsNameservers,
		},
	}

	// The resource belongs to its identity, for cascading deletion.
	if err := controllerutil.SetOwnerReference(identity, network, h.client.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to set resource owner").WithError(err))
		return
	}

	if err := h.client.Create(r.Context(), network); err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to create network").WithError(err))
		return
	}

	util.WriteJSONResponse(w, r, http.StatusCreated, h.convertNetwork(r.Context(), network))
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDNetworksNetworkID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, physicalNetworkID openapi.NetworkIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:networks", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	resource, err := h.getNetwork(r.Context(), physicalNetworkID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, h.convertNetwork(r.Context(), resource))
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDNetworksNetworkID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, physicalNetworkID openapi.NetworkIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:networks", identityapi.Delete, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	resource, err := h.getNetwork(r.Context(), physicalNetworkID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.client.Delete(r.Context(), resource, foregroundDeleteOptions); err != nil {
		if kerrors.IsNotFound(err) {
			errors.HandleError(w, r, errors.HTTPNotFound().WithError(err))
			return
		}

		errors.HandleError(w, r, errors.OAuth2ServerError("unable to delete network").WithError(err))
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) getQuota(ctx context.Context, identity *unikornv1.Identity) (*unikornv1.Quota, error) {
	userinfo, err := authorization.UserinfoFromContext(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to get userinfo").WithError(err)
	}

	options := &client.ListOptions{
		Namespace: h.namespace,
		LabelSelector: labels.SelectorFromSet(map[string]string{
			constants.IdentityLabel: identity.Name,
		}),
	}

	resources := &unikornv1.QuotaList{}

	if err := h.client.List(ctx, resources, options); err != nil {
		return nil, errors.OAuth2ServerError("unable to list quotas").WithError(err)
	}

	// Default scoping rule is that you can only see your own quota.
	resources.Items = slices.DeleteFunc(resources.Items, func(resource unikornv1.Quota) bool {
		return resource.Annotations[coreconstants.CreatorAnnotation] != userinfo.Sub
	})

	if len(resources.Items) == 0 {
		//nolint:nilnil
		return nil, nil
	}

	// TODO: what if there's more than one!!
	return &resources.Items[0], nil
}

func convertFlavorQuotas(in []unikornv1.FlavorQuota) *openapi.FlavorQuotaList {
	if len(in) == 0 {
		return nil
	}

	out := make(openapi.FlavorQuotaList, len(in))

	for i := range in {
		out[i] = openapi.FlavorQuota{
			Id:    in[i].ID,
			Count: in[i].Count,
		}
	}

	return &out
}

func convertQuota(in *unikornv1.Quota) *openapi.QuotasSpec {
	out := &openapi.QuotasSpec{
		Flavors: convertFlavorQuotas(in.Spec.Flavors),
	}

	return out
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDQuotas(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:quotas", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	identity, err := h.getIdentity(r.Context(), identityID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	resource, err := h.getQuota(r.Context(), identity)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if resource == nil {
		resource = &unikornv1.Quota{}
	}

	util.WriteJSONResponse(w, r, http.StatusOK, convertQuota(resource))
}

func generateFlavorQuotas(in *openapi.FlavorQuotaList) []unikornv1.FlavorQuota {
	if in == nil || len(*in) == 0 {
		return nil
	}

	t := *in

	out := make([]unikornv1.FlavorQuota, len(t))

	for i := range t {
		out[i] = unikornv1.FlavorQuota{
			ID:    t[i].Id,
			Count: t[i].Count,
		}
	}

	return out
}

func (h *Handler) generateQuota(ctx context.Context, organizationID, projectID string, identity *unikornv1.Identity, in *openapi.QuotasSpec) (*unikornv1.Quota, error) {
	userinfo, err := authorization.UserinfoFromContext(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to get userinfo").WithError(err)
	}

	metadata := &coreapi.ResourceWriteMetadata{
		Name: fmt.Sprintf("identity-quota-%s", identity.Name),
	}

	resource := &unikornv1.Quota{
		ObjectMeta: conversion.NewObjectMetadata(metadata, h.namespace, userinfo.Sub).WithOrganization(organizationID).WithProject(projectID).WithLabel(constants.RegionLabel, identity.Labels[constants.RegionLabel]).WithLabel(constants.IdentityLabel, identity.Name).Get(),
		Spec: unikornv1.QuotaSpec{
			// TODO: tags??
			Flavors: generateFlavorQuotas(in.Flavors),
		},
	}

	// Ensure the quota is owned by the identity so it is automatically cleaned
	// up on identity deletion.
	if err := controllerutil.SetOwnerReference(identity, resource, h.client.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
		return nil, err
	}

	return resource, nil
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDQuotas(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "region:quotas", identityapi.Update, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.QuotasSpec{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	identity, err := h.getIdentity(r.Context(), identityID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	required, err := h.generateQuota(r.Context(), organizationID, projectID, identity, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	current, err := h.getQuota(r.Context(), identity)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if current == nil {
		if err := h.client.Create(r.Context(), required); err != nil {
			errors.HandleError(w, r, errors.OAuth2ServerError("unable to create quota").WithError(err))
			return
		}

		w.WriteHeader(http.StatusAccepted)
		return
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := h.client.Patch(r.Context(), updated, client.MergeFrom(current)); err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to updated quota").WithError(err))
		return
	}

	w.WriteHeader(http.StatusAccepted)
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
	if err := rbac.AllowOrganizationScope(r.Context(), "region:externalnetworks", identityapi.Read, organizationID); err != nil {
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

func (h *Handler) convertSecurityGroup(in *unikornv1.SecurityGroup) *openapi.SecurityGroupRead {
	provisioningStatus := coreapi.ResourceProvisioningStatusUnknown

	if condition, err := in.StatusConditionRead(unikornv1core.ConditionAvailable); err == nil {
		provisioningStatus = conversion.ConvertStatusCondition(condition)
	}

	out := &openapi.SecurityGroupRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags, provisioningStatus),
		Spec: openapi.SecurityGroupReadSpec{
			RegionId: in.Labels[constants.RegionLabel],
		},
	}

	return out
}

func (h *Handler) convertSecurityGroupList(in *unikornv1.SecurityGroupList) *openapi.SecurityGroupsRead {
	out := make(openapi.SecurityGroupsRead, len(in.Items))

	for i := range in.Items {
		out[i] = *h.convertSecurityGroup(&in.Items[i])
	}

	return &out
}

func (h *Handler) getSecurityGroup(ctx context.Context, id string) (*unikornv1.SecurityGroup, error) {
	resource := &unikornv1.SecurityGroup{}

	if err := h.client.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: id}, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to get security group").WithError(err)
	}

	return resource, nil
}

func (h *Handler) getSecurityGroupList(ctx context.Context, organizationID string) (*unikornv1.SecurityGroupList, error) {
	result := &unikornv1.SecurityGroupList{}

	options := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			coreconstants.OrganizationLabel: organizationID,
		}),
	}

	if err := h.client.List(ctx, result, options); err != nil {
		return nil, errors.OAuth2ServerError("unable to list security groups").WithError(err)
	}

	slices.SortStableFunc(result.Items, func(a, b unikornv1.SecurityGroup) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return result, nil
}

func (h *Handler) generateSecurityGroup(ctx context.Context, organizationID, projectID string, identity *unikornv1.Identity, in *openapi.SecurityGroupWrite) (*unikornv1.SecurityGroup, error) {
	userinfo, err := authorization.UserinfoFromContext(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to get userinfo").WithError(err)
	}

	resource := &unikornv1.SecurityGroup{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, h.namespace, userinfo.Sub).WithOrganization(organizationID).WithProject(projectID).WithLabel(constants.RegionLabel, identity.Labels[constants.RegionLabel]).
			WithLabel(constants.IdentityLabel, identity.Name).Get(),
		Spec: unikornv1.SecurityGroupSpec{
			Tags:     conversion.GenerateTagList(in.Metadata.Tags),
			Provider: identity.Spec.Provider,
		},
	}

	// Ensure the security is owned by the identity so it is automatically cleaned
	// up on identity deletion.
	if err := controllerutil.SetOwnerReference(identity, resource, h.client.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
		return nil, err
	}

	return resource, nil
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDSecuritygroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "region:securitygroups", identityapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.getSecurityGroupList(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, h.convertSecurityGroupList(result))
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter,
	projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter) {

	if err := rbac.AllowProjectScope(r.Context(), "region:securitygroups", identityapi.Create, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.SecurityGroupWrite{}
	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	identity, err := h.getIdentity(r.Context(), identityID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	securityGroup, err := h.generateSecurityGroup(r.Context(), organizationID, projectID, identity, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.client.Create(r.Context(), securityGroup); err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to create security group").WithError(err))
		return
	}

	util.WriteJSONResponse(w, r, http.StatusCreated, h.convertSecurityGroup(securityGroup))
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter,
	projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, securityGroupID openapi.SecurityGroupIDParameter) {

	if err := rbac.AllowProjectScope(r.Context(), "region:securitygroups", identityapi.Delete, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	resource, err := h.getSecurityGroup(r.Context(), securityGroupID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.client.Delete(r.Context(), resource, foregroundDeleteOptions); err != nil {
		if kerrors.IsNotFound(err) {
			errors.HandleError(w, r, errors.HTTPNotFound().WithError(err))
			return
		}

		errors.HandleError(w, r, errors.OAuth2ServerError("unable to delete security group").WithError(err))
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter,
	projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, securityGroupID openapi.SecurityGroupIDParameter) {

	if err := rbac.AllowProjectScope(r.Context(), "region:securitygroups", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	resource, err := h.getSecurityGroup(r.Context(), securityGroupID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, h.convertSecurityGroup(resource))
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter,
	projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, securityGroupID openapi.SecurityGroupIDParameter) {

	if err := rbac.AllowProjectScope(r.Context(), "region:securitygroups", identityapi.Update, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.SecurityGroupWrite{}
	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	identity, err := h.getIdentity(r.Context(), identityID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	required, err := h.generateSecurityGroup(r.Context(), organizationID, projectID, identity, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	current, err := h.getSecurityGroup(r.Context(), securityGroupID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := h.client.Patch(r.Context(), updated, client.MergeFrom(current)); err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to updated security group").WithError(err))
		return
	}

	w.WriteHeader(http.StatusAccepted)

}

func convertSecurityGroupRulePort(in unikornv1.SecurityGroupRulePort) openapi.SecurityGroupRulePort {
	out := openapi.SecurityGroupRulePort{}

	if in.Number != nil {
		out.Number = in.Number
	}

	if in.Range != nil {
		out.Range = &openapi.SecurityGroupRulePortRange{
			Start: in.Range.Start,
			End:   in.Range.End,
		}
	}

	return out
}

func generateSecurityGroupRulePort(in openapi.SecurityGroupRulePort) *unikornv1.SecurityGroupRulePort {
	out := unikornv1.SecurityGroupRulePort{}

	if in.Number != nil {
		out.Number = in.Number
	}

	if in.Range != nil {
		out.Range = &unikornv1.SecurityGroupRulePortRange{
			Start: in.Range.Start,
			End:   in.Range.End,
		}
	}

	return &out
}

func generateSecurityGroupRuleProtocol(in openapi.SecurityGroupRuleWriteSpecProtocol) *unikornv1.SecurityGroupRuleProtocol {
	var out unikornv1.SecurityGroupRuleProtocol

	switch in {
	case openapi.SecurityGroupRuleWriteSpecProtocolTcp:
		out = unikornv1.TCP
	case openapi.SecurityGroupRuleWriteSpecProtocolUdp:
		out = unikornv1.UDP
	}

	return &out
}

func convertSecurityGroupRuleDirection(in unikornv1.SecurityGroupRuleDirection) openapi.SecurityGroupRuleReadSpecDirection {
	switch in {
	case unikornv1.Ingress:
		return openapi.SecurityGroupRuleReadSpecDirectionIngress
	case unikornv1.Egress:
		return openapi.SecurityGroupRuleReadSpecDirectionEgress
	}

	return ""
}

func generateSecurityGroupRuleDirection(in openapi.SecurityGroupRuleWriteSpecDirection) *unikornv1.SecurityGroupRuleDirection {
	var out unikornv1.SecurityGroupRuleDirection

	switch in {
	case openapi.SecurityGroupRuleWriteSpecDirectionIngress:
		out = unikornv1.Ingress
	case openapi.SecurityGroupRuleWriteSpecDirectionEgress:
		out = unikornv1.Egress
	}

	return &out
}

func (h *Handler) convertSecurityGroupRule(in *unikornv1.SecurityGroupRule) *openapi.SecurityGroupRuleRead {
	provisioningStatus := coreapi.ResourceProvisioningStatusUnknown

	if condition, err := in.StatusConditionRead(unikornv1core.ConditionAvailable); err == nil {
		provisioningStatus = conversion.ConvertStatusCondition(condition)
	}

	out := &openapi.SecurityGroupRuleRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags, provisioningStatus),
		Spec: openapi.SecurityGroupRuleReadSpec{
			Direction: convertSecurityGroupRuleDirection(*in.Spec.Direction),
			Protocol:  openapi.SecurityGroupRuleReadSpecProtocol(*in.Spec.Protocol),
			Cidr:      in.Spec.CIDR.String(),
			Port:      convertSecurityGroupRulePort(*in.Spec.Port),
		},
	}

	return out
}

func (h *Handler) convertSecurityGroupRuleList(in *unikornv1.SecurityGroupRuleList) *openapi.SecurityGroupRulesRead {
	out := make(openapi.SecurityGroupRulesRead, len(in.Items))

	for i := range in.Items {
		out[i] = *h.convertSecurityGroupRule(&in.Items[i])
	}

	return &out
}

func (h *Handler) getSecurityGroupRule(ctx context.Context, id string) (*unikornv1.SecurityGroupRule, error) {
	resource := &unikornv1.SecurityGroupRule{}

	if err := h.client.Get(ctx, client.ObjectKey{Namespace: h.namespace, Name: id}, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to get security group rule").WithError(err)
	}

	return resource, nil
}

func (h *Handler) getSecurityGroupRuleList(ctx context.Context, securityGroupID string) (*unikornv1.SecurityGroupRuleList, error) {
	result := &unikornv1.SecurityGroupRuleList{}

	options := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			constants.SecurityGroupLabel: securityGroupID,
		}),
	}

	if err := h.client.List(ctx, result, options); err != nil {
		return nil, errors.OAuth2ServerError("unable to list security group rules").WithError(err)
	}

	slices.SortStableFunc(result.Items, func(a, b unikornv1.SecurityGroupRule) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return result, nil
}

func (h *Handler) generateSecurityGroupRule(ctx context.Context, organizationID, projectID string, identity *unikornv1.Identity, securityGroup *unikornv1.SecurityGroup, in *openapi.SecurityGroupRuleWrite) (*unikornv1.SecurityGroupRule, error) {
	userinfo, err := authorization.UserinfoFromContext(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to get userinfo").WithError(err)
	}

	_, prefix, err := net.ParseCIDR(in.Spec.Cidr)
	if err != nil {
		return nil, errors.OAuth2InvalidRequest("unable to parse prefix").WithError(err)
	}

	resource := &unikornv1.SecurityGroupRule{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, h.namespace, userinfo.Sub).WithOrganization(organizationID).WithProject(projectID).WithLabel(constants.RegionLabel, identity.Labels[constants.RegionLabel]).
			WithLabel(constants.IdentityLabel, identity.Name).WithLabel(constants.SecurityGroupLabel, securityGroup.Name).Get(),
		Spec: unikornv1.SecurityGroupRuleSpec{
			Tags:      conversion.GenerateTagList(in.Metadata.Tags),
			Direction: generateSecurityGroupRuleDirection(in.Spec.Direction),
			Protocol:  generateSecurityGroupRuleProtocol(in.Spec.Protocol),
			Port:      generateSecurityGroupRulePort(in.Spec.Port),
			CIDR: &unikornv1core.IPv4Prefix{
				IPNet: *prefix,
			},
		},
	}

	// Ensure the security is owned by the security group so it is automatically cleaned
	// up on security group deletion.
	if err := controllerutil.SetOwnerReference(securityGroup, resource, h.client.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
		return nil, err
	}

	return resource, nil
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDRules(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter,
	projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, securityGroupID openapi.SecurityGroupIDParameter) {

	if err := rbac.AllowProjectScope(r.Context(), "region:securitygroups", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.getSecurityGroupRuleList(r.Context(), securityGroupID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, h.convertSecurityGroupRuleList(result))
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDRules(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter,
	projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, securityGroupID openapi.SecurityGroupIDParameter) {

	if err := rbac.AllowProjectScope(r.Context(), "region:securitygroups", identityapi.Create, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.SecurityGroupRuleWrite{}
	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	identity, err := h.getIdentity(r.Context(), identityID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	securityGroup, err := h.getSecurityGroup(r.Context(), securityGroupID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	securityGroupRule, err := h.generateSecurityGroupRule(r.Context(), organizationID, projectID, identity, securityGroup, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.client.Create(r.Context(), securityGroupRule); err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to create security group rule").WithError(err))
		return
	}

	util.WriteJSONResponse(w, r, http.StatusCreated, h.convertSecurityGroupRule(securityGroupRule))
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDRulesRuleID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter,
	projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, securityGroupID openapi.SecurityGroupIDParameter, ruleID openapi.RuleIDParameter) {

	if err := rbac.AllowProjectScope(r.Context(), "region:securitygroups", identityapi.Delete, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	resource, err := h.getSecurityGroupRule(r.Context(), ruleID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.client.Delete(r.Context(), resource); err != nil {
		if kerrors.IsNotFound(err) {
			errors.HandleError(w, r, errors.HTTPNotFound().WithError(err))
			return
		}

		errors.HandleError(w, r, errors.OAuth2ServerError("unable to delete security group rule").WithError(err))
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDRulesRuleID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter,
	projectID openapi.ProjectIDParameter, identityID openapi.IdentityIDParameter, securityGroupID openapi.SecurityGroupIDParameter, ruleID openapi.RuleIDParameter) {

	if err := rbac.AllowProjectScope(r.Context(), "region:securitygroups", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	resource, err := h.getSecurityGroupRule(r.Context(), ruleID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, h.convertSecurityGroupRule(resource))
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDServers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "region:servers", identityapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := server.NewClient(h.client, h.namespace).List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter,
	identityID openapi.IdentityIDParameter) {

	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Create, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.ServerWrite{}
	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	identity, err := h.getIdentity(r.Context(), identityID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	// NOTE: exactly 1 is enforced at the API schema level.
	network, err := h.getNetwork(r.Context(), request.Spec.Networks[0].Id)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := server.NewClient(h.client, h.namespace).Create(r.Context(), organizationID, projectID, identity, network, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter,
	identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter) {

	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Delete, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	err := server.NewClient(h.client, h.namespace).Delete(r.Context(), serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter,
	identityID openapi.IdentityIDParameter, serverID openapi.ServerIDParameter) {

	if err := rbac.AllowProjectScope(r.Context(), "region:servers", identityapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := server.NewClient(h.client, h.namespace).Get(r.Context(), serverID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}
