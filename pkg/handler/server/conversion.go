/*
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

package server

import (
	"context"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// convertList converts from a custom resource list into the API definition.
func convertList(in *unikornv1.ServerList) openapi.ServersRead {
	out := make(openapi.ServersRead, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i])
	}

	return out
}

// convert converts from a custom resource into the API definition.
func convert(in *unikornv1.Server) *openapi.ServerRead {
	provisioningStatus := coreapi.ResourceProvisioningStatusUnknown

	if condition, err := in.StatusConditionRead(unikornv1core.ConditionAvailable); err == nil {
		provisioningStatus = conversion.ConvertStatusCondition(condition)
	}

	out := &openapi.ServerRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, provisioningStatus),
		Spec: openapi.ServerReadSpec{
			FlavorId:           in.Spec.FlavorID,
			Image:              convertServerImage(in.Spec.Image),
			Networks:           convertServerNetworks(in.Spec.Networks),
			PublicIPAllocation: convertServerPublicIPAllocation(in.Spec.PublicIPAllocation),
			SecurityGroups:     convertServerSecurityGroups(in.Spec.SecurityGroups),
		},
		Status: openapi.ServerReadStatus{
			PrivateIP: in.Status.PrivateIP,
			PublicIP:  in.Status.PublicIP,
		},
	}

	if tags := convertTags(in.Spec.Tags); tags != nil {
		out.Spec.Tags = &tags
	}

	return out
}

func convertServerImage(in *unikornv1.ServerImage) openapi.ServerImage {
	return openapi.ServerImage{
		Id: in.ID,
	}
}

func convertServerNetworks(in []unikornv1.ServerNetworkSpec) openapi.ServerNetworkList {
	out := make(openapi.ServerNetworkList, len(in))

	for i := range in {
		out[i] = convertServerNetwork(&in[i])
	}

	return out
}

func convertServerNetwork(in *unikornv1.ServerNetworkSpec) openapi.ServerNetwork {
	return openapi.ServerNetwork{
		Id: in.ID,
	}
}

func convertServerPublicIPAllocation(in *unikornv1.ServerPublicIPAllocationSpec) *openapi.ServerPublicIPAllocation {
	if in == nil {
		return nil
	}

	return &openapi.ServerPublicIPAllocation{
		Enabled: in.Enabled,
	}
}

func convertServerSecurityGroups(in []unikornv1.ServerSecurityGroupSpec) *openapi.ServerSecurityGroupList {
	if in == nil {
		return nil
	}

	out := make(openapi.ServerSecurityGroupList, len(in))

	for i := range in {
		out[i] = convertServerSecurityGroup(&in[i])
	}

	return &out
}

func convertServerSecurityGroup(in *unikornv1.ServerSecurityGroupSpec) openapi.ServerSecurityGroup {
	return openapi.ServerSecurityGroup{
		Id: in.ID,
	}
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

type generator struct {
	// client allows Kubernetes API access.
	client client.Client
	// namespace the resource is provisioned in.
	namespace string
	// organizationID is the unique organization identifier.
	organizationID string
	// projectID is the unique project identifier.
	projectID string
	// identity is the identity the resource is provisioned for.
	identity *unikornv1.Identity
}

func newGenerator(client client.Client, namespace, organizationID, projectID string, identity *unikornv1.Identity) *generator {
	return &generator{
		client:         client,
		namespace:      namespace,
		organizationID: organizationID,
		projectID:      projectID,
		identity:       identity,
	}
}

func (g *generator) generate(ctx context.Context, in *openapi.ServerWrite) (*unikornv1.Server, error) {
	userinfo, err := authorization.UserinfoFromContext(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to get userinfo").WithError(err)
	}

	resource := &unikornv1.Server{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, g.namespace, userinfo.Sub).WithOrganization(g.organizationID).WithProject(g.projectID).WithLabel(constants.RegionLabel, g.identity.Labels[constants.RegionLabel]).
			WithLabel(constants.IdentityLabel, g.identity.Name).Get(),
		Spec: unikornv1.ServerSpec{
			Tags:               generateTagList(in.Spec.Tags),
			Provider:           g.identity.Spec.Provider,
			FlavorID:           in.Spec.FlavorId,
			Image:              g.generateImage(&in.Spec.Image),
			PublicIPAllocation: g.generatePublicIPAllocation(in.Spec.PublicIPAllocation),
			SecurityGroups:     g.generateSecurityGroups(in.Spec.SecurityGroups),
			Networks:           g.generateNetworks(in.Spec.Networks),
		},
	}

	// Ensure the server is owned by the identity so it is automatically cleaned
	// up on identity deletion.
	if err := controllerutil.SetOwnerReference(g.identity, resource, g.client.Scheme()); err != nil {
		return nil, err
	}

	return resource, nil
}

func (g *generator) generateImage(in *openapi.ServerImage) *unikornv1.ServerImage {
	out := &unikornv1.ServerImage{
		ID: in.Id,
	}

	if in.Selector != nil {
		out.Selector = &unikornv1.ServerImageSelector{
			OS:      in.Selector.Os,
			Version: in.Selector.Version,
		}
	}

	return out
}

func (g *generator) generatePublicIPAllocation(in *openapi.ServerPublicIPAllocation) *unikornv1.ServerPublicIPAllocationSpec {
	if in == nil {
		return nil
	}

	return &unikornv1.ServerPublicIPAllocationSpec{
		Enabled: in.Enabled,
	}
}

func (g *generator) generateSecurityGroups(in *openapi.ServerSecurityGroupList) []unikornv1.ServerSecurityGroupSpec {
	if in == nil {
		return nil
	}

	out := make([]unikornv1.ServerSecurityGroupSpec, len(*in))

	for i, sg := range *in {
		out[i] = unikornv1.ServerSecurityGroupSpec{
			ID: sg.Id,
		}
	}

	return out
}

func (g *generator) generateNetworks(in openapi.ServerNetworkList) []unikornv1.ServerNetworkSpec {
	out := make([]unikornv1.ServerNetworkSpec, len(in))

	for i, network := range in {
		out[i] = unikornv1.ServerNetworkSpec{
			ID: network.Id,
		}
	}

	return out
}
