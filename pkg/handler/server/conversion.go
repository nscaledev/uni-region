/*
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

package server

import (
	"context"
	"net"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/identity"
	"github.com/unikorn-cloud/region/pkg/handler/network"
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
	out := &openapi.ServerRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.ServerSpec{
			FlavorId:           in.Spec.FlavorID,
			ImageId:            in.Spec.Image.ID,
			Networks:           convertNetworks(in.Spec.Networks),
			PublicIPAllocation: convertPublicIPAllocation(in.Spec.PublicIPAllocation),
			SecurityGroups:     convertSecurityGroups(in.Spec.SecurityGroups),
			UserData:           convertUserData(in.Spec.UserData),
		},
		Status: openapi.ServerStatus{
			Phase:     convertInstanceLifecyclePhase(in.Status.Phase),
			PrivateIP: in.Status.PrivateIP,
			PublicIP:  in.Status.PublicIP,
		},
	}

	return out
}

func convertNetworks(in []unikornv1.ServerNetworkSpec) openapi.ServerNetworkList {
	out := make(openapi.ServerNetworkList, len(in))

	for i := range in {
		out[i] = convertNetwork(&in[i])
	}

	return out
}

func convertNetwork(in *unikornv1.ServerNetworkSpec) openapi.ServerNetwork {
	return openapi.ServerNetwork{
		Id:                  in.ID,
		AllowedAddressPairs: convertNetworkAddressPairs(in.AllowedAddressPairs),
	}
}

func convertNetworkAddressPairs(in []unikornv1.ServerNetworkAddressPair) *openapi.ServerNetworkAllowedAddressPairList {
	if in == nil {
		return nil
	}

	out := make(openapi.ServerNetworkAllowedAddressPairList, len(in))

	for i := range in {
		out[i] = openapi.ServerNetworkAllowedAddressPair{
			Cidr:       in[i].CIDR.String(),
			MacAddress: &in[i].MACAddress,
		}
	}

	return &out
}

func convertPublicIPAllocation(in *unikornv1.ServerPublicIPAllocationSpec) *openapi.ServerPublicIPAllocation {
	if in == nil {
		return nil
	}

	return &openapi.ServerPublicIPAllocation{
		Enabled: in.Enabled,
	}
}

func convertSecurityGroups(in []unikornv1.ServerSecurityGroupSpec) *openapi.ServerSecurityGroupList {
	if in == nil {
		return nil
	}

	out := make(openapi.ServerSecurityGroupList, len(in))

	for i := range in {
		out[i] = convertSecurityGroup(&in[i])
	}

	return &out
}

func convertSecurityGroup(in *unikornv1.ServerSecurityGroupSpec) openapi.ServerSecurityGroup {
	return openapi.ServerSecurityGroup{
		Id: in.ID,
	}
}

func convertUserData(in []byte) *[]byte {
	if in == nil {
		return nil
	}

	return &in
}

func convertInstanceLifecyclePhase(in unikornv1.InstanceLifecyclePhase) openapi.InstanceLifecyclePhase {
	switch in {
	case unikornv1.InstanceLifecyclePhasePending:
		return openapi.Pending
	case unikornv1.InstanceLifecyclePhaseRunning:
		return openapi.Running
	case unikornv1.InstanceLifecyclePhaseStopping:
		return openapi.Stopping
	case unikornv1.InstanceLifecyclePhaseStopped:
		return openapi.Stopped
	default:
		return openapi.Pending
	}
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
	// identity is the unique identity identifier.
	identityID string
}

func newGenerator(client client.Client, namespace, organizationID, projectID, identityID string) *generator {
	return &generator{
		client:         client,
		namespace:      namespace,
		organizationID: organizationID,
		projectID:      projectID,
		identityID:     identityID,
	}
}

func (g *generator) generate(ctx context.Context, in *openapi.ServerWrite) (*unikornv1.Server, error) {
	identity, err := identity.New(g.client, g.namespace).GetRaw(ctx, g.organizationID, g.projectID, g.identityID)
	if err != nil {
		return nil, err
	}

	// TODO: The API enforces a single network.
	network, err := network.New(g.client, g.namespace).GetRaw(ctx, g.organizationID, g.projectID, in.Spec.Networks[0].Id)
	if err != nil {
		return nil, err
	}

	out := &unikornv1.Server{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, g.namespace).WithOrganization(g.organizationID).WithProject(g.projectID).WithLabel(constants.RegionLabel, identity.Labels[constants.RegionLabel]).
			WithLabel(constants.IdentityLabel, identity.Name).Get(),
		Spec: unikornv1.ServerSpec{
			Tags:     conversion.GenerateTagList(in.Metadata.Tags),
			Provider: identity.Spec.Provider,
			FlavorID: in.Spec.FlavorId,
			Image: &unikornv1.ServerImage{
				ID: in.Spec.ImageId,
			},
			PublicIPAllocation: g.generatePublicIPAllocation(in.Spec.PublicIPAllocation),
			SecurityGroups:     g.generateSecurityGroups(in.Spec.SecurityGroups),
			Networks:           g.generateNetworks(in.Spec.Networks),
			UserData:           g.generateUserData(in.Spec.UserData),
		},
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	// Ensure the server is owned by the network so it is automatically cleaned
	// up on cascading deletion.
	if err := controllerutil.SetOwnerReference(network, out, g.client.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
		return nil, err
	}

	return out, nil
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
		addressPairs := g.generateAllowedAddressPairs(network.AllowedAddressPairs)

		out[i] = unikornv1.ServerNetworkSpec{
			ID:                  network.Id,
			AllowedAddressPairs: addressPairs,
		}
	}

	return out
}

func (g *generator) generateAllowedAddressPairs(in *openapi.ServerNetworkAllowedAddressPairList) []unikornv1.ServerNetworkAddressPair {
	out := []unikornv1.ServerNetworkAddressPair{}

	if in == nil {
		return out
	}

	for _, pair := range *in {
		_, prefix, err := net.ParseCIDR(pair.Cidr)
		if err != nil {
			// ignore this address pair
			continue
		}

		var macAddress string

		if pair.MacAddress != nil {
			macAddress = *pair.MacAddress
		}

		out = append(out, unikornv1.ServerNetworkAddressPair{
			CIDR: unikornv1core.IPv4Prefix{
				IPNet: *prefix,
			},
			MACAddress: macAddress,
		})
	}

	return out
}

func (g *generator) generateUserData(in *[]byte) []byte {
	if in == nil {
		return nil
	}

	return *in
}
