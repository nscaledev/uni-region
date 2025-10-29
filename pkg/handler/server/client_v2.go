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

package server

import (
	"cmp"
	"context"
	"encoding/json"
	"reflect"
	"slices"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/identity"
	"github.com/unikorn-cloud/region/pkg/handler/network"
	"github.com/unikorn-cloud/region/pkg/handler/region"
	"github.com/unikorn-cloud/region/pkg/handler/util"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func convertSecurityGroupsV2(in []regionv1.ServerSecurityGroupSpec) *openapi.ServerV2SecurityGroupIDList {
	if len(in) == 0 {
		return nil
	}

	out := make(openapi.ServerV2SecurityGroupIDList, len(in))

	for i := range in {
		out[i] = in[i].ID
	}

	return &out
}

func convertPublicIPV2(in *regionv1.ServerPublicIPAllocationSpec) *bool {
	if in == nil {
		return nil
	}

	return &in.Enabled
}

func convertAllowedSourceAddressesV2(in []regionv1.ServerNetworkAddressPair) *openapi.AllowedSourceAddresses {
	if len(in) == 0 {
		return nil
	}

	out := make(openapi.AllowedSourceAddresses, len(in))

	for i := range in {
		out[i] = in[i].CIDR.String()
	}

	return &out
}

func convertNetworkingV2(in *regionv1.Server) *openapi.ServerV2Networking {
	out := openapi.ServerV2Networking{
		SecurityGroups:         convertSecurityGroupsV2(in.Spec.SecurityGroups),
		PublicIP:               convertPublicIPV2(in.Spec.PublicIPAllocation),
		AllowedSourceAddresses: convertAllowedSourceAddressesV2(in.Spec.Networks[0].AllowedAddressPairs),
	}

	if reflect.ValueOf(out).IsZero() {
		return nil
	}

	return &out
}

func convertPowerStateV2(in regionv1.InstanceLifecyclePhase) *openapi.InstanceLifecyclePhase {
	if in == "" {
		return nil
	}

	switch in {
	case regionv1.InstanceLifecyclePhasePending:
		return ptr.To(openapi.Pending)
	case regionv1.InstanceLifecyclePhaseRunning:
		return ptr.To(openapi.Running)
	case regionv1.InstanceLifecyclePhaseStopping:
		return ptr.To(openapi.Stopping)
	case regionv1.InstanceLifecyclePhaseStopped:
		return ptr.To(openapi.Stopped)
	}

	return nil
}

func convertV2(in *regionv1.Server) *openapi.ServerV2Read {
	out := &openapi.ServerV2Read{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.ServerV2Spec{
			FlavorId:   in.Spec.FlavorID,
			ImageId:    in.Spec.Image.ID,
			Networking: convertNetworkingV2(in),
			UserData:   convertUserData(in.Spec.UserData),
		},
		Status: openapi.ServerV2Status{
			RegionId:   in.Labels[constants.RegionLabel],
			NetworkId:  in.Spec.Networks[0].ID,
			PowerState: convertPowerStateV2(in.Status.Phase),
			PrivateIP:  in.Status.PrivateIP,
			PublicIP:   in.Status.PublicIP,
		},
	}

	return out
}

func convertV2List(in *regionv1.ServerList) openapi.ServersV2Read {
	out := make(openapi.ServersV2Read, len(in.Items))

	for i := range in.Items {
		out[i] = *convertV2(&in.Items[i])
	}

	return out
}

// convertCreateToUpdateRequest marshals a create request into an update request
// that can be used with generate().  Updates are a subset of creates (without the
// immutable bits).
func convertCreateToUpdateRequest(in *openapi.ServerV2Create) (*openapi.ServerV2Update, error) {
	t, err := json.Marshal(in)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to marshal request").WithError(err)
	}

	out := &openapi.ServerV2Update{}

	if err := json.Unmarshal(t, out); err != nil {
		return nil, errors.OAuth2ServerError("failed to unmarshal request").WithError(err)
	}

	return out, nil
}

func (c *Client) generateV2(ctx context.Context, organizationID, projectID string, in *openapi.ServerV2Update, network *regionv1.Network) (*regionv1.Server, error) {
	out := &regionv1.Server{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, c.namespace).
			WithOrganization(organizationID).
			WithProject(projectID).
			WithLabel(constants.RegionLabel, network.Labels[constants.RegionLabel]).
			WithLabel(constants.IdentityLabel, network.Labels[constants.IdentityLabel]).
			WithLabel(constants.NetworkLabel, network.Name).
			WithLabel(constants.ResourceAPIVersionLabel, constants.MarshalAPIVersion(2)).
			Get(),
		Spec: regionv1.ServerSpec{
			Tags: conversion.GenerateTagList(in.Metadata.Tags),
		},
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	// Ensure the server is owned by the network so it is automatically cleaned
	// up on cascading deletion.
	if err := controllerutil.SetOwnerReference(network, out, c.client.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
		return nil, err
	}

	return out, nil
}

func (c *Client) ListV2Admin(ctx context.Context, organizationID string, params openapi.GetApiV2OrganizationsOrganizationIDServersParams) (openapi.ServersV2Read, error) {
	selector := labels.SelectorFromSet(map[string]string{
		coreconstants.OrganizationLabel:   organizationID,
		constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
	})

	selector = util.AddProjectIDQuery(selector, params.ProjectID)
	selector = util.AddRegionIDQuery(selector, params.RegionID)
	selector = util.AddNetworkIDQuery(selector, params.NetworkID)

	options := &client.ListOptions{
		Namespace:     c.namespace,
		LabelSelector: selector,
	}

	result := &regionv1.ServerList{}

	if err := c.client.List(ctx, result, options); err != nil {
		return nil, errors.OAuth2ServerError("unable to list servers").WithError(err)
	}

	tagSelector, err := coreutil.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(resource regionv1.Server) bool {
		return !resource.Spec.Tags.ContainsAll(tagSelector)
	})

	slices.SortStableFunc(result.Items, func(a, b regionv1.Server) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertV2List(result), nil
}

func (c *Client) ListV2(ctx context.Context, organizationID, projectID string, params openapi.GetApiV2OrganizationsOrganizationIDProjectsProjectIDServersParams) (openapi.ServersV2Read, error) {
	selector := labels.SelectorFromSet(map[string]string{
		coreconstants.OrganizationLabel:   organizationID,
		coreconstants.ProjectLabel:        projectID,
		constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
	})

	selector = util.AddRegionIDQuery(selector, params.RegionID)
	selector = util.AddNetworkIDQuery(selector, params.NetworkID)

	options := &client.ListOptions{
		Namespace:     c.namespace,
		LabelSelector: selector,
	}

	result := &regionv1.ServerList{}

	if err := c.client.List(ctx, result, options); err != nil {
		return nil, errors.OAuth2ServerError("unable to list servers").WithError(err)
	}

	tagSelector, err := coreutil.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(resource regionv1.Server) bool {
		return !resource.Spec.Tags.ContainsAll(tagSelector)
	})

	slices.SortStableFunc(result.Items, func(a, b regionv1.Server) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertV2List(result), nil
}

func (c *Client) CreateV2(ctx context.Context, organizationID, projectID string, request *openapi.ServerV2Create) (*openapi.ServerV2Read, error) {
	network, err := network.New(c.client, c.namespace, nil).GetRaw(ctx, organizationID, projectID, request.Spec.NetworkId)
	if err != nil {
		return nil, err
	}

	commonRequest, err := convertCreateToUpdateRequest(request)
	if err != nil {
		return nil, err
	}

	resource, err := c.generateV2(ctx, organizationID, projectID, commonRequest, network)
	if err != nil {
		return nil, err
	}

	if err := c.client.Create(ctx, resource); err != nil {
		return nil, errors.OAuth2ServerError("unable to create security group").WithError(err)
	}

	return convertV2(resource), nil
}

func (c *Client) GetV2Raw(ctx context.Context, organizationID, projectID, serverID string) (*regionv1.Server, error) {
	result, err := c.get(ctx, organizationID, projectID, serverID)
	if err != nil {
		return nil, err
	}

	// Only allow access to resources created by this API (temporarily).
	v, ok := result.Labels[constants.ResourceAPIVersionLabel]
	if !ok {
		return nil, errors.HTTPNotFound()
	}

	version, err := constants.UnmarshalAPIVersion(v)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to parse API version")
	}

	if version != 2 {
		return nil, errors.HTTPNotFound()
	}

	return result, nil
}

func (c *Client) GetV2(ctx context.Context, organizationID, projectID, serverID string) (*openapi.ServerV2Read, error) {
	result, err := c.GetV2Raw(ctx, organizationID, projectID, serverID)
	if err != nil {
		return nil, err
	}

	return convertV2(result), nil
}

func (c *Client) UpdateV2(ctx context.Context, organizationID, projectID, serverID string, request *openapi.ServerV2Update) (*openapi.ServerV2Read, error) {
	current, err := c.GetV2Raw(ctx, organizationID, projectID, serverID)
	if err != nil {
		return nil, err
	}

	if current.DeletionTimestamp != nil {
		return nil, errors.OAuth2InvalidRequest("server is being deleted")
	}

	// Get the network, required for generation.
	network, err := network.New(c.client, c.namespace, nil).GetRaw(ctx, organizationID, projectID, current.Spec.Networks[0].ID)
	if err != nil {
		return nil, err
	}

	required, err := c.generateV2(ctx, organizationID, projectID, request, network)
	if err != nil {
		return nil, err
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return nil, errors.OAuth2ServerError("unable to update server").WithError(err)
	}

	return convertV2(updated), nil
}

func (c *Client) DeleteV2(ctx context.Context, organizationID, projectID, serverID string) error {
	resource, err := c.GetV2Raw(ctx, organizationID, projectID, serverID)
	if err != nil {
		return err
	}

	if err := c.client.Delete(ctx, resource, util.ForegroundDeleteOptions()); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("unable to delete server").WithError(err)
	}

	return nil
}

func (c *Client) getServerIdentityAndProvider(ctx context.Context, organizationID, projectID, serverID string) (*regionv1.Server, *regionv1.Identity, types.Provider, error) {
	server, err := c.GetV2Raw(ctx, organizationID, projectID, serverID)
	if err != nil {
		return nil, nil, nil, err
	}

	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, server.Labels[constants.IdentityLabel])
	if err != nil {
		return nil, nil, nil, err
	}

	provider, err := region.NewClient(c.client, c.namespace).Provider(ctx, server.Labels[constants.RegionLabel])
	if err != nil {
		return nil, nil, nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	return server, identity, provider, nil
}

func (c *Client) StartV2(ctx context.Context, organizationID, projectID, serverID string) error {
	server, identity, provider, err := c.getServerIdentityAndProvider(ctx, organizationID, projectID, serverID)
	if err != nil {
		return err
	}

	if err := provider.StartServer(ctx, identity, server); err != nil {
		return err
	}

	return nil
}

func (c *Client) StopV2(ctx context.Context, organizationID, projectID, serverID string) error {
	server, identity, provider, err := c.getServerIdentityAndProvider(ctx, organizationID, projectID, serverID)
	if err != nil {
		return err
	}

	if err := provider.StopServer(ctx, identity, server); err != nil {
		return err
	}

	return nil
}

func (c *Client) RebootV2(ctx context.Context, organizationID, projectID, serverID string, hard bool) error {
	server, identity, provider, err := c.getServerIdentityAndProvider(ctx, organizationID, projectID, serverID)
	if err != nil {
		return err
	}

	if err := provider.RebootServer(ctx, identity, server, hard); err != nil {
		return err
	}

	return nil
}

func (c *Client) ConsoleOutputV2(ctx context.Context, organizationID, projectID, serverID string, params openapi.GetApiV2OrganizationsOrganizationIDProjectsProjectIDServersServerIDConsoleoutputParams) (*openapi.ConsoleOutputResponse, error) {
	server, identity, provider, err := c.getServerIdentityAndProvider(ctx, organizationID, projectID, serverID)
	if err != nil {
		return nil, err
	}

	contents, err := provider.GetConsoleOutput(ctx, identity, server, params.Length)
	if err != nil {
		return nil, err
	}

	result := &openapi.ConsoleOutputResponse{
		Contents: contents,
	}

	return result, nil
}

func (c *Client) ConsoleSessionV2(ctx context.Context, organizationID, projectID, serverID string) (*openapi.ConsoleSessionResponse, error) {
	server, identity, provider, err := c.getServerIdentityAndProvider(ctx, organizationID, projectID, serverID)
	if err != nil {
		return nil, err
	}

	url, err := provider.CreateConsoleSession(ctx, identity, server)
	if err != nil {
		return nil, err
	}

	result := &openapi.ConsoleSessionResponse{
		Url: url,
	}

	return result, nil
}
