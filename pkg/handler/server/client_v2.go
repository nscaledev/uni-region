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
	"net"
	"reflect"
	"slices"

	corev1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
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
		return ptr.To(openapi.InstanceLifecyclePhasePending)
	case regionv1.InstanceLifecyclePhaseRunning:
		return ptr.To(openapi.InstanceLifecyclePhaseRunning)
	case regionv1.InstanceLifecyclePhaseStopping:
		return ptr.To(openapi.InstanceLifecyclePhaseStopping)
	case regionv1.InstanceLifecyclePhaseStopped:
		return ptr.To(openapi.InstanceLifecyclePhaseStopped)
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

func generatePublicIPAllocation(in *openapi.ServerV2Networking) *regionv1.ServerPublicIPAllocationSpec {
	if in == nil || in.PublicIP == nil || !*in.PublicIP {
		return nil
	}

	return &regionv1.ServerPublicIPAllocationSpec{
		Enabled: true,
	}
}

func generateSecurityGroups(in *openapi.ServerV2Networking) []regionv1.ServerSecurityGroupSpec {
	if in == nil || in.SecurityGroups == nil || len(*in.SecurityGroups) == 0 {
		return nil
	}

	out := make([]regionv1.ServerSecurityGroupSpec, len(*in.SecurityGroups))

	for i, id := range *in.SecurityGroups {
		out[i] = regionv1.ServerSecurityGroupSpec{
			ID: id,
		}
	}

	return out
}

func generateAllowedAddressPairs(in *openapi.ServerV2Networking) []regionv1.ServerNetworkAddressPair {
	if in == nil || in.AllowedSourceAddresses == nil || len(*in.AllowedSourceAddresses) == 0 {
		return nil
	}

	prefixes := *in.AllowedSourceAddresses

	out := make([]regionv1.ServerNetworkAddressPair, len(prefixes))

	for i := range prefixes {
		_, prefix, _ := net.ParseCIDR(prefixes[i])

		out[i] = regionv1.ServerNetworkAddressPair{
			CIDR: corev1.IPv4Prefix{
				IPNet: *prefix,
			},
		}
	}

	return out
}

func generateNetworks(networkID string, in *openapi.ServerV2Networking) []regionv1.ServerNetworkSpec {
	out := regionv1.ServerNetworkSpec{
		ID:                  networkID,
		AllowedAddressPairs: generateAllowedAddressPairs(in),
	}

	return []regionv1.ServerNetworkSpec{out}
}

func generateUserData(in *[]byte) []byte {
	if in == nil {
		return nil
	}

	return *in
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
			Tags:     conversion.GenerateTagList(in.Metadata.Tags),
			FlavorID: in.Spec.FlavorId,
			Image: &regionv1.ServerImage{
				ID: in.Spec.ImageId,
			},
			PublicIPAllocation: generatePublicIPAllocation(in.Spec.Networking),
			SecurityGroups:     generateSecurityGroups(in.Spec.Networking),
			Networks:           generateNetworks(network.Name, in.Spec.Networking),
			UserData:           generateUserData(in.Spec.UserData),
		},
	}

	if err := util.InjectUserPrincipal(ctx, organizationID, projectID); err != nil {
		return nil, errors.OAuth2ServerError("unable to set principal information").WithError(err)
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

func (c *Client) ListV2(ctx context.Context, params openapi.GetApiV2ServersParams) (openapi.ServersV2Read, error) {
	selector := labels.SelectorFromSet(map[string]string{
		constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
	})

	var err error

	selector, err = rbac.AddOrganizationAndProjectIDQuery(ctx, selector, util.OrganizationIDQuery(params.OrganizationID), util.ProjectIDQuery(params.ProjectID))
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to add identity label selector").WithError(err)
	}

	selector, err = util.AddRegionIDQuery(selector, params.RegionID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to add region label selector").WithError(err)
	}

	selector, err = util.AddNetworkIDQuery(selector, params.NetworkID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to add network label selector").WithError(err)
	}

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
		return !resource.Spec.Tags.ContainsAll(tagSelector) ||
			rbac.AllowProjectScope(ctx, "region:servers", identityapi.Read, resource.Labels[coreconstants.OrganizationLabel], resource.Labels[coreconstants.ProjectLabel]) != nil
	})

	slices.SortStableFunc(result.Items, func(a, b regionv1.Server) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertV2List(result), nil
}

func (c *Client) CreateV2(ctx context.Context, request *openapi.ServerV2Create) (*openapi.ServerV2Read, error) {
	network, err := network.New(c.client, c.namespace, nil).GetV2Raw(ctx, request.Spec.NetworkId)
	if err != nil {
		return nil, err
	}

	organizationID := network.Labels[coreconstants.OrganizationLabel]
	projectID := network.Labels[coreconstants.ProjectLabel]

	if err := rbac.AllowProjectScope(ctx, "region:servers", identityapi.Create, organizationID, projectID); err != nil {
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
		return nil, errors.OAuth2ServerError("unable to create server").WithError(err)
	}

	return convertV2(resource), nil
}

func (c *Client) GetV2Raw(ctx context.Context, serverID string) (*regionv1.Server, error) {
	result := &regionv1.Server{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: serverID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to lookup server").WithError(err)
	}

	if err := rbac.AllowProjectScope(ctx, "region:servers", identityapi.Read, result.Labels[coreconstants.OrganizationLabel], result.Labels[coreconstants.ProjectLabel]); err != nil {
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

func (c *Client) GetV2(ctx context.Context, serverID string) (*openapi.ServerV2Read, error) {
	result, err := c.GetV2Raw(ctx, serverID)
	if err != nil {
		return nil, err
	}

	return convertV2(result), nil
}

func (c *Client) UpdateV2(ctx context.Context, serverID string, request *openapi.ServerV2Update) (*openapi.ServerV2Read, error) {
	current, err := c.GetV2Raw(ctx, serverID)
	if err != nil {
		return nil, err
	}

	if err := rbac.AllowProjectScope(ctx, "region:servers", identityapi.Delete, current.Labels[coreconstants.OrganizationLabel], current.Labels[coreconstants.ProjectLabel]); err != nil {
		return nil, err
	}

	if current.DeletionTimestamp != nil {
		return nil, errors.OAuth2InvalidRequest("server is being deleted")
	}

	// Get the network, required for generation.
	network, err := network.New(c.client, c.namespace, nil).GetV2Raw(ctx, current.Spec.Networks[0].ID)
	if err != nil {
		return nil, err
	}

	required, err := c.generateV2(ctx, current.Labels[coreconstants.OrganizationLabel], current.Labels[coreconstants.ProjectLabel], request, network)
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

func (c *Client) DeleteV2(ctx context.Context, serverID string) error {
	resource, err := c.GetV2Raw(ctx, serverID)
	if err != nil {
		return err
	}

	if err := rbac.AllowProjectScope(ctx, "region:servers", identityapi.Delete, resource.Labels[coreconstants.OrganizationLabel], resource.Labels[coreconstants.ProjectLabel]); err != nil {
		return err
	}

	if err := c.client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("unable to delete server").WithError(err)
	}

	return nil
}

// serverProvider gloms together the operations needed to provision servers.
type serverProvider interface {
	types.Server
	types.ServerConsole
	types.Identity
}

func (c *Client) getServerIdentityAndProvider(ctx context.Context, serverID string) (*regionv1.Server, *regionv1.Identity, serverProvider, error) {
	server, err := c.GetV2Raw(ctx, serverID)
	if err != nil {
		return nil, nil, nil, err
	}

	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, server.Labels[coreconstants.OrganizationLabel], server.Labels[coreconstants.ProjectLabel], server.Labels[constants.IdentityLabel])
	if err != nil {
		return nil, nil, nil, err
	}

	provider, err := region.NewClient(c.client, c.namespace).Provider(ctx, server.Labels[constants.RegionLabel])
	if err != nil {
		return nil, nil, nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	return server, identity, provider, nil
}

func (c *Client) SSHKey(ctx context.Context, serverID string) (*openapi.SshKey, error) {
	_, identity, _, err := c.getServerIdentityAndProvider(ctx, serverID)
	if err != nil {
		return nil, err
	}

	var openstackIdentity regionv1.OpenstackIdentity

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: identity.Namespace, Name: identity.Name}, &openstackIdentity); err != nil {
		return nil, errors.OAuth2ServerError("failed to load server identity information").WithError(err)
	}

	if len(openstackIdentity.Spec.SSHPrivateKey) == 0 {
		return nil, errors.OAuth2ServerError("server SSH key unavailable").WithError(err)
	}

	out := &openapi.SshKey{
		PrivateKey: string(openstackIdentity.Spec.SSHPrivateKey),
	}

	return out, nil
}

func (c *Client) StartV2(ctx context.Context, serverID string) error {
	server, identity, provider, err := c.getServerIdentityAndProvider(ctx, serverID)
	if err != nil {
		return err
	}

	if err := provider.StartServer(ctx, identity, server); err != nil {
		return err
	}

	return nil
}

func (c *Client) StopV2(ctx context.Context, serverID string) error {
	server, identity, provider, err := c.getServerIdentityAndProvider(ctx, serverID)
	if err != nil {
		return err
	}

	if err := provider.StopServer(ctx, identity, server); err != nil {
		return err
	}

	return nil
}

func (c *Client) RebootV2(ctx context.Context, serverID string, hard bool) error {
	server, identity, provider, err := c.getServerIdentityAndProvider(ctx, serverID)
	if err != nil {
		return err
	}

	if err := provider.RebootServer(ctx, identity, server, hard); err != nil {
		return err
	}

	return nil
}

func (c *Client) ConsoleOutputV2(ctx context.Context, serverID string, params openapi.GetApiV2ServersServerIDConsoleoutputParams) (*openapi.ConsoleOutputResponse, error) {
	server, identity, provider, err := c.getServerIdentityAndProvider(ctx, serverID)
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

func (c *Client) ConsoleSessionV2(ctx context.Context, serverID string) (*openapi.ConsoleSessionResponse, error) {
	server, identity, provider, err := c.getServerIdentityAndProvider(ctx, serverID)
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
