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

package securitygroup

import (
	"cmp"
	"context"
	"encoding/json"
	"slices"

	corev1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
	errorsv2 "github.com/unikorn-cloud/core/pkg/server/v2/errors"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/network"
	"github.com/unikorn-cloud/region/pkg/handler/util"
	"github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func convertPrefixV2(in *corev1.IPv4Prefix) *string {
	if in == nil {
		return nil
	}

	return ptr.To(in.String())
}

func convertRuleV2(in *regionv1.SecurityGroupRule) *openapi.SecurityGroupRuleV2 {
	out := &openapi.SecurityGroupRuleV2{
		Direction: convertDirection(in.Direction),
		Protocol:  convertProtocol(in.Protocol),
		Prefix:    convertPrefixV2(in.CIDR),
	}

	if in.Protocol == regionv1.TCP || in.Protocol == regionv1.UDP && in.Port != nil {
		if in.Port != nil {
			if in.Port.Number != nil {
				out.Port = in.Port.Number
			} else if in.Port.Range != nil {
				out.Port = &in.Port.Range.Start
				out.PortMax = &in.Port.Range.End
			}
		}
	}

	return out
}

func convertRuleListV2(in []regionv1.SecurityGroupRule) openapi.SecurityGroupRuleV2List {
	if len(in) == 0 {
		return nil
	}

	out := make(openapi.SecurityGroupRuleV2List, len(in))

	for i := range in {
		out[i] = *convertRuleV2(&in[i])
	}

	return out
}

func convertV2(in *regionv1.SecurityGroup) *openapi.SecurityGroupV2Read {
	return &openapi.SecurityGroupV2Read{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.SecurityGroupV2Spec{
			Rules: convertRuleListV2(in.Spec.Rules),
		},
		Status: openapi.SecurityGroupV2Status{
			RegionId:  in.Labels[constants.RegionLabel],
			NetworkId: in.Labels[constants.NetworkLabel],
		},
	}
}

func convertV2List(in *regionv1.SecurityGroupList) openapi.SecurityGroupsV2Read {
	out := make(openapi.SecurityGroupsV2Read, len(in.Items))

	for i := range in.Items {
		out[i] = *convertV2(&in.Items[i])
	}

	return out
}

func (c *Client) ListV2(ctx context.Context, params openapi.GetApiV2SecuritygroupsParams) (openapi.SecurityGroupsV2Read, error) {
	tagSelector, err := coreutil.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	selector := labels.SelectorFromSet(map[string]string{
		constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
	})

	selector, err = rbac.AddOrganizationAndProjectIDQuery(ctx, selector, util.OrganizationIDQuery(params.OrganizationID), util.ProjectIDQuery(params.ProjectID))
	if err != nil {
		return nil, err
	}

	selector, err = util.AddRegionIDQuery(selector, params.RegionID)
	if err != nil {
		return nil, err
	}

	selector, err = util.AddNetworkIDQuery(selector, params.NetworkID)
	if err != nil {
		return nil, err
	}

	opts := []client.ListOption{
		&client.ListOptions{
			Namespace:     c.namespace,
			LabelSelector: selector,
		},
	}

	var list regionv1.SecurityGroupList
	if err := c.client.List(ctx, &list, opts...); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve security groups: %w", err).
			Prefixed()

		return nil, err
	}

	list.Items = slices.DeleteFunc(list.Items, func(resource regionv1.SecurityGroup) bool {
		return !resource.Spec.Tags.ContainsAll(tagSelector) ||
			rbac.AllowProjectScope(ctx, "region:securitygroups:v2", identityapi.Read, resource.Labels[coreconstants.OrganizationLabel], resource.Labels[coreconstants.ProjectLabel]) != nil
	})

	slices.SortStableFunc(list.Items, func(a, b regionv1.SecurityGroup) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertV2List(&list), nil
}

func (c *Client) GetV2Raw(ctx context.Context, securityGroupID string) (*regionv1.SecurityGroup, error) {
	key := client.ObjectKey{
		Namespace: c.namespace,
		Name:      securityGroupID,
	}

	var securityGroup regionv1.SecurityGroup
	if err := c.client.Get(ctx, key, &securityGroup); err != nil {
		if kerrors.IsNotFound(err) {
			err = errorsv2.NewResourceMissingError("security group").
				WithCause(err).
				Prefixed()

			return nil, err
		}

		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve security group: %w", err).
			Prefixed()

		return nil, err
	}

	if err := rbac.AllowProjectScope(ctx, "region:securitygroups:v2", identityapi.Read, securityGroup.Labels[coreconstants.OrganizationLabel], securityGroup.Labels[coreconstants.ProjectLabel]); err != nil {
		return nil, err
	}

	// Only allow access to resources created by this API (temporarily).
	if err := util.EnsureObjectAPIVersion("security group", &securityGroup, 2); err != nil {
		return nil, err
	}

	return &securityGroup, nil
}

func (c *Client) GetV2(ctx context.Context, securityGroupID string) (*openapi.SecurityGroupV2Read, error) {
	result, err := c.GetV2Raw(ctx, securityGroupID)
	if err != nil {
		return nil, err
	}

	return convertV2(result), nil
}

// convertCreateToUpdateRequest marshals a create request into an update request
// that can be used with generate().  Updates are a subset of creates (without the
// immutable bits).
func convertCreateToUpdateRequest(in *openapi.SecurityGroupV2Create) (*openapi.SecurityGroupV2Update, error) {
	bs, err := json.Marshal(in)
	if err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to marshal security group create request: %w", err).
			Prefixed()

		return nil, err
	}

	var params openapi.SecurityGroupV2Update
	if err := json.Unmarshal(bs, &params); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to unmarshal data to security group update request: %w", err).
			Prefixed()

		return nil, err
	}

	return &params, nil
}

func protocolIsLayer4(in openapi.NetworkProtocol) bool {
	return in == openapi.NetworkProtocolTcp || in == openapi.NetworkProtocolUdp
}

func validateRule(in *openapi.SecurityGroupRuleV2) error {
	if !protocolIsLayer4(in.Protocol) && in.Port != nil {
		return errorsv2.NewInvalidRequestError().
			WithSimpleCause("port specified in security group rule for a layer 3 protocol").
			WithErrorDescription("Port cannot be configured for non-layer 4 protocols.").
			Prefixed()
	}

	if protocolIsLayer4(in.Protocol) && in.Port != nil && in.PortMax != nil {
		if *in.Port >= *in.PortMax {
			return errorsv2.NewInvalidRequestError().
				WithSimpleCause("invalid port range specified in security group rule").
				WithErrorDescription("The 'port' must be less than the 'portMax' when specifying a port range.").
				Prefixed()
		}
	}

	return nil
}

func generateRuleV2(in *openapi.SecurityGroupRuleV2) (*regionv1.SecurityGroupRule, error) {
	prefix, err := generatePrefix(in.Prefix)
	if err != nil {
		return nil, err
	}

	if err := validateRule(in); err != nil {
		return nil, err
	}

	out := &regionv1.SecurityGroupRule{
		Direction: generateDirection(in.Direction),
		Protocol:  generateProtocol(in.Protocol),
		CIDR:      prefix,
	}

	if in.Protocol == openapi.NetworkProtocolTcp || in.Protocol == openapi.NetworkProtocolUdp {
		if in.Port != nil {
			if in.PortMax != nil {
				out.Port = &regionv1.SecurityGroupRulePort{
					Range: &regionv1.SecurityGroupRulePortRange{
						Start: *in.Port,
						End:   *in.PortMax,
					},
				}
			} else {
				out.Port = &regionv1.SecurityGroupRulePort{
					Number: in.Port,
				}
			}
		}
	}

	return out, nil
}

func generateRuleListV2(in openapi.SecurityGroupRuleV2List) ([]regionv1.SecurityGroupRule, error) {
	out := make([]regionv1.SecurityGroupRule, len(in))

	for i := range in {
		t, err := generateRuleV2(&in[i])
		if err != nil {
			return nil, err
		}

		out[i] = *t
	}

	return out, nil
}

func (c *Client) generateV2(ctx context.Context, organizationID, projectID string, request *openapi.SecurityGroupV2Update, network *regionv1.Network) (*regionv1.SecurityGroup, error) {
	rules, err := generateRuleListV2(request.Spec.Rules)
	if err != nil {
		return nil, err
	}

	out := &regionv1.SecurityGroup{
		ObjectMeta: conversion.NewObjectMetadata(&request.Metadata, c.namespace).
			WithOrganization(organizationID).
			WithProject(projectID).
			WithLabel(constants.RegionLabel, network.Labels[constants.RegionLabel]).
			WithLabel(constants.IdentityLabel, network.Labels[constants.IdentityLabel]).
			WithLabel(constants.NetworkLabel, network.Name).
			WithLabel(constants.ResourceAPIVersionLabel, constants.MarshalAPIVersion(2)).
			Get(),
		Spec: regionv1.SecurityGroupSpec{
			Tags:  conversion.GenerateTagList(request.Metadata.Tags),
			Rules: rules,
		},
	}

	if err := util.InjectUserPrincipal(ctx, organizationID, projectID); err != nil {
		return nil, err
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, err
	}

	if err := controllerutil.SetOwnerReference(network, out, c.client.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to set owner reference: %w", err).
			Prefixed()

		return nil, err
	}

	return out, nil
}

func (c *Client) CreateV2(ctx context.Context, request *openapi.SecurityGroupV2Create) (*openapi.SecurityGroupV2Read, error) {
	// Check the network exists, and the user has permission to it.
	network, err := network.New(c.client, c.namespace, nil).GetV2Raw(ctx, request.Spec.NetworkId)
	if err != nil {
		if errorsv2.IsAPIResourceMissingError(err) {
			err = errorsv2.NewInvalidRequestError().
				WithCause(err).
				WithErrorDescription("The provided network ID is invalid or cannot be resolved.").
				Prefixed()

			return nil, err
		}

		return nil, err
	}

	organizationID := network.Labels[coreconstants.OrganizationLabel]
	projectID := network.Labels[coreconstants.ProjectLabel]

	if err := rbac.AllowProjectScope(ctx, "region:securitygroups:v2", identityapi.Create, organizationID, projectID); err != nil {
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
		err = errorsv2.NewInternalError().
			WithCausef("failed to create security group: %w", err).
			Prefixed()

		return nil, err
	}

	return convertV2(resource), nil
}

func (c *Client) UpdateV2(ctx context.Context, securityGroupID string, request *openapi.SecurityGroupV2Update) (*openapi.SecurityGroupV2Read, error) {
	current, err := c.GetV2Raw(ctx, securityGroupID)
	if err != nil {
		return nil, err
	}

	if err := rbac.AllowProjectScope(ctx, "region:securitygroups:v2", identityapi.Delete, current.Labels[coreconstants.OrganizationLabel], current.Labels[coreconstants.ProjectLabel]); err != nil {
		return nil, err
	}

	if current.DeletionTimestamp != nil {
		err = errorsv2.NewConflictError().
			WithSimpleCause("security group is being deleted").
			WithErrorDescription("The security group is being deleted and cannot be modified.").
			Prefixed()

		return nil, err
	}

	// Get the network, required for generation.
	network, err := network.New(c.client, c.namespace, nil).GetV2Raw(ctx, current.Labels[constants.NetworkLabel])
	if err != nil {
		if errorsv2.IsAPIResourceMissingError(err) {
			err = errorsv2.NewInternalError().WithCause(err).Prefixed()
			return nil, err
		}

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
		err = errorsv2.NewInternalError().
			WithCausef("failed to patch security group: %w", err).
			Prefixed()

		return nil, err
	}

	return convertV2(updated), nil
}

func (c *Client) DeleteV2(ctx context.Context, securityGroupID string) error {
	resource, err := c.GetV2Raw(ctx, securityGroupID)
	if err != nil {
		return err
	}

	if err := rbac.AllowProjectScope(ctx, "region:securitygroups:v2", identityapi.Delete, resource.Labels[coreconstants.OrganizationLabel], resource.Labels[coreconstants.ProjectLabel]); err != nil {
		return err
	}

	if resource.DeletionTimestamp != nil {
		return nil
	}

	if len(manager.GetResourceReferences(resource)) > 0 {
		return errors.HTTPForbidden("security group is in use and callot be deleted")
	}

	if err := c.client.Delete(ctx, resource, util.ForegroundDeleteOptions()); err != nil {
		if kerrors.IsNotFound(err) {
			return errorsv2.NewResourceMissingError("security group").
				WithCause(err).
				Prefixed()
		}

		return errorsv2.NewInternalError().
			WithCausef("failed to delete security group: %w", err).
			Prefixed()
	}

	return nil
}
