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
	"fmt"
	"slices"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
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

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func convertV2(in *regionv1.SecurityGroup) *openapi.SecurityGroupV2Read {
	return &openapi.SecurityGroupV2Read{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.SecurityGroupV2Spec{
			Rules: convertRuleList(in.Spec.Rules),
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

	result := &regionv1.SecurityGroupList{}

	if err := c.client.List(ctx, result, options); err != nil {
		return nil, errors.OAuth2ServerError("unable to list security groups").WithError(err)
	}

	tagSelector, err := coreutil.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(resource regionv1.SecurityGroup) bool {
		return !resource.Spec.Tags.ContainsAll(tagSelector) ||
			rbac.AllowProjectScope(ctx, "region:securitygroups:v2", identityapi.Read, resource.Labels[coreconstants.OrganizationLabel], resource.Labels[coreconstants.ProjectLabel]) != nil
	})

	slices.SortStableFunc(result.Items, func(a, b regionv1.SecurityGroup) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertV2List(result), nil
}

func (c *Client) GetV2Raw(ctx context.Context, securityGroupID string) (*regionv1.SecurityGroup, error) {
	result := &regionv1.SecurityGroup{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: securityGroupID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to lookup security group").WithError(err)
	}

	if err := rbac.AllowProjectScope(ctx, "region:securitygroups:v2", identityapi.Read, result.Labels[coreconstants.OrganizationLabel], result.Labels[coreconstants.ProjectLabel]); err != nil {
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
	t, err := json.Marshal(in)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to marshal request").WithError(err)
	}

	out := &openapi.SecurityGroupV2Update{}

	if err := json.Unmarshal(t, out); err != nil {
		return nil, errors.OAuth2ServerError("failed to unmarshal request").WithError(err)
	}

	return out, nil
}

// validateV2 checks things JSON schema cannot.
func validateV2(request *openapi.SecurityGroupV2Update) error {
	if request.Spec.Rules != nil {
		for i, rule := range request.Spec.Rules {
			if rule.Port.Number == nil && rule.Port.Range == nil {
				return errors.OAuth2InvalidRequest(fmt.Sprintf("rule index %d must have port number or range set", i))
			}

			if rule.Port.Range != nil && rule.Port.Range.Start >= rule.Port.Range.End {
				return errors.OAuth2InvalidRequest(fmt.Sprintf("rule index %d must have a range where start < end", i))
			}
		}
	}

	return nil
}

func (c *Client) generateV2(ctx context.Context, organizationID, projectID string, request *openapi.SecurityGroupV2Update, network *regionv1.Network) (*regionv1.SecurityGroup, error) {
	rules, err := generateRuleList(request.Spec.Rules)
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
		return nil, errors.OAuth2ServerError("unable to set principal information").WithError(err)
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	if err := controllerutil.SetOwnerReference(network, out, c.client.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
		return nil, errors.OAuth2ServerError("unable to set resource owner").WithError(err)
	}

	return out, nil
}

func (c *Client) CreateV2(ctx context.Context, request *openapi.SecurityGroupV2Create) (*openapi.SecurityGroupV2Read, error) {
	// Check the network exists, and the user has permission to it.
	network, err := network.New(c.client, c.namespace, nil).GetV2Raw(ctx, request.Spec.NetworkId)
	if err != nil {
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

	if err := validateV2(commonRequest); err != nil {
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

func (c *Client) UpdateV2(ctx context.Context, securityGroupID string, request *openapi.SecurityGroupV2Update) (*openapi.SecurityGroupV2Read, error) {
	current, err := c.GetV2Raw(ctx, securityGroupID)
	if err != nil {
		return nil, err
	}

	if err := rbac.AllowProjectScope(ctx, "region:securitygroups:v2", identityapi.Delete, current.Labels[coreconstants.OrganizationLabel], current.Labels[coreconstants.ProjectLabel]); err != nil {
		return nil, err
	}

	if current.DeletionTimestamp != nil {
		return nil, errors.OAuth2InvalidRequest("security group is being deleted")
	}

	// Get the network, required for generation.
	network, err := network.New(c.client, c.namespace, nil).GetV2Raw(ctx, current.Labels[constants.NetworkLabel])
	if err != nil {
		return nil, err
	}

	if err := validateV2(request); err != nil {
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
		return nil, errors.OAuth2ServerError("unable to update security group").WithError(err)
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

	if err := c.client.Delete(ctx, resource, util.ForegroundDeleteOptions()); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("unable to delete security group").WithError(err)
	}

	return nil
}
