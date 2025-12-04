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
	"net"
	"slices"

	unikorncorev1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/identity"
	"github.com/unikorn-cloud/region/pkg/handler/util"
	"github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// Client provides a restful API for identities.
type Client struct {
	// client ia a Kubernetes client.
	client client.Client
	// namespace we are running in.
	namespace string
}

// New creates a new client.
func New(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

// convertProtocol from a Kubernetes representation into an API one.
func convertProtocol(in unikornv1.SecurityGroupRuleProtocol) openapi.NetworkProtocol {
	switch in {
	case unikornv1.Any:
		return openapi.NetworkProtocolAny
	case unikornv1.ICMP:
		return openapi.NetworkProtocolIcmp
	case unikornv1.TCP:
		return openapi.NetworkProtocolTcp
	case unikornv1.UDP:
		return openapi.NetworkProtocolUdp
	case unikornv1.VRRP:
		return openapi.NetworkProtocolVrrp
	}

	return ""
}

// convertDirection from a Kubernetes representation into an API one.
func convertDirection(in unikornv1.SecurityGroupRuleDirection) openapi.NetworkDirection {
	switch in {
	case unikornv1.Ingress:
		return openapi.NetworkDirectionIngress
	case unikornv1.Egress:
		return openapi.NetworkDirectionEgress
	}

	return ""
}

// convertPort from a Kubernetes representation into an API one.
func convertPort(in *unikornv1.SecurityGroupRulePort) *openapi.SecurityGroupRulePort {
	if in == nil {
		return nil
	}

	out := &openapi.SecurityGroupRulePort{}

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

// convertRule converts a single resource from the Kubernetes representation into the API one.
func convertRule(in *unikornv1.SecurityGroupRule) *openapi.SecurityGroupRule {
	out := &openapi.SecurityGroupRule{
		Direction: convertDirection(in.Direction),
		Protocol:  convertProtocol(in.Protocol),
		Port:      convertPort(in.Port),
	}

	if in.CIDR != nil {
		out.Cidr = ptr.To(in.CIDR.String())
	}

	return out
}

// convertRuleList converts a list of resources from the Kubernetes representation into the API one.
func convertRuleList(in []unikornv1.SecurityGroupRule) openapi.SecurityGroupRuleList {
	out := make(openapi.SecurityGroupRuleList, len(in))

	for i := range in {
		out[i] = *convertRule(&in[i])
	}

	return out
}

// convert converts a single resource from the Kubernetes representation into the API one.
func convert(in *unikornv1.SecurityGroup) *openapi.SecurityGroupRead {
	out := &openapi.SecurityGroupRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.SecurityGroupSpec{
			Rules: convertRuleList(in.Spec.Rules),
		},
	}

	return out
}

// convertList converts a list of resources from the Kubernetes representation into the API one.
func convertList(in *unikornv1.SecurityGroupList) openapi.SecurityGroupsRead {
	out := make(openapi.SecurityGroupsRead, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i])
	}

	return out
}

// generateProtocol from an API representation into a Kubernetes one.
func generateProtocol(in openapi.NetworkProtocol) unikornv1.SecurityGroupRuleProtocol {
	var out unikornv1.SecurityGroupRuleProtocol

	switch in {
	case openapi.NetworkProtocolAny:
		out = unikornv1.Any
	case openapi.NetworkProtocolIcmp:
		out = unikornv1.ICMP
	case openapi.NetworkProtocolTcp:
		out = unikornv1.TCP
	case openapi.NetworkProtocolUdp:
		out = unikornv1.UDP
	case openapi.NetworkProtocolVrrp:
		out = unikornv1.VRRP
	}

	return out
}

// generateDirection from an API representation into a Kubernetes one.
func generateDirection(in openapi.NetworkDirection) unikornv1.SecurityGroupRuleDirection {
	var out unikornv1.SecurityGroupRuleDirection

	switch in {
	case openapi.NetworkDirectionIngress:
		out = unikornv1.Ingress
	case openapi.NetworkDirectionEgress:
		out = unikornv1.Egress
	}

	return out
}

// generatePort from an API representation into a Kubernetes one.
func generatePort(in *openapi.SecurityGroupRulePort) *unikornv1.SecurityGroupRulePort {
	if in == nil {
		return nil
	}

	out := &unikornv1.SecurityGroupRulePort{}

	if in.Number != nil {
		out.Number = in.Number
	}

	if in.Range != nil {
		out.Range = &unikornv1.SecurityGroupRulePortRange{
			Start: in.Range.Start,
			End:   in.Range.End,
		}
	}

	return out
}

func generatePrefix(in *string) (*unikorncorev1.IPv4Prefix, error) {
	if in == nil {
		//nolint:nilnil
		return nil, nil
	}

	_, prefix, err := net.ParseCIDR(*in)
	if err != nil {
		return nil, errors.OAuth2InvalidRequest("unable to parse prefix").WithError(err)
	}

	out := &unikorncorev1.IPv4Prefix{
		IPNet: *prefix,
	}

	return out, nil
}

// generateRule a new resource from a request.
func generateRule(in *openapi.SecurityGroupRule) (*unikornv1.SecurityGroupRule, error) {
	prefix, err := generatePrefix(in.Cidr)
	if err != nil {
		return nil, err
	}

	out := &unikornv1.SecurityGroupRule{
		Direction: generateDirection(in.Direction),
		Protocol:  generateProtocol(in.Protocol),
		Port:      generatePort(in.Port),
		CIDR:      prefix,
	}

	return out, nil
}

func generateRuleList(in openapi.SecurityGroupRuleList) ([]unikornv1.SecurityGroupRule, error) {
	out := make([]unikornv1.SecurityGroupRule, len(in))

	for i := range in {
		t, err := generateRule(&in[i])
		if err != nil {
			return nil, err
		}

		out[i] = *t
	}

	return out, nil
}

// generate a new resource from a request.
func (c *Client) generate(ctx context.Context, organizationID, projectID, identityID string, in *openapi.SecurityGroupWrite) (*unikornv1.SecurityGroup, error) {
	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return nil, err
	}

	rules, err := generateRuleList(in.Spec.Rules)
	if err != nil {
		return nil, err
	}

	out := &unikornv1.SecurityGroup{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, c.namespace).WithOrganization(organizationID).WithProject(projectID).WithLabel(constants.RegionLabel, identity.Labels[constants.RegionLabel]).WithLabel(constants.IdentityLabel, identity.Name).Get(),
		Spec: unikornv1.SecurityGroupSpec{
			Tags:  conversion.GenerateTagList(in.Metadata.Tags),
			Rules: rules,
		},
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	// Ensure the security is owned by the identity so it is automatically cleaned
	// up on identity deletion.
	if err := controllerutil.SetOwnerReference(identity, out, c.client.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
		return nil, err
	}

	return out, nil
}

// GetRaw gives access to the raw Kubernetes resource.
func (c *Client) GetRaw(ctx context.Context, organizationID, projectID, securityGroupID string) (*unikornv1.SecurityGroup, error) {
	resource := &unikornv1.SecurityGroup{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: securityGroupID}, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to get security group").WithError(err)
	}

	if err := coreutil.AssertProjectOwnership(resource, organizationID, projectID); err != nil {
		return nil, err
	}

	return resource, nil
}

// List returns an ordered list of all resources in scope.
func (c *Client) List(ctx context.Context, organizationID string, params openapi.GetApiV1OrganizationsOrganizationIDSecuritygroupsParams) (openapi.SecurityGroupsRead, error) {
	result := &unikornv1.SecurityGroupList{}

	options := &client.ListOptions{
		Namespace: c.namespace,
		LabelSelector: labels.SelectorFromSet(map[string]string{
			coreconstants.OrganizationLabel: organizationID,
		}),
	}

	if err := c.client.List(ctx, result, options); err != nil {
		return nil, errors.OAuth2ServerError("unable to list security groups").WithError(err)
	}

	slices.SortStableFunc(result.Items, func(a, b unikornv1.SecurityGroup) int {
		return cmp.Compare(a.Name, b.Name)
	})

	tagSelector, err := coreutil.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(resource unikornv1.SecurityGroup) bool {
		return !resource.Spec.Tags.ContainsAll(tagSelector)
	})

	return convertList(result), nil
}

// Create instantiates a new resource.
func (c *Client) Create(ctx context.Context, organizationID, projectID, identityID string, request *openapi.SecurityGroupWrite) (*openapi.SecurityGroupRead, error) {
	securityGroup, err := c.generate(ctx, organizationID, projectID, identityID, request)
	if err != nil {
		return nil, err
	}

	if err := c.client.Create(ctx, securityGroup); err != nil {
		return nil, errors.OAuth2ServerError("unable to create security group").WithError(err)
	}

	return convert(securityGroup), nil
}

// Get a resource.
func (c *Client) Get(ctx context.Context, organizationID, projectID, securityGroupID string) (*openapi.SecurityGroupRead, error) {
	result, err := c.GetRaw(ctx, organizationID, projectID, securityGroupID)
	if err != nil {
		return nil, err
	}

	return convert(result), nil
}

func metadataMutator(required, current metav1.Object) error {
	req := required.GetLabels()
	if req == nil {
		req = map[string]string{}
	}

	cur := current.GetLabels()

	if v, ok := cur[constants.IdentityLabel]; ok {
		req[constants.IdentityLabel] = v
	}

	if v, ok := cur[constants.RegionLabel]; ok {
		req[constants.RegionLabel] = v
	}

	if v, ok := cur[constants.NetworkLabel]; ok {
		req[constants.NetworkLabel] = v
	}

	required.SetLabels(req)

	return nil
}

// Update a resource.
func (c *Client) Update(ctx context.Context, organizationID, projectID, identityID, securityGroupID string, request *openapi.SecurityGroupWrite) (*openapi.SecurityGroupRead, error) {
	required, err := c.generate(ctx, organizationID, projectID, identityID, request)
	if err != nil {
		return nil, err
	}

	current, err := c.GetRaw(ctx, organizationID, projectID, securityGroupID)
	if err != nil {
		return nil, err
	}

	if err := conversion.UpdateObjectMetadata(required, current, common.IdentityMetadataMutator, metadataMutator); err != nil {
		return nil, err
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return nil, errors.OAuth2ServerError("unable to updated security group").WithError(err)
	}

	return convert(updated), nil
}

// Delete a resource.
func (c *Client) Delete(ctx context.Context, organizationID, projectID, securityGroupID string) error {
	resource, err := c.GetRaw(ctx, organizationID, projectID, securityGroupID)
	if err != nil {
		return err
	}

	if err := c.client.Delete(ctx, resource, util.ForegroundDeleteOptions()); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("unable to delete security group").WithError(err)
	}

	return nil
}
