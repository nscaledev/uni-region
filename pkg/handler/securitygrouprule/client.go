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

package securitygrouprule

import (
	"cmp"
	"context"
	"net"
	"slices"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/identity"
	"github.com/unikorn-cloud/region/pkg/handler/securitygroup"
	"github.com/unikorn-cloud/region/pkg/handler/util"
	"github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

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
	case unikornv1.TCP:
		return openapi.Tcp
	case unikornv1.UDP:
		return openapi.Udp
	}

	return ""
}

// convertDirection from a Kubernetes representation into an API one.
func convertDirection(in unikornv1.SecurityGroupRuleDirection) openapi.NetworkDirection {
	switch in {
	case unikornv1.Ingress:
		return openapi.Ingress
	case unikornv1.Egress:
		return openapi.Egress
	}

	return ""
}

// convertPort from a Kubernetes representation into an API one.
func convertPort(in unikornv1.SecurityGroupRulePort) openapi.SecurityGroupRulePort {
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

// convert converts a single resource from the Kubernetes representation into the API one.
func convert(in *unikornv1.SecurityGroupRule) *openapi.SecurityGroupRuleRead {
	out := &openapi.SecurityGroupRuleRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.SecurityGroupRuleSpec{
			Direction: convertDirection(*in.Spec.Direction),
			Protocol:  convertProtocol(*in.Spec.Protocol),
			Cidr:      in.Spec.CIDR.String(),
			Port:      convertPort(*in.Spec.Port),
		},
	}

	return out
}

// convertList converts a list of resources from the Kubernetes representation into the API one.
func convertList(in *unikornv1.SecurityGroupRuleList) openapi.SecurityGroupRulesRead {
	out := make(openapi.SecurityGroupRulesRead, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i])
	}

	return out
}

// generateProtocol from an API representation into a Kubernetes one.
func generateProtocol(in openapi.NetworkProtocol) *unikornv1.SecurityGroupRuleProtocol {
	var out unikornv1.SecurityGroupRuleProtocol

	switch in {
	case openapi.Tcp:
		out = unikornv1.TCP
	case openapi.Udp:
		out = unikornv1.UDP
	}

	return &out
}

// generateDirection from an API representation into a Kubernetes one.
func generateDirection(in openapi.NetworkDirection) *unikornv1.SecurityGroupRuleDirection {
	var out unikornv1.SecurityGroupRuleDirection

	switch in {
	case openapi.Ingress:
		out = unikornv1.Ingress
	case openapi.Egress:
		out = unikornv1.Egress
	}

	return &out
}

// generatePort from an API representation into a Kubernetes one.
func generatePort(in openapi.SecurityGroupRulePort) *unikornv1.SecurityGroupRulePort {
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

// generate a new resource from a request.
func (c *Client) generate(ctx context.Context, organizationID, projectID, identityID, securityGroupID string, in *openapi.SecurityGroupRuleWrite) (*unikornv1.SecurityGroupRule, error) {
	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return nil, err
	}

	securityGroup, err := securitygroup.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, securityGroupID)
	if err != nil {
		return nil, err
	}

	_, prefix, err := net.ParseCIDR(in.Spec.Cidr)
	if err != nil {
		return nil, errors.OAuth2InvalidRequest("unable to parse prefix").WithError(err)
	}

	out := &unikornv1.SecurityGroupRule{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, c.namespace).WithOrganization(organizationID).WithProject(projectID).WithLabel(constants.RegionLabel, identity.Labels[constants.RegionLabel]).
			WithLabel(constants.IdentityLabel, identity.Name).WithLabel(constants.SecurityGroupLabel, securityGroup.Name).Get(),
		Spec: unikornv1.SecurityGroupRuleSpec{
			Tags:      conversion.GenerateTagList(in.Metadata.Tags),
			Direction: generateDirection(in.Spec.Direction),
			Protocol:  generateProtocol(in.Spec.Protocol),
			Port:      generatePort(in.Spec.Port),
			CIDR: &unikornv1core.IPv4Prefix{
				IPNet: *prefix,
			},
		},
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	// Ensure the security is owned by the security group rule so it is automatically cleaned
	// up on security group rule deletion.
	if err := controllerutil.SetOwnerReference(securityGroup, out, c.client.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
		return nil, err
	}

	return out, nil
}

// GetRaw gives access to the raw Kubernetes resource.
func (c *Client) GetRaw(ctx context.Context, organizationID, projectID, securityGroupRuleID string) (*unikornv1.SecurityGroupRule, error) {
	resource := &unikornv1.SecurityGroupRule{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: securityGroupRuleID}, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to get security group rule").WithError(err)
	}

	if err := util.AssertProjectOwnership(resource, organizationID, projectID); err != nil {
		return nil, err
	}

	return resource, nil
}

// List returns an ordered list of all resources in scope.
func (c *Client) List(ctx context.Context, organizationID, securityGroupID string) (openapi.SecurityGroupRulesRead, error) {
	result := &unikornv1.SecurityGroupRuleList{}

	options := &client.ListOptions{
		Namespace: c.namespace,
		LabelSelector: labels.SelectorFromSet(map[string]string{
			coreconstants.OrganizationLabel: organizationID,
			constants.SecurityGroupLabel:    securityGroupID,
		}),
	}

	if err := c.client.List(ctx, result, options); err != nil {
		return nil, errors.OAuth2ServerError("unable to list security group rules").WithError(err)
	}

	slices.SortStableFunc(result.Items, func(a, b unikornv1.SecurityGroupRule) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertList(result), nil
}

// Create instantiates a new resource.
func (c *Client) Create(ctx context.Context, organizationID, projectID, identityID, securityGroupID string, request *openapi.SecurityGroupRuleWrite) (*openapi.SecurityGroupRuleRead, error) {
	result, err := c.generate(ctx, organizationID, projectID, identityID, securityGroupID, request)
	if err != nil {
		return nil, err
	}

	if err := c.client.Create(ctx, result); err != nil {
		return nil, errors.OAuth2ServerError("unable to create security group rule").WithError(err)
	}

	return convert(result), nil
}

// Get a resource.
func (c *Client) Get(ctx context.Context, organizationID, projectID, securityGroupRuleID string) (*openapi.SecurityGroupRuleRead, error) {
	result, err := c.GetRaw(ctx, organizationID, projectID, securityGroupRuleID)
	if err != nil {
		return nil, err
	}

	return convert(result), nil
}

// Delete a resource.
func (c *Client) Delete(ctx context.Context, organizationID, projectID, securityGroupRuleID string) error {
	resource, err := c.GetRaw(ctx, organizationID, projectID, securityGroupRuleID)
	if err != nil {
		return err
	}

	if err := c.client.Delete(ctx, resource, util.ForegroundDeleteOptions()); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("unable to delete security group rule").WithError(err)
	}

	return nil
}
