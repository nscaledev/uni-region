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
	"slices"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/identity"
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

// convert converts a single resource from the Kubernetes representation into the API one.
func convert(in *unikornv1.SecurityGroup) *openapi.SecurityGroupRead {
	out := &openapi.SecurityGroupRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.SecurityGroupReadSpec{
			RegionId: in.Labels[constants.RegionLabel],
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

// generate a new resource from a request.
func (c *Client) generate(ctx context.Context, organizationID, projectID, identityID string, in *openapi.SecurityGroupWrite) (*unikornv1.SecurityGroup, error) {
	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return nil, err
	}

	info, err := authorization.FromContext(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to get userinfo").WithError(err)
	}

	resource := &unikornv1.SecurityGroup{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, c.namespace, info.Userinfo.Sub).WithOrganization(organizationID).WithProject(projectID).WithLabel(constants.RegionLabel, identity.Labels[constants.RegionLabel]).
			WithLabel(constants.IdentityLabel, identity.Name).Get(),
		Spec: unikornv1.SecurityGroupSpec{
			Tags:     conversion.GenerateTagList(in.Metadata.Tags),
			Provider: identity.Spec.Provider,
		},
	}

	// Ensure the security is owned by the identity so it is automatically cleaned
	// up on identity deletion.
	if err := controllerutil.SetOwnerReference(identity, resource, c.client.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
		return nil, err
	}

	return resource, nil
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

	if err := util.AssertProjectOwnership(resource, organizationID, projectID); err != nil {
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

	tagSelector, err := util.DecodeTagSelectorParam(params.Tag)
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
