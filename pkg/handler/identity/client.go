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

package identity

import (
	"cmp"
	"context"
	"encoding/base64"
	"slices"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/region"
	"github.com/unikorn-cloud/region/pkg/handler/util"
	"github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
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
func (c *Client) convert(ctx context.Context, in *unikornv1.Identity) *openapi.IdentityRead {
	out := &openapi.IdentityRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.IdentitySpec{
			RegionId: in.Labels[constants.RegionLabel],
		},
	}

	//nolint:exhaustive,gocritic
	switch in.Spec.Provider {
	case unikornv1.ProviderOpenstack:
		out.Spec.Type = openapi.Openstack

		var openstackIdentity unikornv1.OpenstackIdentity

		if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: in.Name}, &openstackIdentity); err == nil {
			var sshPrivateKey *string

			if len(openstackIdentity.Spec.SSHPrivateKey) > 0 {
				sshPrivateKey = ptr.To(string(openstackIdentity.Spec.SSHPrivateKey))
			}

			out.Spec.Openstack = &openapi.IdentitySpecOpenStack{
				Cloud:         openstackIdentity.Spec.Cloud,
				UserId:        openstackIdentity.Spec.UserID,
				ProjectId:     openstackIdentity.Spec.ProjectID,
				ServerGroupId: openstackIdentity.Spec.ServerGroupID,
				SshKeyName:    openstackIdentity.Spec.SSHKeyName,
				SshPrivateKey: sshPrivateKey,
			}

			if openstackIdentity.Spec.CloudConfig != nil {
				cloudConfig := base64.URLEncoding.EncodeToString(openstackIdentity.Spec.CloudConfig)
				out.Spec.Openstack.CloudConfig = &cloudConfig
			}
		}
	}

	return out
}

// convertList converts a list of resources from the Kubernetes representation into the API one.
func (c *Client) convertList(ctx context.Context, in unikornv1.IdentityList) openapi.IdentitiesRead {
	out := make(openapi.IdentitiesRead, len(in.Items))

	for i := range in.Items {
		out[i] = *c.convert(ctx, &in.Items[i])
	}

	return out
}

// generate a new resource from a request.
func (c *Client) generate(ctx context.Context, organizationID, projectID string, request *openapi.IdentityWrite) (*unikornv1.Identity, error) {
	provider, err := region.NewClient(c.client, c.namespace).Provider(ctx, request.Spec.RegionId)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to get region provider").WithError(err)
	}

	region, err := provider.Region(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to get region").WithError(err)
	}

	out := &unikornv1.Identity{
		ObjectMeta: conversion.NewObjectMetadata(&request.Metadata, c.namespace).WithOrganization(organizationID).WithProject(projectID).WithLabel(constants.RegionLabel, request.Spec.RegionId).Get(),
		Spec: unikornv1.IdentitySpec{
			Tags:     conversion.GenerateTagList(request.Metadata.Tags),
			Provider: region.Spec.Provider,
		},
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	return out, nil
}

// GetRaw gives access to the raw Kubernetes resource.
func (c *Client) GetRaw(ctx context.Context, organizationID, projectID, identityID string) (*unikornv1.Identity, error) {
	resource := &unikornv1.Identity{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: identityID}, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to lookup identity").WithError(err)
	}

	if err := coreutil.AssertProjectOwnership(resource, organizationID, projectID); err != nil {
		return nil, err
	}

	return resource, nil
}

// List returns an ordered list of all resources in scope.
func (c *Client) List(ctx context.Context, organizationID string) (openapi.IdentitiesRead, error) {
	var result unikornv1.IdentityList

	options := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			coreconstants.OrganizationLabel: organizationID,
		}),
	}

	if err := c.client.List(ctx, &result, options); err != nil {
		return nil, errors.OAuth2ServerError("unable to list identities").WithError(err)
	}

	slices.SortStableFunc(result.Items, func(a, b unikornv1.Identity) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return c.convertList(ctx, result), nil
}

// Create instantiates a new resource.
func (c *Client) Create(ctx context.Context, organizationID, projectID string, request *openapi.IdentityWrite) (*openapi.IdentityRead, error) {
	resource, err := c.generate(ctx, organizationID, projectID, request)
	if err != nil {
		return nil, err
	}

	if err := c.client.Create(ctx, resource); err != nil {
		return nil, errors.OAuth2ServerError("unable to create identity").WithError(err)
	}

	return c.convert(ctx, resource), nil
}

// Get a resource.
func (c *Client) Get(ctx context.Context, organizationID, projectID, identityID string) (*openapi.IdentityRead, error) {
	result, err := c.GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return nil, err
	}

	return c.convert(ctx, result), nil
}

// Delete a resource.
func (c *Client) Delete(ctx context.Context, organizationID, projectID, identityID string) error {
	result, err := c.GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return err
	}

	if err := c.client.Delete(ctx, result, util.ForegroundDeleteOptions()); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("unable to delete identity").WithError(err)
	}

	return nil
}
