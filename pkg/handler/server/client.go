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
	"cmp"
	"context"
	goerrors "errors"
	"net/http"
	"slices"

	"github.com/gophercloud/gophercloud/v2"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/identity"
	"github.com/unikorn-cloud/region/pkg/handler/region"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/openstack"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

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
func NewClient(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

// get gives access to the raw Kubernetes resource.
func (c *Client) get(ctx context.Context, organizationID, projectID, serverID string) (*unikornv1.Server, error) {
	resource := &unikornv1.Server{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: serverID}, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to get server").WithError(err)
	}

	if err := util.AssertProjectOwnership(resource, organizationID, projectID); err != nil {
		return nil, err
	}

	return resource, nil
}

// List returns an ordered list of all resources in scope.
func (c *Client) List(ctx context.Context, organizationID string, params openapi.GetApiV1OrganizationsOrganizationIDServersParams) (openapi.ServersRead, error) {
	result := &unikornv1.ServerList{}

	options := &client.ListOptions{
		Namespace: c.namespace,
		LabelSelector: labels.SelectorFromSet(map[string]string{
			coreconstants.OrganizationLabel: organizationID,
		}),
	}

	if err := c.client.List(ctx, result, options); err != nil {
		return nil, errors.OAuth2ServerError("unable to list servers").WithError(err)
	}

	tagSelector, err := util.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(resource unikornv1.Server) bool {
		return !resource.Spec.Tags.ContainsAll(tagSelector)
	})

	// Apply ordering guarantees, ordered by name.
	slices.SortStableFunc(result.Items, func(a, b unikornv1.Server) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertList(result), nil
}

// Create instantiates a new resource.
func (c *Client) Create(ctx context.Context, organizationID, projectID, identityID string, request *openapi.ServerWrite) (*openapi.ServerRead, error) {
	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return nil, err
	}

	provider, err := region.NewClient(c.client, c.namespace).Provider(ctx, identity.Labels[constants.RegionLabel])
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	if _, err := provider.GetImage(ctx, organizationID, request.Spec.ImageId); err != nil {
		if goerrors.Is(err, openstack.ErrResourceNotFound) {
			return nil, errors.HTTPNotFound()
		}

		return nil, errors.OAuth2ServerError("failed to retrieve image from provider").WithError(err)
	}

	resource, err := newGenerator(c.client, c.namespace, organizationID, projectID, identityID).generate(ctx, request)
	if err != nil {
		return nil, err
	}

	resource.Status.Phase = unikornv1.InstanceLifecyclePhasePending

	if err := c.client.Create(ctx, resource); err != nil {
		return nil, errors.OAuth2ServerError("unable to create server").WithError(err)
	}

	return convert(resource), nil
}

// Get a resource.
func (c *Client) Get(ctx context.Context, organizationID, projectID, serverID string) (*openapi.ServerRead, error) {
	resource, err := c.get(ctx, organizationID, projectID, serverID)
	if err != nil {
		return nil, err
	}

	return convert(resource), nil
}

// Update a resource.
func (c *Client) Update(ctx context.Context, organizationID, projectID, identityID, serverID string, request *openapi.ServerWrite) (*openapi.ServerRead, error) {
	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return nil, err
	}

	provider, err := region.NewClient(c.client, c.namespace).Provider(ctx, identity.Labels[constants.RegionLabel])
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	if _, err := provider.GetImage(ctx, organizationID, request.Spec.ImageId); err != nil {
		if goerrors.Is(err, openstack.ErrResourceNotFound) {
			return nil, errors.HTTPNotFound()
		}

		return nil, errors.OAuth2ServerError("failed to retrieve image from provider").WithError(err)
	}

	current, err := c.get(ctx, organizationID, projectID, serverID)
	if err != nil {
		return nil, err
	}

	required, err := newGenerator(c.client, c.namespace, organizationID, projectID, identityID).generate(ctx, request)
	if err != nil {
		return nil, err
	}

	if err := conversion.UpdateObjectMetadata(required, current, common.IdentityMetadataMutator); err != nil {
		return nil, errors.OAuth2ServerError("failed to merge metadata").WithError(err)
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return nil, errors.OAuth2ServerError("failed to patch server").WithError(err)
	}

	return convert(updated), nil
}

func (c *Client) Reboot(ctx context.Context, organizationID, projectID, identityID, serverID string, hard bool) error {
	current, err := c.get(ctx, organizationID, projectID, serverID)
	if err != nil {
		return err
	}

	provider, err := region.NewClient(c.client, c.namespace).Provider(ctx, current.Labels[constants.RegionLabel])
	if err != nil {
		return errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return err
	}

	// REVIEW_ME: Do we want to track who rebooted the server, and when?
	// REVIEW_ME: This action only reboots the server with the existing configuration, so updating the labels (creator/principal) seems a bit weird.

	if err := provider.RebootServer(ctx, identity, current, hard); err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusConflict) {
			// REVIEW_ME: Should this return 409 instead? But we will probably need to add a new error type for that.
			return errors.OAuth2InvalidRequest("server cannot be rebooted in its current state").WithError(err)
		}

		if hard {
			return errors.OAuth2ServerError("failed to hard reboot server").WithError(err)
		}

		return errors.OAuth2ServerError("failed to soft reboot server").WithError(err)
	}

	return nil
}

//nolint:dupl
func (c *Client) Start(ctx context.Context, organizationID, projectID, identityID, serverID string) error {
	current, err := c.get(ctx, organizationID, projectID, serverID)
	if err != nil {
		return err
	}

	provider, err := region.NewClient(c.client, c.namespace).Provider(ctx, current.Labels[constants.RegionLabel])
	if err != nil {
		return errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return err
	}

	if err := provider.StartServer(ctx, identity, current); err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusConflict) {
			// REVIEW_ME: Should this return 409 instead? But we will probably need to add a new error type for that.
			return errors.OAuth2InvalidRequest("server cannot be started in its current state").WithError(err)
		}

		return errors.OAuth2ServerError("failed to start server").WithError(err)
	}

	// REVIEW_ME: Do we want to track who started the server, and when?
	updated := current.DeepCopy()
	updated.Status.Phase = unikornv1.InstanceLifecyclePhasePending

	if err := c.client.Status().Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return errors.OAuth2ServerError("failed to patch server").WithError(err)
	}

	return nil
}

//nolint:dupl
func (c *Client) Stop(ctx context.Context, organizationID, projectID, identityID, serverID string) error {
	current, err := c.get(ctx, organizationID, projectID, serverID)
	if err != nil {
		return err
	}

	provider, err := region.NewClient(c.client, c.namespace).Provider(ctx, current.Labels[constants.RegionLabel])
	if err != nil {
		return errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return err
	}

	if err := provider.StopServer(ctx, identity, current); err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusConflict) {
			// REVIEW_ME: Should this return 409 instead? But we will probably need to add a new error type for that.
			return errors.OAuth2InvalidRequest("server cannot be stopped in its current state").WithError(err)
		}

		return errors.OAuth2ServerError("failed to stop server").WithError(err)
	}

	// REVIEW_ME: Do we want to track who stopped the server, and when?
	updated := current.DeepCopy()
	updated.Status.Phase = unikornv1.InstanceLifecyclePhaseStopping

	if err := c.client.Status().Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return errors.OAuth2ServerError("failed to patch server").WithError(err)
	}

	return nil
}

// Delete a resource.
func (c *Client) Delete(ctx context.Context, organizationID, projectID, serverID string) error {
	resource, err := c.get(ctx, organizationID, projectID, serverID)
	if err != nil {
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

func (c *Client) CreateConsoleSession(ctx context.Context, organizationID, projectID, identityID, serverID string) (*openapi.ConsoleSessionResponse, error) {
	current, err := c.get(ctx, organizationID, projectID, serverID)
	if err != nil {
		return nil, err
	}

	provider, err := region.NewClient(c.client, c.namespace).Provider(ctx, current.Labels[constants.RegionLabel])
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return nil, err
	}

	url, err := provider.CreateConsoleSession(ctx, identity, current)
	if err != nil {
		// REVIEW_ME: This looks odd. Shouldn't the ErrResourceDependency error be moved to the provider package?
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) || goerrors.Is(err, openstack.ErrResourceDependency) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("failed to create console session").WithError(err)
	}

	response := &openapi.ConsoleSessionResponse{
		Url: url,
	}

	return response, nil
}

func (c *Client) GetConsoleOutput(ctx context.Context, organizationID, projectID, identityID, serverID string, params openapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDConsoleoutputParams) (*openapi.ConsoleOutputResponse, error) {
	current, err := c.get(ctx, organizationID, projectID, serverID)
	if err != nil {
		return nil, err
	}

	provider, err := region.NewClient(c.client, c.namespace).Provider(ctx, current.Labels[constants.RegionLabel])
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return nil, err
	}

	contents, err := provider.GetConsoleOutput(ctx, identity, current, params.Length)
	if err != nil {
		// REVIEW_ME: This looks odd. Shouldn't the ErrResourceDependency error be moved to the provider package?
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) || goerrors.Is(err, openstack.ErrResourceDependency) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("failed to create console session").WithError(err)
	}

	response := &openapi.ConsoleOutputResponse{
		Contents: contents,
	}

	return response, nil
}
