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
	"slices"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/util"
	errorsv2 "github.com/unikorn-cloud/core/pkg/server/v2/errors"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/identity"
	"github.com/unikorn-cloud/region/pkg/handler/region"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"

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
	key := client.ObjectKey{
		Namespace: c.namespace,
		Name:      serverID,
	}

	var server unikornv1.Server
	if err := c.client.Get(ctx, key, &server); err != nil {
		if kerrors.IsNotFound(err) {
			err = errorsv2.NewResourceMissingError("server").
				WithCause(err).
				Prefixed()

			return nil, err
		}

		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve server: %w", err).
			Prefixed()

		return nil, err
	}

	if err := util.AssertProjectOwnership(&server, organizationID, projectID); err != nil {
		return nil, err
	}

	return &server, nil
}

// List returns an ordered list of all resources in scope.
func (c *Client) List(ctx context.Context, organizationID string, params openapi.GetApiV1OrganizationsOrganizationIDServersParams) (openapi.ServersRead, error) {
	tagSelector, err := util.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	opts := []client.ListOption{
		&client.ListOptions{
			Namespace: c.namespace,
			LabelSelector: labels.SelectorFromSet(labels.Set{
				coreconstants.OrganizationLabel: organizationID,
			}),
		},
	}

	var list unikornv1.ServerList
	if err := c.client.List(ctx, &list, opts...); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve servers: %w", err).
			Prefixed()

		return nil, err
	}

	list.Items = slices.DeleteFunc(list.Items, func(resource unikornv1.Server) bool {
		return !resource.Spec.Tags.ContainsAll(tagSelector)
	})

	// Apply ordering guarantees, ordered by name.
	slices.SortStableFunc(list.Items, func(a, b unikornv1.Server) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertList(&list), nil
}

// Create instantiates a new resource.
func (c *Client) Create(ctx context.Context, organizationID, projectID, identityID string, request *openapi.ServerWrite) (*openapi.ServerRead, error) {
	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return nil, err
	}

	provider, err := region.NewClient(c.client, c.namespace).Provider(ctx, identity.Labels[constants.RegionLabel])
	if err != nil {
		return nil, err
	}

	if _, err := provider.GetImage(ctx, organizationID, request.Spec.ImageId); err != nil {
		if goerrors.Is(err, types.ErrResourceNotFound) {
			err = errorsv2.NewResourceMissingError("image").
				WithCause(err).
				Prefixed()

			return nil, err
		}

		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve image: %w", err).
			Prefixed()

		return nil, err
	}

	resource, err := newGenerator(c.client, c.namespace, organizationID, projectID, identityID).generate(ctx, request)
	if err != nil {
		return nil, err
	}

	resource.Status.Phase = unikornv1.InstanceLifecyclePhasePending

	if err := c.client.Create(ctx, resource); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to create server: %w", err).
			Prefixed()

		return nil, err
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
		return nil, err
	}

	if _, err := provider.GetImage(ctx, organizationID, request.Spec.ImageId); err != nil {
		if goerrors.Is(err, types.ErrResourceNotFound) {
			err = errorsv2.NewResourceMissingError("image").
				WithCause(err).
				Prefixed()

			return nil, err
		}

		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve image: %w", err).
			Prefixed()

		return nil, err
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
		return nil, err
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to patch server: %w", err).
			Prefixed()

		return nil, err
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
		return err
	}

	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return err
	}

	return c.reboot(ctx, current, hard, identity, provider)
}

func (c *Client) reboot(ctx context.Context, server *unikornv1.Server, hard bool, identity *unikornv1.Identity, provider types.Provider) error {
	// REVIEW_ME: Do we want to track who rebooted the server, and when?
	// REVIEW_ME: This action only reboots the server with the existing configuration, so updating the labels (creator/principal) seems a bit weird.
	if err := provider.RebootServer(ctx, identity, server, hard); err != nil {
		if goerrors.Is(err, types.ErrResourceNotFound) {
			return nil
		}

		if goerrors.Is(err, types.ErrConflict) {
			return errorsv2.NewConflictError().
				WithCause(err).
				WithErrorDescription("The server cannot be rebooted in its current state.").
				Prefixed()
		}

		if hard {
			return errorsv2.NewInternalError().
				WithCausef("failed to hard reboot server: %w", err).
				Prefixed()
		}

		return errorsv2.NewInternalError().
			WithCausef("failed to soft reboot server: %w", err).
			Prefixed()
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
		return err
	}

	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return err
	}

	return c.start(ctx, current, identity, provider)
}

func (c *Client) start(ctx context.Context, server *unikornv1.Server, identity *unikornv1.Identity, provider types.Provider) error {
	if err := provider.StartServer(ctx, identity, server); err != nil {
		if goerrors.Is(err, types.ErrResourceNotFound) {
			return errorsv2.NewResourceMissingError("server").
				WithCause(err).
				Prefixed()
		}

		if goerrors.Is(err, types.ErrConflict) {
			return errorsv2.NewConflictError().
				WithCause(err).
				WithErrorDescription("The server cannot be started in its current state.").
				Prefixed()
		}

		return errorsv2.NewInternalError().
			WithCausef("failed to start server: %w", err).
			Prefixed()
	}

	// REVIEW_ME: Do we want to track who started the server, and when?
	updated := server.DeepCopy()
	updated.Status.Phase = unikornv1.InstanceLifecyclePhasePending

	if err := c.client.Status().Patch(ctx, updated, client.MergeFrom(server)); err != nil {
		return errorsv2.NewInternalError().
			WithCausef("failed to patch server: %w", err).
			Prefixed()
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
		return err
	}

	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return err
	}

	return c.stop(ctx, current, identity, provider)
}

func (c *Client) stop(ctx context.Context, server *unikornv1.Server, identity *unikornv1.Identity, provider types.Provider) error {
	if err := provider.StopServer(ctx, identity, server); err != nil {
		if goerrors.Is(err, types.ErrResourceNotFound) {
			return errorsv2.NewResourceMissingError("server").
				WithCause(err).
				Prefixed()
		}

		if goerrors.Is(err, types.ErrConflict) {
			return errorsv2.NewConflictError().
				WithCause(err).
				WithErrorDescription("The server cannot be stopped in its current state.").
				Prefixed()
		}

		return errorsv2.NewInternalError().
			WithCausef("failed to stop server: %w", err).
			Prefixed()
	}

	// REVIEW_ME: Do we want to track who stopped the server, and when?
	updated := server.DeepCopy()
	updated.Status.Phase = unikornv1.InstanceLifecyclePhaseStopping

	if err := c.client.Status().Patch(ctx, updated, client.MergeFrom(server)); err != nil {
		return errorsv2.NewInternalError().
			WithCausef("failed to patch server: %w", err).
			Prefixed()
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
			return errorsv2.NewResourceMissingError("server").
				WithCause(err).
				Prefixed()
		}

		return errorsv2.NewInternalError().
			WithCausef("failed to delete server: %w", err).
			Prefixed()
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
		return nil, err
	}

	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return nil, err
	}

	return c.createConsoleSession(ctx, current, identity, provider)
}

func (c *Client) createConsoleSession(ctx context.Context, server *unikornv1.Server, identity *unikornv1.Identity, provider types.Provider) (*openapi.ConsoleSessionResponse, error) {
	url, err := provider.CreateConsoleSession(ctx, identity, server)
	if err != nil {
		if goerrors.Is(err, types.ErrResourceNotFound) {
			err = errorsv2.NewResourceMissingError("server").
				WithCause(err).
				Prefixed()

			return nil, err
		}

		if goerrors.Is(err, types.ErrConflict) {
			err = errorsv2.NewConflictError().
				WithCause(err).
				WithErrorDescription("The server cannot be accessed in its current state.").
				Prefixed()

			return nil, err
		}

		err = errorsv2.NewInternalError().
			WithCausef("failed to create console session: %w", err).
			Prefixed()

		return nil, err
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
		return nil, err
	}

	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return nil, err
	}

	return c.getConsoleOutput(ctx, current, params.Length, identity, provider)
}

func (c *Client) getConsoleOutput(ctx context.Context, server *unikornv1.Server, length *int, identity *unikornv1.Identity, provider types.Provider) (*openapi.ConsoleOutputResponse, error) {
	contents, err := provider.GetConsoleOutput(ctx, identity, server, length)
	if err != nil {
		if goerrors.Is(err, types.ErrResourceNotFound) {
			err = errorsv2.NewResourceMissingError("server").
				WithCause(err).
				Prefixed()

			return nil, err
		}

		if goerrors.Is(err, types.ErrConflict) {
			err = errorsv2.NewConflictError().
				WithCause(err).
				WithErrorDescription("The server console output cannot be retrieved in its current state.").
				Prefixed()

			return nil, err
		}

		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve console output: %w", err).
			Prefixed()

		return nil, err
	}

	response := &openapi.ConsoleOutputResponse{
		Contents: contents,
	}

	return response, nil
}
