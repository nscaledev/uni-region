/*
Copyright 2024-2025 the Unikorn Authors.
Copyright 2026 Nscale.

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
	"fmt"
	"slices"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	identitycommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/identity"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Client provides a restful API for identities.
type Client struct {
	common.ClientArgs
}

// New creates a new client.
func NewClient(clientArgs common.ClientArgs) *Client {
	return &Client{
		ClientArgs: clientArgs,
	}
}

// get gives access to the raw Kubernetes resource.
func (c *Client) get(ctx context.Context, organizationID, projectID, serverID string) (*unikornv1.Server, error) {
	resource := &unikornv1.Server{}

	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: serverID}, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: unable to get server", err)
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
		Namespace: c.Namespace,
		LabelSelector: labels.SelectorFromSet(map[string]string{
			coreconstants.OrganizationLabel: organizationID,
		}),
	}

	if err := c.Client.List(ctx, result, options); err != nil {
		return nil, fmt.Errorf("%w: unable to list servers", err)
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
	identity, err := identity.New(c.ClientArgs).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return nil, err
	}

	provider, err := c.Providers.LookupCloud(ctx, identity.Labels[constants.RegionLabel])
	if err != nil {
		return nil, providers.ProviderToServerError(err)
	}

	if _, err := provider.GetImage(ctx, organizationID, request.Spec.ImageId); err != nil {
		if goerrors.Is(err, coreerrors.ErrResourceNotFound) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: failed to retrieve image from provider", err)
	}

	resource, err := newGenerator(c.ClientArgs, organizationID, projectID, identityID).generate(ctx, request)
	if err != nil {
		return nil, err
	}

	resource.Status.Phase = unikornv1.InstanceLifecyclePhasePending

	if err := c.Client.Create(ctx, resource); err != nil {
		return nil, fmt.Errorf("%w: unable to create server", err)
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
	identity, err := identity.New(c.ClientArgs).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return nil, err
	}

	provider, err := c.Providers.LookupCloud(ctx, identity.Labels[constants.RegionLabel])
	if err != nil {
		return nil, providers.ProviderToServerError(err)
	}

	if _, err := provider.GetImage(ctx, organizationID, request.Spec.ImageId); err != nil {
		if goerrors.Is(err, coreerrors.ErrResourceNotFound) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: failed to retrieve image from provider", err)
	}

	current, err := c.get(ctx, organizationID, projectID, serverID)
	if err != nil {
		return nil, err
	}

	required, err := newGenerator(c.ClientArgs, organizationID, projectID, identityID).generate(ctx, request)
	if err != nil {
		return nil, err
	}

	if err := conversion.UpdateObjectMetadata(required, current, identitycommon.IdentityMetadataMutator); err != nil {
		return nil, fmt.Errorf("%w: failed to merge metadata", err)
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := c.Client.Patch(ctx, updated, client.MergeFromWithOptions(current, &client.MergeFromWithOptimisticLock{})); err != nil {
		return nil, fmt.Errorf("%w: failed to patch server", err)
	}

	return convert(updated), nil
}

func (c *Client) getServerIdentityAndProvider(ctx context.Context, organizationID, projectID, identityID, serverID string) (*unikornv1.Server, *unikornv1.Identity, types.Provider, error) {
	current, err := c.get(ctx, organizationID, projectID, serverID)
	if err != nil {
		return nil, nil, nil, err
	}

	identity, err := identity.New(c.ClientArgs).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return nil, nil, nil, err
	}

	provider, err := c.Providers.LookupCloud(ctx, current.Labels[constants.RegionLabel])
	if err != nil {
		return nil, nil, nil, providers.ProviderToServerError(err)
	}

	return current, identity, provider, nil
}

func (c *Client) Reboot(ctx context.Context, organizationID, projectID, identityID, serverID string, hard bool) error {
	server, identity, provider, err := c.getServerIdentityAndProvider(ctx, organizationID, projectID, identityID, serverID)
	if err != nil {
		return err
	}

	return c.reboot(ctx, identity, server, hard, provider)
}

func (c *Client) reboot(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, hard bool, provider types.Provider) error {
	if err := provider.RebootServer(ctx, identity, server, hard); err != nil {
		if goerrors.Is(err, coreerrors.ErrResourceNotFound) {
			return errors.HTTPNotFound().WithError(err)
		}

		if goerrors.Is(err, coreerrors.ErrConflict) {
			return errors.OAuth2InvalidRequest("server cannot be rebooted in its current state").WithError(err)
		}

		if hard {
			return fmt.Errorf("%w: failed to hard reboot server", err)
		}

		return fmt.Errorf("%w: failed to soft reboot server", err)
	}

	return nil
}

func (c *Client) Start(ctx context.Context, organizationID, projectID, identityID, serverID string) error {
	server, identity, provider, err := c.getServerIdentityAndProvider(ctx, organizationID, projectID, identityID, serverID)
	if err != nil {
		return err
	}

	return c.start(ctx, identity, server, provider)
}

func (c *Client) start(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, provider types.Provider) error {
	if err := provider.StartServer(ctx, identity, server); err != nil {
		if goerrors.Is(err, coreerrors.ErrResourceNotFound) {
			return errors.HTTPNotFound().WithError(err)
		}

		if goerrors.Is(err, coreerrors.ErrConflict) {
			return errors.OAuth2InvalidRequest("server cannot be started in its current state").WithError(err)
		}

		return fmt.Errorf("%w: failed to start server", err)
	}

	updated := server.DeepCopy()
	updated.Status.Phase = unikornv1.InstanceLifecyclePhasePending

	if err := c.Client.Status().Patch(ctx, updated, client.MergeFromWithOptions(server, &client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("%w: failed to patch server", err)
	}

	return nil
}

func (c *Client) Stop(ctx context.Context, organizationID, projectID, identityID, serverID string) error {
	server, identity, provider, err := c.getServerIdentityAndProvider(ctx, organizationID, projectID, identityID, serverID)
	if err != nil {
		return err
	}

	return c.stop(ctx, identity, server, provider)
}

func (c *Client) stop(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, provider types.Provider) error {
	if err := provider.StopServer(ctx, identity, server); err != nil {
		if goerrors.Is(err, coreerrors.ErrResourceNotFound) {
			return errors.HTTPNotFound().WithError(err)
		}

		if goerrors.Is(err, coreerrors.ErrConflict) {
			return errors.OAuth2InvalidRequest("server cannot be stopped in its current state").WithError(err)
		}

		return fmt.Errorf("%w: failed to stop server", err)
	}

	updated := server.DeepCopy()
	updated.Status.Phase = unikornv1.InstanceLifecyclePhaseStopping

	if err := c.Client.Status().Patch(ctx, updated, client.MergeFromWithOptions(server, &client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("%w: failed to patch server", err)
	}

	return nil
}

// Delete a resource.
func (c *Client) Delete(ctx context.Context, organizationID, projectID, serverID string) error {
	resource, err := c.get(ctx, organizationID, projectID, serverID)
	if err != nil {
		return err
	}

	if err := c.Client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return fmt.Errorf("%w: unable to delete server", err)
	}

	return nil
}

func (c *Client) CreateConsoleSession(ctx context.Context, organizationID, projectID, identityID, serverID string) (*openapi.ConsoleSessionResponse, error) {
	server, identity, provider, err := c.getServerIdentityAndProvider(ctx, organizationID, projectID, identityID, serverID)
	if err != nil {
		return nil, err
	}

	return c.createConsoleSession(ctx, identity, server, provider)
}

func (c *Client) createConsoleSession(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, provider types.Provider) (*openapi.ConsoleSessionResponse, error) {
	url, err := provider.CreateConsoleSession(ctx, identity, server)
	if err != nil {
		if goerrors.Is(err, coreerrors.ErrResourceNotFound) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		if goerrors.Is(err, coreerrors.ErrConflict) {
			return nil, errors.OAuth2InvalidRequest("server cannot be accessed in its current state").WithError(err)
		}

		return nil, fmt.Errorf("%w: failed to create console session", err)
	}

	response := &openapi.ConsoleSessionResponse{
		Url: url,
	}

	return response, nil
}

func (c *Client) GetConsoleOutput(ctx context.Context, organizationID, projectID, identityID, serverID string, params openapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDConsoleoutputParams) (*openapi.ConsoleOutputResponse, error) {
	server, identity, provider, err := c.getServerIdentityAndProvider(ctx, organizationID, projectID, identityID, serverID)
	if err != nil {
		return nil, err
	}

	return c.getConsoleOutput(ctx, identity, server, params.Length, provider)
}

func (c *Client) getConsoleOutput(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, length *int, provider types.Provider) (*openapi.ConsoleOutputResponse, error) {
	contents, err := provider.GetConsoleOutput(ctx, identity, server, length)
	if err != nil {
		if goerrors.Is(err, coreerrors.ErrResourceNotFound) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		if goerrors.Is(err, coreerrors.ErrConflict) {
			return nil, errors.OAuth2InvalidRequest("server console output cannot be retrieved in its current state").WithError(err)
		}

		return nil, fmt.Errorf("%w: failed to retrieve console output", err)
	}

	response := &openapi.ConsoleOutputResponse{
		Contents: contents,
	}

	return response, nil
}
