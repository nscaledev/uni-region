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
	"slices"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Client struct {
	// client allows Kubernetes API access.
	client client.Client

	// namespace the controller runs in.
	namespace string
}

func NewClient(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

func (c *Client) List(ctx context.Context, organizationID string) (openapi.ServersRead, error) {
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

	// Apply ordering guarantees, ordered by name.
	slices.SortStableFunc(result.Items, func(a, b unikornv1.Server) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertList(result), nil
}

func (c *Client) Create(ctx context.Context, organizationID, projectID string, identity *unikornv1.Identity, network *unikornv1.Network, request *openapi.ServerWrite) (*openapi.ServerRead, error) {
	resource, err := newGenerator(c.client, c.namespace, organizationID, projectID, identity, network).generate(ctx, request)
	if err != nil {
		return nil, err
	}

	if err := c.client.Create(ctx, resource); err != nil {
		return nil, errors.OAuth2ServerError("unable to create server").WithError(err)
	}

	return convert(resource), nil
}

func (c *Client) Get(ctx context.Context, serverID string) (*openapi.ServerRead, error) {
	resource, err := c.getServer(ctx, serverID)
	if err != nil {
		return nil, err
	}

	return convert(resource), nil
}

func (c *Client) Delete(ctx context.Context, serverID string) error {
	resource, err := c.getServer(ctx, serverID)
	if err != nil {
		return err
	}

	if resource.DeletionTimestamp != nil {
		return errors.OAuth2InvalidRequest("server is already being deleted")
	}

	if err := c.client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("unable to delete server").WithError(err)
	}

	return nil
}

func (c *Client) getServer(ctx context.Context, id string) (*unikornv1.Server, error) {
	resource := &unikornv1.Server{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: id}, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to get server").WithError(err)
	}

	return resource, nil
}
