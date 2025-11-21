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

package image

import (
	"cmp"
	"context"
	goerrors "errors"
	"io"
	"slices"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Client struct {
	client    client.Client
	namespace string
}

func NewClient(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

type provider interface {
	types.ImageRead
}

var errTempNotImplemented = goerrors.New("not implemented (yet)")

func (c *Client) provider(ctx context.Context, regionID string) (provider, error) {
	return providers.New(ctx, c.client, c.namespace, regionID)
}

func (c *Client) ListImages(ctx context.Context, organizationID, regionID string) (openapi.Images, error) {
	provider, err := c.provider(ctx, regionID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	result, err := provider.ListImages(ctx, organizationID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to list images").WithError(err)
	}

	// Apply ordering guarantees, ordered by name.
	slices.SortStableFunc(result, func(a, b types.Image) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertImages(result), nil
}

func (c *Client) CreateImage(ctx context.Context, organizationID, regionID string, request *openapi.ImageCreateRequest) (*openapi.ImageResponse, error) {
	return nil, errTempNotImplemented
}

func (c *Client) DeleteImage(ctx context.Context, organizationID, regionID, imageID string) error {
	return errTempNotImplemented
}

func (c *Client) UploadImage(ctx context.Context, organizationID, regionID, imageID string, contentType string, data io.Reader) (*openapi.ImageResponse, error) {
	return nil, errTempNotImplemented
}
