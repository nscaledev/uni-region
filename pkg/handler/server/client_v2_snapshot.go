/*
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
	"context"

	"github.com/unikorn-cloud/core/pkg/constants"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/region/pkg/handler/image"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

func (c *Client) CreateV2Snapshot(ctx context.Context, serverID string, request *openapi.SnapshotCreate) (*openapi.ImageResponse, error) {
	server, identity, provider, err := c.getServerIdentityAndProviderV2(ctx, serverID)
	if err != nil {
		return nil, err
	}

	organizationID := server.Labels[constants.OrganizationLabel]

	// You need region:servers/read to get the server in the first place, then
	// region:images/create to make the image. The first of those is implicitly
	// checked when the server is fetched.
	if err := rbac.AllowOrganizationScope(ctx, "region:images", identityapi.Create, organizationID); err != nil {
		return nil, err
	}

	// Get the existing image so we can preserve the metadata.
	requested, err := provider.GetImage(ctx, organizationID, server.Spec.Image.ID)
	if err != nil {
		return nil, err
	}

	// Give it a new name and ensure it belongs to the server's organization.
	// TODO: patch in any new metadata e.g. software packages.
	requested.Name = request.Metadata.Name
	requested.Tags = image.GenerateTags(request.Metadata.Tags)
	requested.OrganizationID = &organizationID

	result, err := provider.CreateSnapshot(ctx, identity, server, requested)
	if err != nil {
		return nil, err
	}

	return image.ConvertImage(result), nil
}
