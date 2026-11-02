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

	"github.com/unikorn-cloud/identity/pkg/authz"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/image"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

func (c *ClientV2) CreateV2Snapshot(ctx context.Context, serverID regionids.ServerID, request *openapi.SnapshotCreate) (*openapi.ImageResponse, error) {
	// A snapshot is an action on the server, which needs update on it, and it
	// makes an image, which needs region:images/create in the server's
	// organization.  The server is what the request acts on.
	server, identity, provider, err := c.getServerIdentityAndProviderV2(ctx, serverID, actionTarget("snapshot"))
	if err != nil {
		return nil, err
	}

	// Recover the typed organization ID so a malformed owner label fails closed
	// rather than silently denying access; it is the single source for the
	// string form used in tags below.
	organizationScopeID, err := server.OrganizationID()
	if err != nil {
		return nil, err
	}

	images := authz.Target{
		Endpoint:  "region:images",
		Operation: authz.Create,
	}

	if err := rbac.AllowOrganizationScopeOn(ctx, images, organizationScopeID); err != nil {
		return nil, err
	}

	organizationID := organizationScopeID.String()

	// Get the existing image so we can preserve the metadata.
	requested, err := provider.GetImage(ctx, organizationScopeID, server.Spec.Image.ID)
	if err != nil {
		return nil, err
	}

	// Get all the user-supplied tags, and set our own tags for the provenance and ownership.
	tags := image.GenerateTags(request.Metadata.Tags, map[string]string{
		constants.ImageSourceTag:         constants.ImageSourceSnapshot,
		constants.ImageOrganizationIDTag: organizationID,
	})

	// Give it a new name and ensure it belongs to the server's organization.
	// TODO: patch in any new metadata e.g. software packages.
	requested.Name = request.Metadata.Name
	requested.Tags = tags
	requested.OrganizationID = &organizationID

	result, err := provider.CreateSnapshot(ctx, identity, server, requested)
	if err != nil {
		return nil, err
	}

	return image.ConvertImage(result), nil
}
