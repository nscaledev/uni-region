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
	"github.com/unikorn-cloud/core/pkg/server/errors"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

func (c *Client) CreateV2Snapshot(ctx context.Context, serverID string, request *openapi.SnapshotCreate) (*openapi.ImageResponse, error) {
	server, err := c.GetV2Raw(ctx, serverID)
	if err != nil {
		return nil, err
	}

	if err := rbac.AllowOrganizationScope(ctx, "region:images", identityapi.Create, server.Labels[constants.OrganizationLabel]); err != nil {
		return nil, err
	}

	// FIXME stub
	return nil, errors.HTTPUnprocessableContent("unimplemented")
}
