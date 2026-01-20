/*
Copyright 2025 the Unikorn Authors.
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

package image

import (
	"cmp"
	"context"
	"slices"

	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"
)

func (c *Client) QueryImages(ctx context.Context, regionID string, params openapi.GetApiV2RegionsRegionIDImagesParams) (openapi.Images, error) {
	prov, err := c.getProvider(ctx, c.Client, c.Namespace, regionID)
	if err != nil {
		return nil, err
	}

	query, err := prov.QueryImages()
	if err != nil {
		return nil, err
	}

	if orgIDs := params.OrganizationID; orgIDs != nil {
		// default scope to available, if not provided.
		if params.Scope != nil && *params.Scope == openapi.GetApiV2RegionsRegionIDImagesParamsScopeOwned {
			query = query.OwnedByOrganization(*orgIDs...)
		} else {
			query = query.AvailableToOrganization(*orgIDs...)
		}
	}

	if s := params.Status; s != nil {
		statuses := *s

		queryStatuses := make([]types.ImageStatus, 0, len(statuses))

		for i := range statuses {
			if s := generateStatus(statuses[i]); s != "" {
				queryStatuses = append(queryStatuses, s)
			}
		}

		query = query.StatusIn(queryStatuses...)
	}

	result, err := query.List(ctx)
	if err != nil {
		return nil, err
	}

	// Apply ordering guarantees, ordered by name.
	slices.SortStableFunc(result, func(a, b types.Image) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertImages(result), nil
}
