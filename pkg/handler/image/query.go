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
	"context"

	"github.com/unikorn-cloud/region/pkg/openapi"
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

	result, err := query.List(ctx)
	if err != nil {
		return nil, err
	}

	return convertImages(result), nil
}
