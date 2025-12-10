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

package api

import (
	"fmt"
	"net/url"
)

// Endpoints contains API endpoint patterns.
// Add endpoint methods here as you write tests for them.
type Endpoints struct{}

// NewEndpoints creates a new Endpoints instance.
func NewEndpoints() *Endpoints {
	return &Endpoints{}
}

// ListRegions returns the endpoint for listing all regions in an organization.
func (e *Endpoints) ListRegions(orgID string) string {
	return fmt.Sprintf("/api/v1/organizations/%s/regions",
		url.PathEscape(orgID))
}

// GetRegionDetail returns the endpoint for getting detailed region information.
func (e *Endpoints) GetRegionDetail(orgID, regionID string) string {
	return fmt.Sprintf("/api/v1/organizations/%s/regions/%s/detail",
		url.PathEscape(orgID), url.PathEscape(regionID))
}

// ListFlavors returns the endpoint for listing flavors in a region.
func (e *Endpoints) ListFlavors(orgID, regionID string) string {
	return fmt.Sprintf("/api/v1/organizations/%s/regions/%s/flavors",
		url.PathEscape(orgID), url.PathEscape(regionID))
}

// ListImages returns the endpoint for listing images in a region.
func (e *Endpoints) ListImages(orgID, regionID string) string {
	return fmt.Sprintf("/api/v1/organizations/%s/regions/%s/images",
		url.PathEscape(orgID), url.PathEscape(regionID))
}

// ListExternalNetworks returns the endpoint for listing external networks in a region.
func (e *Endpoints) ListExternalNetworks(orgID, regionID string) string {
	return fmt.Sprintf("/api/v1/organizations/%s/regions/%s/externalnetworks",
		url.PathEscape(orgID), url.PathEscape(regionID))
}
