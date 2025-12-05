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

// Example endpoint patterns, taken from what in uni-compute:
//
// func (e *Endpoints) ListRegions(orgID string) string {
// 	return fmt.Sprintf("/api/v1/organizations/%s/regions",
// 		url.PathEscape(orgID))
// }
//
// func (e *Endpoints) CreateIdentity(orgID, projectID string) string {
// 	return fmt.Sprintf("/api/v1/organizations/%s/projects/%s/identities",
// 		url.PathEscape(orgID), url.PathEscape(projectID))
// }

// Suppress unused warnings - remove this when I add the actual endpoints.
var _ = fmt.Sprint
var _ = url.PathEscape
