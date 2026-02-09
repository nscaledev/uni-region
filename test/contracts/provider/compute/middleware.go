//go:build integration

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

package compute_test

import (
	"net/http"

	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	commonmiddleware "github.com/unikorn-cloud/region/test/contracts/provider/common"
)

// MockACLMiddleware injects a mock ACL into the request context for contract testing.
// This allows the handler to bypass RBAC checks without requiring real authentication.
// For contract testing with parameterized states, organization IDs come from the consumer contract,
// so we create a permissive ACL that extracts the organization ID from the request path.
func MockACLMiddleware(_ []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create endpoints that grant read access to all region resources
			endpoints := identityapi.AclEndpoints{
				{Name: "region:regions", Operations: identityapi.AclOperations{identityapi.Read}},
				{Name: "region:flavors", Operations: identityapi.AclOperations{identityapi.Read}},
				{Name: "region:images", Operations: identityapi.AclOperations{identityapi.Read}},
				{Name: "region:externalnetworks", Operations: identityapi.AclOperations{identityapi.Read}},
				{Name: "region:regions/detail", Operations: identityapi.AclOperations{identityapi.Read}},
			}

			// Extract organization ID from request path
			// Pattern: /api/v1/organizations/{orgID}/...
			orgID := commonmiddleware.ExtractOrganizationID(r.URL.Path)
			if orgID == "" {
				// Fallback to a default org if extraction fails
				orgID = "test-org"
			}

			// Create a single organization with the extracted/default ID
			organizations := identityapi.AclOrganizationList{
				{
					Id:        orgID,
					Endpoints: &endpoints,
				},
			}

			mockACL := &identityapi.Acl{
				Organizations: &organizations,
			}

			// Inject the mock ACL into the request context
			ctx := rbac.NewContext(r.Context(), mockACL)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
