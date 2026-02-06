//go:build integration

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

package kubernetes_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/region/pkg/openapi"
	commonmiddleware "github.com/unikorn-cloud/region/test/contracts/provider/common"
)

// MockACLMiddleware injects a mock ACL into the request context for contract testing.
// This allows the handler to bypass RBAC checks without requiring real authentication.
// For contract testing with parameterized states, organization IDs come from the consumer contract,
// so we create a permissive ACL that extracts the organization ID from the request path.
func MockACLMiddleware(_ []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract organization ID and project ID from request path
			// Pattern: /api/v1/organizations/{orgID}/projects/{projectID}/...
			orgID := commonmiddleware.ExtractOrganizationID(r.URL.Path)
			if orgID == "" {
				orgID = "test-org"
			}

			projectID := commonmiddleware.ExtractProjectID(r.URL.Path)
			if projectID == "" {
				projectID = "test-project"
			}

			// Create organization-level endpoints for region resources
			orgEndpoints := identityapi.AclEndpoints{
				{Name: "region:regions", Operations: identityapi.AclOperations{identityapi.Read}},
				{Name: "region:regions/detail", Operations: identityapi.AclOperations{identityapi.Read}},
				{Name: "region:flavors", Operations: identityapi.AclOperations{identityapi.Read}},
				{Name: "region:images", Operations: identityapi.AclOperations{identityapi.Read}},
				{Name: "region:externalnetworks", Operations: identityapi.AclOperations{identityapi.Read}},
			}

			// Create project-level endpoints for compute resources
			projectEndpoints := identityapi.AclEndpoints{
				{Name: "region:servers", Operations: identityapi.AclOperations{identityapi.Read, identityapi.Create, identityapi.Update, identityapi.Delete}},
				{Name: "region:identities", Operations: identityapi.AclOperations{identityapi.Read, identityapi.Create, identityapi.Update, identityapi.Delete}},
				{Name: "region:networks", Operations: identityapi.AclOperations{identityapi.Read, identityapi.Create, identityapi.Update, identityapi.Delete}},
			}

			// Create project ACL
			projects := identityapi.AclProjectList{
				{
					Id:        projectID,
					Endpoints: projectEndpoints,
				},
			}

			// Create organization with both org-level and project-level permissions
			organizations := identityapi.AclOrganizationList{
				{
					Id:        orgID,
					Endpoints: &orgEndpoints,
					Projects:  &projects,
				},
			}

			mockACL := &identityapi.Acl{
				Organizations: &organizations,
			}

			// Inject mock authorization info for SetIdentityMetadata
			mockUserinfo := &identityapi.Userinfo{
				Sub: "test-user@example.com",
			}
			mockAuthInfo := &authorization.Info{
				Token:    "mock-token",
				Userinfo: mockUserinfo,
			}

			// Inject mock principal for SetIdentityMetadata
			mockPrincipal := &principal.Principal{
				OrganizationID: orgID,
				ProjectID:      projectID,
				Actor:          "test-user@example.com",
			}

			// Inject all contexts
			ctx := r.Context()
			ctx = rbac.NewContext(ctx, mockACL)
			ctx = authorization.NewContext(ctx, mockAuthInfo)
			ctx = principal.NewContext(ctx, mockPrincipal)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// IdentityCreationMockMiddleware mocks POST /identities responses for contract testing.
// This bypasses OpenStack provider initialization which requires real infrastructure.
func IdentityCreationMockMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !shouldInterceptIdentityCreation(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Parse request body
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read request body", http.StatusInternalServerError)
				return
			}
			defer r.Body.Close()

			var identityRequest openapi.IdentityWrite
			if err := json.Unmarshal(body, &identityRequest); err != nil {
				http.Error(w, "failed to parse request body", http.StatusBadRequest)
				return
			}

			// Create mock identity response
			mockResponse := openapi.IdentityRead{
				Metadata: coreopenapi.ProjectScopedResourceReadMetadata{
					Id:                 "fc763eba-0905-41c5-a27f-3934ab26786c",
					Name:               identityRequest.Metadata.Name,
					CreationTime:       time.Date(2000, 2, 1, 12, 30, 0, 0, time.UTC),
					OrganizationId:     commonmiddleware.ExtractOrganizationID(r.URL.Path),
					ProjectId:          commonmiddleware.ExtractProjectID(r.URL.Path),
					ProvisioningStatus: coreopenapi.ResourceProvisioningStatusUnknown,
				},
				Spec: openapi.IdentitySpec{
					RegionId: identityRequest.Spec.RegionId,
				},
			}

			// Write response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(mockResponse)
		})
	}
}

// shouldInterceptIdentityCreation checks if this is a POST to /identities.
func shouldInterceptIdentityCreation(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}

	// Pattern: /api/v1/organizations/{orgID}/projects/{projectID}/identities
	path := r.URL.Path

	return strings.HasSuffix(path, "/identities") && strings.Contains(path, "/projects/")
}

// ExternalNetworksMockMiddleware mocks external networks for OpenStack cluster.
func ExternalNetworksMockMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !shouldInterceptExternalNetworks(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Return minimal mock data - consumer contract requires at least 1 item
			mockNetworks := []openapi.ExternalNetwork{
				{
					Id: "fc763eba-0905-41c5-a27f-3934ab26786c",
				},
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(mockNetworks)
		})
	}
}

// shouldInterceptExternalNetworks checks if this is a GET to /externalnetworks.
func shouldInterceptExternalNetworks(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}

	// Pattern: /api/v1/organizations/{orgID}/regions/{regionID}/externalnetworks
	path := r.URL.Path

	return strings.HasSuffix(path, "/externalnetworks")
}

// ImagesMockMiddleware mocks images for OpenStack cluster.
func ImagesMockMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !shouldInterceptImages(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Return mock image for contract testing
			softwareVersions := openapi.SoftwareVersions{
				"kubernetes": "v1.27.0",
			}

			mockImages := []openapi.Image{
				{
					Metadata: coreopenapi.StaticResourceMetadata{
						Id:   "fc763eba-0905-41c5-a27f-3934ab26786c",
						Name: "Ubuntu 22.04 Kubernetes v1.27.0",
					},
					Spec: openapi.ImageSpec{
						SoftwareVersions: &softwareVersions,
					},
				},
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(mockImages)
		})
	}
}

// shouldInterceptImages checks if this is a GET to /images.
func shouldInterceptImages(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}

	// Pattern: /api/v1/organizations/{orgID}/regions/{regionID}/images
	path := r.URL.Path

	return strings.HasSuffix(path, "/images") && !strings.Contains(path, "/images/")
}
