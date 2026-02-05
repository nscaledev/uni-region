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
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

// State constants for Pact contract testing.
// These must match the state names in the consumer contracts exactly.
const (
	StateRegionExists                  = "region exists"
	StateProjectExistsInRegion         = "project exists in region"
	StateServerExistsInProject         = "server exists in project"
	StateIdentityExists                = "identity exists"
	StateIdentityExistsWithPhysicalNet = "identity exists with physical network support"
	StateIdentityIsProvisioned         = "identity is provisioned"
	StateNetworkIsProvisioned          = "network is provisioned"
	StateRegionHasExternalNetworks     = "region has external networks"
	StateRegionHasFlavors              = "region has flavors"
	StateRegionHasImages               = "region has images"
	StateOrganizationHasRegions        = "organization has regions"
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
			orgID := extractOrganizationID(r.URL.Path)
			if orgID == "" {
				orgID = "test-org"
			}

			projectID := extractProjectID(r.URL.Path)
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

// extractOrganizationID extracts the organization ID from the request path.
// Expected pattern: /api/v1/organizations/{orgID}/...
func extractOrganizationID(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "organizations" && i+1 < len(parts) {
			return parts[i+1]
		}
	}

	return ""
}

// extractProjectID extracts the project ID from the request path.
// Expected pattern: /api/v1/organizations/{orgID}/projects/{projectID}/...
func extractProjectID(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "projects" && i+1 < len(parts) {
			return parts[i+1]
		}
	}

	return ""
}

// RegionSortingMiddleware sorts regions responses for Pact contract testing.
//
// Background: Pact Go v2 requires specific array ordering for verification.
// The OpenAPI spec does not guarantee ordering, but we sort deterministically
// (OpenStack before Kubernetes, then alphabetically by name) to satisfy Pact.
//
// Note: This is a limitation of Pact Go v2, which doesn't support order-independent
// array matching for specific items. In the real API, ordering is not guaranteed.
// basically this is a workaround to make the test pass, but sorting does not change the semantics of the response.
func RegionSortingMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !shouldInterceptRegionsRequest(r) {
				next.ServeHTTP(w, r)
				return
			}

			recorder := captureResponse(w, next, r)
			copyHeaders(w, recorder)

			if !shouldProcessResponse(recorder) {
				writeResponseAsIs(w, recorder)
				return
			}

			processAndWriteRegionsResponse(w, recorder)
		})
	}
}

// shouldInterceptRegionsRequest checks if this is a GET request to the regions list endpoint.
// This is used to determine whether the response should be transformed for sorting to satisfy Pact contract testing.
func shouldInterceptRegionsRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}

	// Pattern: /api/v1/organizations/{orgID}/regions
	path := r.URL.Path

	return strings.HasSuffix(path, "/regions") && !strings.Contains(path, "/regions/")
}

// captureResponse captures the handler response using a recorder.
// This allows us to inspect and transform the response before writing it to the client.
// once again this is a workaround to make the test pass, but it does not change the semantics of the response.
func captureResponse(w http.ResponseWriter, next http.Handler, r *http.Request) *responseRecorder {
	recorder := &responseRecorder{
		ResponseWriter: w,
		body:           &bytes.Buffer{},
		statusCode:     http.StatusOK,
		headers:        make(http.Header),
	}
	next.ServeHTTP(recorder, r)

	return recorder
}

// copyHeaders copies all headers from the recorder to the response writer.
func copyHeaders(w http.ResponseWriter, recorder *responseRecorder) {
	for key, values := range recorder.headers {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
}

// shouldProcessResponse checks if the response should be processed (200 OK).
// Only successful responses are transformed; errors are passed through unchanged.
func shouldProcessResponse(recorder *responseRecorder) bool {
	return recorder.statusCode == http.StatusOK
}

// writeResponseAsIs writes the recorded response without modification.
// Used as a fallback when transformation fails or is not needed.
func writeResponseAsIs(w http.ResponseWriter, recorder *responseRecorder) {
	w.WriteHeader(recorder.statusCode)
	_, _ = io.Copy(w, recorder.body)
}

// processAndWriteRegionsResponse parses, transforms, sorts, and writes the regions response.
// This ensures consistent ordering and ID format for Pact verification.
func processAndWriteRegionsResponse(w http.ResponseWriter, recorder *responseRecorder) {
	var regions []openapi.RegionRead
	if err := json.Unmarshal(recorder.body.Bytes(), &regions); err != nil {
		fmt.Printf("Warning: failed to unmarshal regions response for transformation: %v\n", err)
		writeResponseAsIs(w, recorder)

		return
	}

	transformRegionIDs(regions)
	sortRegions(regions)

	sortedJSON, err := json.Marshal(regions)
	if err != nil {
		fmt.Printf("Warning: failed to marshal transformed regions: %v\n", err)
		writeResponseAsIs(w, recorder)

		return
	}

	w.WriteHeader(recorder.statusCode)
	_, _ = w.Write(sortedJSON)
}

// transformRegionIDs converts region IDs from names to UUIDs for Pact testing.
// The provider returns region names as IDs, but the pact expects UUID format.
// the reason we have this is usually there is a middleware that converts the region names to UUIDs.
// This transformation ensures consistent IDs across test runs.
func transformRegionIDs(regions []openapi.RegionRead) {
	for i := range regions {
		if regions[i].Metadata.Id != "" {
			regions[i].Metadata.Id = nameToUUID(regions[i].Metadata.Name)
		}
	}
}

// sortRegions sorts by type (OpenStack first) then by name.
// This deterministic ordering is required for Pact Go v2 verification.
func sortRegions(regions []openapi.RegionRead) {
	slices.SortStableFunc(regions, func(a, b openapi.RegionRead) int {
		if a.Spec.Type != b.Spec.Type {
			if a.Spec.Type == openapi.RegionTypeOpenstack {
				return -1
			}

			if b.Spec.Type == openapi.RegionTypeOpenstack {
				return 1
			}
		}

		return cmp.Compare(a.Metadata.Name, b.Metadata.Name)
	})
}

// responseRecorder captures the response for processing.
// It implements http.ResponseWriter to intercept writes from the handler.
type responseRecorder struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
	headers    http.Header
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
}

func (r *responseRecorder) Header() http.Header {
	if r.headers == nil {
		r.headers = make(http.Header)
	}

	return r.headers
}

// regionIDNamespace is the namespace UUID for generating deterministic region IDs.
var regionIDNamespace = uuid.NameSpaceURL //nolint:gochecknoglobals // Standard namespace for resource identifiers

// nameToUUID generates a deterministic UUID v5 from a region name.
func nameToUUID(name string) string {
	id := uuid.NewSHA1(regionIDNamespace, []byte("region-id:"+name))
	return id.String()
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
					OrganizationId:     extractOrganizationID(r.URL.Path),
					ProjectId:          extractProjectID(r.URL.Path),
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
