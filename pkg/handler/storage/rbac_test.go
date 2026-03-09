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

package storage_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	identitymock "github.com/unikorn-cloud/identity/pkg/openapi/mock"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/storage"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

const (
	testOrgID  = "foo"
	testProjID = "bar"
)

// aclWithOrgScopeStorageCreate grants region:filestorage:v2/Create at
// organization scope, so CreateV2 must verify the project via the identity API.
func aclWithOrgScopeStorageCreate() *identityapi.Acl {
	return &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{
			{
				Id: testOrgID,
				Endpoints: &identityapi.AclEndpoints{
					{
						Name:       "region:filestorage:v2",
						Operations: identityapi.AclOperations{identityapi.Create},
					},
				},
			},
		},
	}
}

// minimalStorageV2CreateRequest returns a StorageV2Create request body with
// the given organization and project IDs.
func minimalStorageV2CreateRequest(orgID, projID string) *openapi.StorageV2Create {
	return &openapi.StorageV2Create{
		Metadata: coreapi.ResourceWriteMetadata{
			Name: "test-storage",
		},
		Spec: struct {
			Attachments    *openapi.StorageAttachmentV2Spec `json:"attachments,omitempty"`
			OrganizationId string                           `json:"organizationId"`
			ProjectId      string                           `json:"projectId"`
			RegionId       string                           `json:"regionId"`
			SizeGiB        int64                            `json:"sizeGiB"`
			StorageClassId string                           `json:"storageClassId"`
			StorageType    openapi.StorageTypeV2Spec        `json:"storageType"`
		}{
			OrganizationId: orgID,
			ProjectId:      projID,
		},
	}
}

// TestStorageCreateV2RBACOrgScopedProjectNotFound verifies that CreateV2 returns
// a 404 Not Found when the caller has org-scoped ACL but supplies a project ID
// that does not exist.
func TestStorageCreateV2RBACOrgScopedProjectNotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	mockIdentity.EXPECT().
		GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), testOrgID, "nonexistent-project").
		Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
		}, nil)

	c := storage.New(common.ClientArgs{Identity: mockIdentity})

	ctx := rbac.NewContext(t.Context(), aclWithOrgScopeStorageCreate())

	_, err := c.CreateV2(ctx, minimalStorageV2CreateRequest(testOrgID, "nonexistent-project"))

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

// TestStorageCreateV2RBACNoPermissions verifies that CreateV2 returns a
// forbidden error when the caller has no relevant permissions.
func TestStorageCreateV2RBACNoPermissions(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	// No EXPECT calls — the identity API must not be contacted.

	c := storage.New(common.ClientArgs{Identity: mockIdentity})

	ctx := rbac.NewContext(t.Context(), &identityapi.Acl{})

	_, err := c.CreateV2(ctx, minimalStorageV2CreateRequest(testOrgID, testProjID))

	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err), "expected forbidden, got: %v", err)
}
