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

package server_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	identitymock "github.com/unikorn-cloud/identity/pkg/openapi/mock"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/server"
	"github.com/unikorn-cloud/region/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	srvOrganizationID = "foo"
	srvProjectID      = "bar"
	srvNamespace      = "test-namespace"
	srvNetworkID      = "test-network"
)

// newSrvFakeClient builds a fake k8s client pre-populated with the given objects.
func newSrvFakeClient(t *testing.T, objects ...runtime.Object) *fake.ClientBuilder {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, regionv1.AddToScheme(scheme))

	builder := fake.NewClientBuilder().WithScheme(scheme)

	for _, o := range objects {
		builder = builder.WithRuntimeObjects(o)
	}

	return builder
}

// testSrvNetworkWithProject returns a v2 Network object with the given org/project labels.
func testSrvNetworkWithProject(orgID, projID string) *regionv1.Network {
	return &regionv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      srvNetworkID,
			Namespace: srvNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   orgID,
				coreconstants.ProjectLabel:        projID,
				constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
			},
		},
	}
}

// aclWithOrgScopeServerCreate grants network:read and region:servers/Create at
// organization scope so GetV2Raw passes and AllowProjectScopeCreate is reached.
func aclWithOrgScopeServerCreate(orgID string) *identityapi.Acl {
	return &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{
			{
				Id: orgID,
				Endpoints: &identityapi.AclEndpoints{
					{
						Name:       "region:networks:v2",
						Operations: identityapi.AclOperations{identityapi.Read},
					},
					{
						Name:       "region:servers",
						Operations: identityapi.AclOperations{identityapi.Create},
					},
				},
			},
		},
	}
}

// aclWithSrvNetworkReadOnly grants network:read at organization scope but no
// server:create, so the server RBAC check returns forbidden.
func aclWithSrvNetworkReadOnly(orgID string) *identityapi.Acl {
	return &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{
			{
				Id: orgID,
				Endpoints: &identityapi.AclEndpoints{
					{
						Name:       "region:networks:v2",
						Operations: identityapi.AclOperations{identityapi.Read},
					},
				},
			},
		},
	}
}

func minimalServerV2CreateRequest(networkID string) *openapi.ServerV2Create {
	return &openapi.ServerV2Create{
		Metadata: coreapi.ResourceWriteMetadata{Name: "test-server"},
		Spec: openapi.ServerV2CreateSpec{
			NetworkId: networkID,
		},
	}
}

// TestServerCreateV2RBACOrgScopedProjectNotFound verifies that CreateV2 returns
// a 404 Not Found when the caller has org-scoped ACL but the project from the
// network labels does not exist in the identity service.
func TestServerCreateV2RBACOrgScopedProjectNotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvOrganizationID, "nonexistent-project")

	k8sClient := newSrvFakeClient(t, network).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	mockIdentity.EXPECT().
		GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), srvOrganizationID, "nonexistent-project").
		Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
		}, nil)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate(srvOrganizationID))

	_, err := c.CreateV2(ctx, minimalServerV2CreateRequest(srvNetworkID))

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

// TestServerCreateV2RBACNoCreatePermission verifies that CreateV2 returns
// forbidden when the caller has network:read permission but no server:create
// permission.
func TestServerCreateV2RBACNoCreatePermission(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvOrganizationID, srvProjectID)

	k8sClient := newSrvFakeClient(t, network).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	// No EXPECT calls — the identity API must not be contacted.

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithSrvNetworkReadOnly(srvOrganizationID))

	_, err := c.CreateV2(ctx, minimalServerV2CreateRequest(srvNetworkID))

	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err), "expected forbidden, got: %v", err)
}
