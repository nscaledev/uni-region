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

package securitygroup_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	identitymock "github.com/unikorn-cloud/identity/pkg/openapi/mock"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/securitygroup"
	"github.com/unikorn-cloud/region/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	sgOrganizationID     = "11111111-1111-4111-a111-111111111111"
	sgProjectID          = "22222222-2222-4222-a222-222222222222"
	sgNonexistentProject = "33333333-3333-4333-a333-333333333333"
	sgNamespace          = "test-namespace"
	sgNetworkID          = "test-network"
)

// newSGFakeClient builds a fake k8s client pre-populated with the given objects.
func newSGFakeClient(t *testing.T, objects ...runtime.Object) *fake.ClientBuilder {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, regionv1.AddToScheme(scheme))

	builder := fake.NewClientBuilder().WithScheme(scheme)

	for _, o := range objects {
		builder = builder.WithRuntimeObjects(o)
	}

	return builder
}

// testNetworkWithProject returns a v2 Network object with the given org/project labels.
func testNetworkWithProject(orgID, projID string) *regionv1.Network {
	return &regionv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sgNetworkID,
			Namespace: sgNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   orgID,
				coreconstants.ProjectLabel:        projID,
				constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
			},
		},
	}
}

// aclWithOrgScopeSGCreate grants network:read and securitygroup:create at
// organization scope so GetV2Raw passes and AllowProjectScopeCreate is reached.
func aclWithOrgScopeSGCreate(orgID string) *identityapi.Acl {
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
						Name:       "region:securitygroups:v2",
						Operations: identityapi.AclOperations{identityapi.Create},
					},
				},
			},
		},
	}
}

// aclWithNetworkReadOnly grants network:read at organization scope but no
// securitygroup:create, so the securitygroup RBAC check returns forbidden.
func aclWithNetworkReadOnly(orgID string) *identityapi.Acl {
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

func minimalSGCreateRequest(networkID string) *openapi.SecurityGroupV2Create {
	return &openapi.SecurityGroupV2Create{
		Metadata: coreapi.ResourceWriteMetadata{Name: "test-sg"},
		Spec: openapi.SecurityGroupV2CreateSpec{
			NetworkId: networkID,
			Rules:     openapi.SecurityGroupRuleV2List{},
		},
	}
}

// TestSGCreateV2RBACOrgScopedProjectNotFound verifies that CreateV2 returns a
// 404 Not Found when the caller has org-scoped ACL but the project from the
// network labels does not exist in the identity service.
func TestSGCreateV2RBACOrgScopedProjectNotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testNetworkWithProject(sgOrganizationID, sgNonexistentProject)

	k8sClient := newSGFakeClient(t, network).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	mockIdentity.EXPECT().
		GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), identityids.MustParseOrganizationID(sgOrganizationID), identityids.MustParseProjectID(sgNonexistentProject)).
		Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
		}, nil)

	c := securitygroup.New(common.ClientArgs{
		Client:    k8sClient,
		Namespace: sgNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithOrgScopeSGCreate(sgOrganizationID))

	_, err := c.CreateV2(ctx, minimalSGCreateRequest(sgNetworkID))

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

// TestSGCreateV2RBACNoCreatePermission verifies that CreateV2 returns forbidden
// when the caller has network:read permission but no securitygroup:create permission.
func TestSGCreateV2RBACNoCreatePermission(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testNetworkWithProject(sgOrganizationID, sgProjectID)

	k8sClient := newSGFakeClient(t, network).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	// No EXPECT calls — the identity API must not be contacted.

	c := securitygroup.New(common.ClientArgs{
		Client:    k8sClient,
		Namespace: sgNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithNetworkReadOnly(sgOrganizationID))

	_, err := c.CreateV2(ctx, minimalSGCreateRequest(sgNetworkID))

	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err), "expected forbidden, got: %v", err)
}

// sgProjectACL grants region:networks:v2 read (so network lookups succeed) plus the
// given region:securitygroups:v2 operations, all at project scope. ListV2/GetV2Raw
// use AllowProjectScope, so a project-scoped grant is what authorizes them.
func sgProjectACL(securityGroupOps ...identityapi.AclOperation) *identityapi.Acl {
	endpoints := identityapi.AclEndpoints{
		{Name: "region:networks:v2", Operations: identityapi.AclOperations{identityapi.Read}},
	}

	if len(securityGroupOps) != 0 {
		endpoints = append(endpoints, identityapi.AclEndpoint{
			Name:       "region:securitygroups:v2",
			Operations: securityGroupOps,
		})
	}

	return &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{
			{
				Id: sgOrganizationID,
				Projects: &identityapi.AclProjectList{
					{Id: sgProjectID, Endpoints: endpoints},
				},
			},
		},
	}
}

// withSGPrincipal attaches the authorization and principal information that the
// generate path (InjectUserPrincipal, SetIdentityMetadata) requires on a write.
func withSGPrincipal(ctx context.Context) context.Context {
	ctx = authorization.NewContext(ctx, &authorization.Info{
		Userinfo: &identityapi.Userinfo{Sub: "token-actor"},
	})

	return principal.NewContext(ctx, &principal.Principal{Actor: "test@example.com"})
}

// testSecurityGroupV2 returns a v2 SecurityGroup owned by the test org/project and
// labelled so GetV2Raw's API-version guard passes.
func testSecurityGroupV2(name string) *regionv1.SecurityGroup {
	return &regionv1.SecurityGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: sgNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   sgOrganizationID,
				coreconstants.ProjectLabel:        sgProjectID,
				coreconstants.NameLabel:           name,
				constants.RegionLabel:             "test-region",
				constants.NetworkLabel:            sgNetworkID,
				constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
			},
		},
	}
}

func newSGClient(t *testing.T, objects ...runtime.Object) *securitygroup.Client {
	t.Helper()

	return securitygroup.New(common.ClientArgs{
		Client:    newSGFakeClient(t, objects...).Build(),
		Namespace: sgNamespace,
	})
}

// TestSGGetV2 verifies GetV2 returns a security group's converted view, including the
// region and network identifiers carried on its labels.
func TestSGGetV2(t *testing.T) {
	t.Parallel()

	resource := testSecurityGroupV2("sg-1")

	c := newSGClient(t, resource)

	ctx := rbac.NewContext(t.Context(), sgProjectACL(identityapi.Read))

	result, err := c.GetV2(ctx, "sg-1")

	require.NoError(t, err)
	require.Equal(t, "sg-1", result.Metadata.Id)
	require.Equal(t, "test-region", result.Status.RegionId)
	require.Equal(t, sgNetworkID, result.Status.NetworkId)
}

// TestSGGetV2RawNotFound verifies a missing security group returns 404.
func TestSGGetV2RawNotFound(t *testing.T) {
	t.Parallel()

	c := newSGClient(t)

	ctx := rbac.NewContext(t.Context(), sgProjectACL(identityapi.Read))

	_, err := c.GetV2Raw(ctx, "does-not-exist")

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

// TestSGGetV2RawNoReadPermission verifies a caller without securitygroup read access
// is refused even when the resource exists.
func TestSGGetV2RawNoReadPermission(t *testing.T) {
	t.Parallel()

	resource := testSecurityGroupV2("sg-1")

	c := newSGClient(t, resource)

	// network read only, no securitygroup read.
	ctx := rbac.NewContext(t.Context(), sgProjectACL())

	_, err := c.GetV2Raw(ctx, "sg-1")

	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err), "expected forbidden, got: %v", err)
}

// TestSGGetV2RawMissingAPIVersion verifies a resource without the API-version label is
// hidden behind a 404 rather than being returned by the v2 client.
func TestSGGetV2RawMissingAPIVersion(t *testing.T) {
	t.Parallel()

	resource := testSecurityGroupV2("sg-1")
	delete(resource.Labels, constants.ResourceAPIVersionLabel)

	c := newSGClient(t, resource)

	ctx := rbac.NewContext(t.Context(), sgProjectACL(identityapi.Read))

	_, err := c.GetV2Raw(ctx, "sg-1")

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

// TestSGGetV2RawWrongAPIVersion verifies a v1 resource is not reachable through the v2
// client.
func TestSGGetV2RawWrongAPIVersion(t *testing.T) {
	t.Parallel()

	resource := testSecurityGroupV2("sg-1")
	resource.Labels[constants.ResourceAPIVersionLabel] = constants.MarshalAPIVersion(1)

	c := newSGClient(t, resource)

	ctx := rbac.NewContext(t.Context(), sgProjectACL(identityapi.Read))

	_, err := c.GetV2Raw(ctx, "sg-1")

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

// TestSGListV2 verifies ListV2 returns the project's security groups, name-sorted.
func TestSGListV2(t *testing.T) {
	t.Parallel()

	c := newSGClient(t, testSecurityGroupV2("sg-b"), testSecurityGroupV2("sg-a"))

	ctx := rbac.NewContext(t.Context(), sgProjectACL(identityapi.Read))

	result, err := c.ListV2(ctx, openapi.GetApiV2SecuritygroupsParams{})

	require.NoError(t, err)
	require.Len(t, result, 2)
	require.Equal(t, "sg-a", result[0].Metadata.Id)
	require.Equal(t, "sg-b", result[1].Metadata.Id)
}

// TestSGListV2ExcludesUnauthorizedProject verifies a security group in a project the
// caller cannot see is omitted from the listing.
func TestSGListV2ExcludesUnauthorizedProject(t *testing.T) {
	t.Parallel()

	visible := testSecurityGroupV2("sg-visible")

	hidden := testSecurityGroupV2("sg-hidden")
	hidden.Labels[coreconstants.ProjectLabel] = "other-project"

	c := newSGClient(t, visible, hidden)

	ctx := rbac.NewContext(t.Context(), sgProjectACL(identityapi.Read))

	result, err := c.ListV2(ctx, openapi.GetApiV2SecuritygroupsParams{})

	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, "sg-visible", result[0].Metadata.Id)
}

// TestSGListV2Empty verifies ListV2 returns nothing when the project has no security
// groups.
func TestSGListV2Empty(t *testing.T) {
	t.Parallel()

	c := newSGClient(t)

	ctx := rbac.NewContext(t.Context(), sgProjectACL(identityapi.Read))

	result, err := c.ListV2(ctx, openapi.GetApiV2SecuritygroupsParams{})

	require.NoError(t, err)
	require.Empty(t, result)
}

// TestSGDeleteV2 verifies a delete removes the resource and a subsequent read fails.
func TestSGDeleteV2(t *testing.T) {
	t.Parallel()

	resource := testSecurityGroupV2("sg-1")

	c := newSGClient(t, resource)

	ctx := rbac.NewContext(t.Context(), sgProjectACL(identityapi.Read, identityapi.Delete))

	require.NoError(t, c.DeleteV2(ctx, "sg-1"))

	_, err := c.GetV2Raw(ctx, "sg-1")
	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found after delete, got: %v", err)
}

// TestSGDeleteV2NotFound verifies deleting a missing security group returns 404.
func TestSGDeleteV2NotFound(t *testing.T) {
	t.Parallel()

	c := newSGClient(t)

	ctx := rbac.NewContext(t.Context(), sgProjectACL(identityapi.Read, identityapi.Delete))

	err := c.DeleteV2(ctx, "does-not-exist")

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

// TestSGDeleteV2NoDeletePermission verifies a read-only caller cannot delete.
func TestSGDeleteV2NoDeletePermission(t *testing.T) {
	t.Parallel()

	resource := testSecurityGroupV2("sg-1")

	c := newSGClient(t, resource)

	ctx := rbac.NewContext(t.Context(), sgProjectACL(identityapi.Read))

	err := c.DeleteV2(ctx, "sg-1")

	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err), "expected forbidden, got: %v", err)
}

// TestSGDeleteV2InUse verifies a security group still referenced by another resource
// (an extra finalizer) cannot be deleted and reports a forbidden error.
func TestSGDeleteV2InUse(t *testing.T) {
	t.Parallel()

	resource := testSecurityGroupV2("sg-1")
	resource.Finalizers = []string{"servers.region.unikorn-cloud.org/ref-1"}

	c := newSGClient(t, resource)

	ctx := rbac.NewContext(t.Context(), sgProjectACL(identityapi.Read, identityapi.Delete))

	err := c.DeleteV2(ctx, "sg-1")

	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err), "expected forbidden (in use), got: %v", err)
}

// TestSGDeleteV2AlreadyDeleting verifies deleting a resource that is already being
// deleted is a no-op rather than an error.
func TestSGDeleteV2AlreadyDeleting(t *testing.T) {
	t.Parallel()

	resource := testSecurityGroupV2("sg-1")
	now := metav1.NewTime(time.Now())
	resource.DeletionTimestamp = &now
	resource.Finalizers = []string{"securitygroups.region.unikorn-cloud.org/test"}

	c := newSGClient(t, resource)

	ctx := rbac.NewContext(t.Context(), sgProjectACL(identityapi.Read, identityapi.Delete))

	require.NoError(t, c.DeleteV2(ctx, "sg-1"))
}

// TestSGUpdateV2 verifies a successful update applies the requested rules and returns
// the converted resource.
//
// NOTE: UpdateV2 currently authorizes against the Delete operation (see client_v2.go),
// so a superset grant (Read+Update+Delete) is used here to stay correct regardless of
// whether that permission check is later corrected to Update.
func TestSGUpdateV2(t *testing.T) {
	t.Parallel()

	network := testNetworkWithProject(sgOrganizationID, sgProjectID)
	resource := testSecurityGroupV2("sg-1")

	c := newSGClient(t, network, resource)

	ctx := withSGPrincipal(rbac.NewContext(t.Context(),
		sgProjectACL(identityapi.Read, identityapi.Update, identityapi.Delete)))

	request := &openapi.SecurityGroupV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: "sg-1"},
		Spec: openapi.SecurityGroupV2Spec{
			Rules: openapi.SecurityGroupRuleV2List{
				{
					Direction: openapi.NetworkDirectionIngress,
					Protocol:  openapi.NetworkProtocolAny,
				},
			},
		},
	}

	result, err := c.UpdateV2(ctx, "sg-1", request)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Spec.Rules, 1)
	require.Equal(t, openapi.NetworkDirectionIngress, result.Spec.Rules[0].Direction)
	require.Equal(t, sgNetworkID, result.Status.NetworkId)
}

// TestSGUpdateV2NotFound verifies updating a missing security group returns 404.
func TestSGUpdateV2NotFound(t *testing.T) {
	t.Parallel()

	c := newSGClient(t)

	ctx := rbac.NewContext(t.Context(),
		sgProjectACL(identityapi.Read, identityapi.Update, identityapi.Delete))

	request := &openapi.SecurityGroupV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: "does-not-exist"},
		Spec:     openapi.SecurityGroupV2Spec{Rules: openapi.SecurityGroupRuleV2List{}},
	}

	_, err := c.UpdateV2(ctx, "does-not-exist", request)

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

// TestSGUpdateV2NoPermission verifies a read-only caller cannot update.
func TestSGUpdateV2NoPermission(t *testing.T) {
	t.Parallel()

	resource := testSecurityGroupV2("sg-1")

	c := newSGClient(t, resource)

	ctx := rbac.NewContext(t.Context(), sgProjectACL(identityapi.Read))

	request := &openapi.SecurityGroupV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: "sg-1"},
		Spec:     openapi.SecurityGroupV2Spec{Rules: openapi.SecurityGroupRuleV2List{}},
	}

	_, err := c.UpdateV2(ctx, "sg-1", request)

	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err), "expected forbidden, got: %v", err)
}

// TestSGUpdateV2BeingDeleted verifies updating a resource already marked for deletion
// is rejected as a bad request.
func TestSGUpdateV2BeingDeleted(t *testing.T) {
	t.Parallel()

	resource := testSecurityGroupV2("sg-1")
	now := metav1.NewTime(time.Now())
	resource.DeletionTimestamp = &now
	resource.Finalizers = []string{"securitygroups.region.unikorn-cloud.org/test"}

	c := newSGClient(t, resource)

	ctx := rbac.NewContext(t.Context(),
		sgProjectACL(identityapi.Read, identityapi.Update, identityapi.Delete))

	request := &openapi.SecurityGroupV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: "sg-1"},
		Spec:     openapi.SecurityGroupV2Spec{Rules: openapi.SecurityGroupRuleV2List{}},
	}

	_, err := c.UpdateV2(ctx, "sg-1", request)

	require.Error(t, err)
	require.True(t, coreerrors.IsBadRequest(err), "expected bad request (being deleted), got: %v", err)
}
