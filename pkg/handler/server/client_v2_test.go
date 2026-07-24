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
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	corev1alpha1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
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
	"github.com/unikorn-cloud/region/pkg/handler/server"
	idstest "github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/openapi"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	srvOrganizationID     = "11111111-1111-4111-a111-111111111111"
	srvProjectID          = "22222222-2222-4222-a222-222222222222"
	srvNonexistentProject = "33333333-3333-4333-a333-333333333333"
	srvNamespace          = "test-namespace"
	srvNetworkID          = "aaaabbbb-1234-5678-9abc-def012345678"
	srvFlavorID           = "44444444-4444-4444-a444-444444444444"
	srvImageID            = "55555555-5555-4555-a555-555555555555"
	srvServerID           = "66666666-6666-4666-a666-666666666666"
	srvNonexistentID      = "77777777-7777-4777-a777-777777777777"
	srvRegionID           = "88888888-8888-4888-a888-888888888888"
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

// testSrvNetworkWithProject returns a v2 Network object with the given project label.
func testSrvNetworkWithProject(projID string) *regionv1.Network {
	return &regionv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      srvNetworkID,
			Namespace: srvNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   srvOrganizationID,
				coreconstants.ProjectLabel:        projID,
				constants.RegionLabel:             srvRegionID,
				constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
			},
		},
	}
}

// aclWithOrgScopeServerCreate grants network:read, securitygroups:read,
// sshcertificateauthorities:read and region:servers/Create at organization scope so
// the referenced-resource GetV2Raw calls pass and AllowProjectScopeCreate is reached.
func aclWithOrgScopeServerCreate() *identityapi.Acl {
	return &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{
			{
				Id: srvOrganizationID,
				Endpoints: &identityapi.AclEndpoints{
					{
						Name:       "region:networks:v2",
						Operations: identityapi.AclOperations{identityapi.Read},
					},
					{
						Name:       "region:servers",
						Operations: identityapi.AclOperations{identityapi.Create},
					},
					{
						Name:       "region:securitygroups:v2",
						Operations: identityapi.AclOperations{identityapi.Read},
					},
					{
						Name:       "region:sshcertificateauthorities:v2",
						Operations: identityapi.AclOperations{identityapi.Read},
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

func aclWithSrvUpdate() *identityapi.Acl {
	return &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{
			{
				Id: srvOrganizationID,
				Endpoints: &identityapi.AclEndpoints{
					{
						Name:       "region:networks:v2",
						Operations: identityapi.AclOperations{identityapi.Read},
					},
					{
						Name:       "region:servers",
						Operations: identityapi.AclOperations{identityapi.Read, identityapi.Update},
					},
				},
			},
		},
	}
}

func expectProjectFound(mockIdentity *identitymock.MockClientWithResponsesInterface) *gomock.Call {
	return mockIdentity.EXPECT().
		GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), identityids.MustParseOrganizationID(srvOrganizationID), identityids.MustParseProjectID(srvProjectID)).
		Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
		}, nil)
}

// newMockProvidersWithReadyImage builds a Providers mock whose provider
// resolves the fixture image as Ready and compatible with the fixture flavor,
// so create requests pass the boundary image validation.
func newMockProvidersWithReadyImage(ctrl *gomock.Controller) *mockproviders.MockProviders {
	mockProvider := mocktypes.NewMockProvider(ctrl)
	mockProvider.EXPECT().GetImage(gomock.Any(), gomock.Any(), idstest.MustParseImageID(srvImageID)).
		Return(&types.Image{ID: srvImageID, Status: types.ImageStatusReady, Virtualization: types.Any}, nil).AnyTimes()
	mockProvider.EXPECT().Flavors(gomock.Any()).Return(types.FlavorList{{ID: srvFlavorID}}, nil).AnyTimes()

	mockProviders := mockproviders.NewMockProviders(ctrl)
	mockProviders.EXPECT().LookupCloud(gomock.Any()).Return(mockProvider, nil).AnyTimes()

	return mockProviders
}

func minimalServerV2CreateRequest() *openapi.ServerV2Create {
	return &openapi.ServerV2Create{
		Metadata: coreapi.ResourceWriteMetadata{Name: "test-server"},
		Spec: openapi.ServerV2CreateSpec{
			NetworkId: idstest.MustParseNetworkID(srvNetworkID),
			FlavorId:  idstest.MustParseFlavorID(srvFlavorID),
			ImageId:   idstest.MustParseImageID(srvImageID),
		},
	}
}

func withPrincipal(ctx context.Context) context.Context {
	ctx = authorization.NewContext(ctx, &authorization.Info{
		Userinfo: &identityapi.Userinfo{
			Sub: "token-actor",
		},
	})

	return principal.NewContext(ctx, &principal.Principal{
		Actor: "test@example.com",
	})
}

func testSSHCertificateAuthorityWithProject(projID string) *regionv1.SSHCertificateAuthority {
	return &regionv1.SSHCertificateAuthority{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-1",
			Namespace: srvNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   srvOrganizationID,
				coreconstants.ProjectLabel:        projID,
				constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
			},
		},
		Spec: regionv1.SSHCertificateAuthoritySpec{
			PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBuildOnlyTrustAnchor comment",
		},
	}
}

func testServerWithSSHCertificateAuthority() *regionv1.Server {
	const (
		serverID = srvServerID
		caID     = "ca-1"
	)

	return &regionv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serverID,
			Namespace: srvNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   srvOrganizationID,
				coreconstants.ProjectLabel:        srvProjectID,
				coreconstants.NameLabel:           serverID,
				constants.RegionLabel:             srvRegionID,
				constants.IdentityLabel:           "test-identity",
				constants.NetworkLabel:            srvNetworkID,
				constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
			},
		},
		Spec: regionv1.ServerSpec{
			FlavorID: idstest.MustParseFlavorID(srvFlavorID),
			Image: &regionv1.ServerImage{
				ID: idstest.MustParseImageID(srvImageID),
			},
			Networks: []regionv1.ServerNetworkSpec{{
				ID: idstest.MustParseNetworkID(srvNetworkID),
			}},
			SSHCertificateAuthorityID: ptr.To(caID),
		},
	}
}

func testSecurityGroupInNetwork(networkID, securityGroupID string) *regionv1.SecurityGroup {
	return &regionv1.SecurityGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      securityGroupID,
			Namespace: srvNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   srvOrganizationID,
				coreconstants.ProjectLabel:        srvProjectID,
				constants.NetworkLabel:            networkID,
				constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
			},
		},
	}
}

// TestServerCreateV2RBACOrgScopedProjectNotFound verifies that CreateV2 returns
// a 404 Not Found when the caller has org-scoped ACL but the project from the
// network labels does not exist in the identity service.
func TestServerCreateV2RBACOrgScopedProjectNotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvNonexistentProject)

	k8sClient := newSrvFakeClient(t, network).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	mockIdentity.EXPECT().
		GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), identityids.MustParseOrganizationID(srvOrganizationID), identityids.MustParseProjectID(srvNonexistentProject)).
		Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
		}, nil)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate())

	_, err := c.CreateV2(ctx, minimalServerV2CreateRequest())

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

// TestServerCreateV2RBACNoCreatePermission verifies that CreateV2 returns
// forbidden when the caller has network:read permission but no server:create
// permission.
func TestServerCreateV2RBACNoCreatePermission(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)

	k8sClient := newSrvFakeClient(t, network).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	// No EXPECT calls — the identity API must not be contacted.

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithSrvNetworkReadOnly(srvOrganizationID))

	_, err := c.CreateV2(ctx, minimalServerV2CreateRequest())

	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err), "expected forbidden, got: %v", err)
}

func TestServerCreateV2SSHCertificateAuthorityNotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)

	k8sClient := newSrvFakeClient(t, network).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectProjectFound(mockIdentity)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate())

	request := minimalServerV2CreateRequest()
	request.Spec.SshCertificateAuthorityId = ptr.To("missing-ca")

	_, err := c.CreateV2(ctx, request)

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

func TestServerCreateV2SSHCertificateAuthorityRejectsCrossProjectReference(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)
	ca := testSSHCertificateAuthorityWithProject("99999999-9999-4999-a999-999999999999")

	k8sClient := newSrvFakeClient(t, network, ca).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectProjectFound(mockIdentity)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate())

	request := minimalServerV2CreateRequest()
	request.Spec.SshCertificateAuthorityId = ptr.To(ca.Name)

	_, err := c.CreateV2(ctx, request)

	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
}

func TestServerCreateV2SecurityGroupNotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)

	k8sClient := newSrvFakeClient(t, network).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectProjectFound(mockIdentity)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate())

	request := minimalServerV2CreateRequest()
	request.Spec.Networking = &openapi.ServerV2Networking{
		SecurityGroups: &openapi.ServerV2SecurityGroupIDList{idstest.MustParseSecurityGroupID("88888888-8888-4888-a888-888888888888")},
	}

	_, err := c.CreateV2(ctx, request)

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

func TestServerCreateV2SecurityGroupRejectsDifferentNetwork(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)
	// A security group in the same organization and project as the server, but in a
	// different network — and therefore a different identity / OpenStack project.
	securityGroup := testSecurityGroupInNetwork("99999999-9999-4999-a999-999999999999", "77777777-7777-4777-a777-777777777777")

	k8sClient := newSrvFakeClient(t, network, securityGroup).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectProjectFound(mockIdentity)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate())

	request := minimalServerV2CreateRequest()
	request.Spec.Networking = &openapi.ServerV2Networking{
		SecurityGroups: &openapi.ServerV2SecurityGroupIDList{idstest.MustParseSecurityGroupID(securityGroup.Name)},
	}

	_, err := c.CreateV2(ctx, request)

	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
}

func TestServerCreateV2SecurityGroupAcceptsSameNetwork(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)
	securityGroup := testSecurityGroupInNetwork(srvNetworkID, "77777777-7777-4777-a777-777777777777")

	k8sClient := newSrvFakeClient(t, network, securityGroup).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectProjectFound(mockIdentity)

	mockProviders := newMockProvidersWithReadyImage(ctrl)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
		Providers: mockProviders,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	request := minimalServerV2CreateRequest()
	request.Spec.Networking = &openapi.ServerV2Networking{
		SecurityGroups: &openapi.ServerV2SecurityGroupIDList{idstest.MustParseSecurityGroupID(securityGroup.Name)},
	}

	result, err := c.CreateV2(ctx, request)

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestServerCreateV2SSHCertificateAuthorityRejectsUnsupportedUserData(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)
	ca := testSSHCertificateAuthorityWithProject(srvProjectID)

	k8sClient := newSrvFakeClient(t, network, ca).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectProjectFound(mockIdentity)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	request := minimalServerV2CreateRequest()
	request.Spec.SshCertificateAuthorityId = ptr.To(ca.Name)
	request.Spec.UserData = ptr.To([]byte("echo hello"))

	_, err := c.CreateV2(ctx, request)

	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
}

func TestServerCreateV2SSHCertificateAuthorityAcceptsSupportedUserData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		userData []byte
	}{
		{
			name:     "CloudConfig",
			userData: []byte("#cloud-config\nusers: []\n"),
		},
		{
			name:     "Multipart",
			userData: []byte("Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\nMIME-Version: 1.0\r\n\r\n--BOUNDARY\r\nContent-Type: text/x-shellscript\r\n\r\n#!/bin/sh\necho hello\r\n--BOUNDARY--\r\n"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			network := testSrvNetworkWithProject(srvProjectID)
			ca := testSSHCertificateAuthorityWithProject(srvProjectID)

			k8sClient := newSrvFakeClient(t, network, ca).Build()

			mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
			expectProjectFound(mockIdentity)

			mockProviders := newMockProvidersWithReadyImage(ctrl)

			c := server.NewClientV2(common.ClientArgs{
				Client:    k8sClient,
				Namespace: srvNamespace,
				Identity:  mockIdentity,
				Providers: mockProviders,
			})

			ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

			request := minimalServerV2CreateRequest()
			request.Spec.SshCertificateAuthorityId = ptr.To(ca.Name)
			request.Spec.UserData = ptr.To(test.userData)

			result, err := c.CreateV2(ctx, request)

			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, ca.Name, *result.Status.SshCertificateAuthorityId)
		})
	}
}

func TestServerCreateV2RejectsMalformedUserDataWithoutSSHCertificateAuthority(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)

	k8sClient := newSrvFakeClient(t, network).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectProjectFound(mockIdentity)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	request := minimalServerV2CreateRequest()
	request.Spec.UserData = ptr.To([]byte("echo hello"))

	_, err := c.CreateV2(ctx, request)

	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
	require.ErrorContains(t, err, "unsupported userData format")
}

func TestServerCreateV2AcceptsUserDataWithoutSSHCertificateAuthority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		userData []byte
	}{
		{
			name:     "CloudConfig",
			userData: []byte("#cloud-config\nusers: []\n"),
		},
		{
			name:     "ShellScript",
			userData: []byte("#!/bin/sh\necho hello\n"),
		},
		{
			name:     "Multipart",
			userData: []byte("Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\nMIME-Version: 1.0\r\n\r\n--BOUNDARY\r\nContent-Type: text/x-shellscript\r\n\r\n#!/bin/sh\necho hello\r\n--BOUNDARY--\r\n"),
		},
		{
			// Gzip user-data is passed to the platform unmodified when no managed
			// augmentation occurs, so it must not be rejected at the boundary.
			name:     "Gzip",
			userData: []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			network := testSrvNetworkWithProject(srvProjectID)

			k8sClient := newSrvFakeClient(t, network).Build()

			mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
			expectProjectFound(mockIdentity)

			mockProviders := newMockProvidersWithReadyImage(ctrl)

			c := server.NewClientV2(common.ClientArgs{
				Client:    k8sClient,
				Namespace: srvNamespace,
				Identity:  mockIdentity,
				Providers: mockProviders,
			})

			ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

			request := minimalServerV2CreateRequest()
			request.Spec.UserData = ptr.To(test.userData)

			result, err := c.CreateV2(ctx, request)

			require.NoError(t, err)
			require.NotNil(t, result)

			resource := &regionv1.Server{}
			require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKey{Namespace: srvNamespace, Name: result.Metadata.Id}, resource))
			require.Equal(t, test.userData, resource.Spec.UserData)
		})
	}
}

func TestServerCreateV2SSHCertificateAuthorityRejectsGzipUserData(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)
	ca := testSSHCertificateAuthorityWithProject(srvProjectID)

	k8sClient := newSrvFakeClient(t, network, ca).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectProjectFound(mockIdentity)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	request := minimalServerV2CreateRequest()
	request.Spec.SshCertificateAuthorityId = ptr.To(ca.Name)
	request.Spec.UserData = ptr.To([]byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00})

	_, err := c.CreateV2(ctx, request)

	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
	require.ErrorContains(t, err, "gzip")
}

func TestServerCreateV2RejectsInvalidAllowedSourceAddress(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)

	k8sClient := newSrvFakeClient(t, network).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectProjectFound(mockIdentity)

	mockProviders := newMockProvidersWithReadyImage(ctrl)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
		Providers: mockProviders,
	})

	ctx := rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate())

	request := minimalServerV2CreateRequest()
	request.Spec.Networking = &openapi.ServerV2Networking{
		AllowedSourceAddresses: &openapi.AllowedSourceAddresses{"definitely-not-a-cidr"},
	}

	_, err := c.CreateV2(ctx, request)

	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
}

func TestServerCreateV2SetsInfrastructureRef(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)

	k8sClient := newSrvFakeClient(t, network).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	mockIdentity.EXPECT().
		GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), identityids.MustParseOrganizationID(srvOrganizationID), identityids.MustParseProjectID(srvProjectID)).
		Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
		}, nil)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
		Providers: newMockProvidersWithReadyImage(ctrl),
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	infrastructureRef := "node-uuid-123"
	request := minimalServerV2CreateRequest()
	request.Spec.InfrastructureRef = &infrastructureRef
	request.Spec.SshInjection = ptr.To(openapi.SshInjection("none"))

	result, err := c.CreateV2(ctx, request)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Status.InfrastructureRef)
	require.Equal(t, infrastructureRef, *result.Status.InfrastructureRef)
	require.NotNil(t, result.Status.SshInjection)
	require.Equal(t, openapi.SshInjection("none"), *result.Status.SshInjection)

	created := &regionv1.Server{}
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKey{Namespace: srvNamespace, Name: result.Metadata.Id}, created))
	require.NotNil(t, created.Spec.InfrastructureRef)
	require.Equal(t, infrastructureRef, *created.Spec.InfrastructureRef)
	require.NotNil(t, created.Spec.SSHInjection)
	require.Equal(t, regionv1.ServerSSHInjectionNone, *created.Spec.SSHInjection)
}

func TestServerCreateV2RejectsInfrastructureRefWithIdentitySSHKey(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)

	k8sClient := newSrvFakeClient(t, network).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectProjectFound(mockIdentity)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	infrastructureRef := "node-uuid-123"
	request := minimalServerV2CreateRequest()
	request.Spec.InfrastructureRef = &infrastructureRef

	_, err := c.CreateV2(ctx, request)

	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
}

func TestServerCreateV2AllowsInfrastructureRefWithSSHCertificateAuthority(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)
	ca := testSSHCertificateAuthorityWithProject(srvProjectID)

	k8sClient := newSrvFakeClient(t, network, ca).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectProjectFound(mockIdentity)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
		Providers: newMockProvidersWithReadyImage(ctrl),
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	infrastructureRef := "node-uuid-123"
	request := minimalServerV2CreateRequest()
	request.Spec.InfrastructureRef = &infrastructureRef
	request.Spec.SshCertificateAuthorityId = ptr.To(ca.Name)

	result, err := c.CreateV2(ctx, request)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, ca.Name, *result.Status.SshCertificateAuthorityId)
	require.NotNil(t, result.Status.SshInjection)
	require.Equal(t, openapi.SshInjection("ca"), *result.Status.SshInjection)
	require.Equal(t, infrastructureRef, *result.Status.InfrastructureRef)
}

func TestServerCreateV2RejectsIncompatibleSSHInjection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		sshInjection openapi.SshInjection
		caID         *string
	}{
		{
			name:         "CAWithoutReference",
			sshInjection: openapi.SshInjection("ca"),
		},
		{
			name:         "IdentityKeypairWithCA",
			sshInjection: openapi.SshInjection("identityKeypair"),
			caID:         ptr.To("ca-1"),
		},
		{
			name:         "NoneWithCA",
			sshInjection: openapi.SshInjection("none"),
			caID:         ptr.To("ca-1"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			network := testSrvNetworkWithProject(srvProjectID)

			k8sClient := newSrvFakeClient(t, network).Build()

			mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
			expectProjectFound(mockIdentity)

			c := server.NewClientV2(common.ClientArgs{
				Client:    k8sClient,
				Namespace: srvNamespace,
				Identity:  mockIdentity,
			})

			ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

			request := minimalServerV2CreateRequest()
			request.Spec.SshInjection = ptr.To(test.sshInjection)
			request.Spec.SshCertificateAuthorityId = test.caID

			_, err := c.CreateV2(ctx, request)

			require.Error(t, err)
			require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
		})
	}
}

func TestServerUpdateV2PreservesSSHCertificateAuthority(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)
	resource := testServerWithSSHCertificateAuthority()
	resource.Spec.SSHInjection = ptr.To(regionv1.ServerSSHInjectionCA)

	k8sClient := newSrvFakeClient(t, network, resource).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithSrvUpdate()))

	request := &openapi.ServerV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: resource.Name},
		Spec: openapi.ServerV2Spec{
			FlavorId: resource.Spec.FlavorID,
			ImageId:  resource.Spec.Image.ID,
			UserData: ptr.To([]byte("#cloud-config\nusers: []\n")),
		},
	}

	result, err := c.UpdateV2(ctx, idstest.MustParseServerID(resource.Name), request)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, resource.Spec.SSHCertificateAuthorityID, result.Status.SshCertificateAuthorityId)
	require.NotNil(t, result.Status.SshInjection)
	require.Equal(t, openapi.SshInjection("ca"), *result.Status.SshInjection)

	updated, err := c.GetV2Raw(ctx, resource.Name)
	require.NoError(t, err)
	require.Equal(t, resource.Spec.SSHCertificateAuthorityID, updated.Spec.SSHCertificateAuthorityID)
	require.NotNil(t, updated.Spec.SSHInjection)
	require.Equal(t, regionv1.ServerSSHInjectionCA, *updated.Spec.SSHInjection)
}

func TestServerUpdateV2RejectsFlavorChange(t *testing.T) {
	t.Parallel()

	resource := testServerV2(srvServerID)
	c := server.NewClientV2(common.ClientArgs{
		Client:    newSrvFakeClient(t, resource).Build(),
		Namespace: srvNamespace,
	})
	ctx := rbac.NewContext(t.Context(), aclWithSrvUpdate())
	request := &openapi.ServerV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: resource.Name},
		Spec: openapi.ServerV2Spec{
			FlavorId: idstest.MustParseFlavorID("99999999-9999-4999-a999-999999999999"),
			ImageId:  resource.Spec.Image.ID,
		},
	}

	_, err := c.UpdateV2(ctx, idstest.MustParseServerID(resource.Name), request)
	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err))
}

func TestServerUpdateV2ValidatesChangedImage(t *testing.T) {
	t.Parallel()

	const newImageID = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"

	ctrl := gomock.NewController(t)
	resource := testServerV2(srvServerID)
	network := testSrvNetworkWithProject(srvProjectID)
	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().GetImage(gomock.Any(), identityids.MustParseOrganizationID(srvOrganizationID), idstest.MustParseImageID(newImageID)).
		Return(&types.Image{ID: newImageID, Status: types.ImageStatusReady, Virtualization: types.Any}, nil)
	provider.EXPECT().Flavors(gomock.Any()).Return(types.FlavorList{{ID: srvFlavorID}}, nil)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(srvRegionID).Return(provider, nil)
	c := server.NewClientV2(common.ClientArgs{
		Client:    newSrvFakeClient(t, network, resource).Build(),
		Namespace: srvNamespace,
		Providers: providers,
	})
	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithSrvUpdate()))
	request := &openapi.ServerV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: resource.Name},
		Spec: openapi.ServerV2Spec{
			FlavorId: resource.Spec.FlavorID,
			ImageId:  idstest.MustParseImageID(newImageID),
		},
	}

	result, err := c.UpdateV2(ctx, idstest.MustParseServerID(resource.Name), request)
	require.NoError(t, err)
	require.Equal(t, idstest.MustParseImageID(newImageID), result.Spec.ImageId)
}

// TestServerUpdateV2RejectsChangedMalformedUserData verifies that an update
// changing the persisted user-data to a malformed payload is rejected with
// HTTP 422 at the API boundary rather than failing at the next rebuild.
func TestServerUpdateV2RejectsChangedMalformedUserData(t *testing.T) {
	t.Parallel()

	resource := testServerV2(srvServerID)
	network := testSrvNetworkWithProject(srvProjectID)

	c := server.NewClientV2(common.ClientArgs{
		Client:    newSrvFakeClient(t, network, resource).Build(),
		Namespace: srvNamespace,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithSrvUpdate()))

	request := &openapi.ServerV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: resource.Name},
		Spec: openapi.ServerV2Spec{
			FlavorId: resource.Spec.FlavorID,
			ImageId:  resource.Spec.Image.ID,
			UserData: ptr.To([]byte("echo hello")),
		},
	}

	_, err := c.UpdateV2(ctx, idstest.MustParseServerID(resource.Name), request)

	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
}

// TestServerUpdateV2AcceptsUnchangedMalformedUserData verifies that PUTting
// back the identical stored user-data is accepted even when that payload
// predates validation and would no longer pass it, so legacy servers keep
// working with full-replace clients.
func TestServerUpdateV2AcceptsUnchangedMalformedUserData(t *testing.T) {
	t.Parallel()

	legacyUserData := []byte("echo hello")

	resource := testServerV2(srvServerID)
	resource.Spec.UserData = legacyUserData
	network := testSrvNetworkWithProject(srvProjectID)

	c := server.NewClientV2(common.ClientArgs{
		Client:    newSrvFakeClient(t, network, resource).Build(),
		Namespace: srvNamespace,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithSrvUpdate()))

	request := &openapi.ServerV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: resource.Name},
		Spec: openapi.ServerV2Spec{
			FlavorId: resource.Spec.FlavorID,
			ImageId:  resource.Spec.Image.ID,
			UserData: ptr.To(legacyUserData),
		},
	}

	result, err := c.UpdateV2(ctx, idstest.MustParseServerID(resource.Name), request)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, legacyUserData, *result.Spec.UserData)
}

// TestServerUpdateV2AcceptsChangedValidUserData verifies that an update
// changing the persisted user-data to a well-formed payload is accepted and
// the new value is persisted.
func TestServerUpdateV2AcceptsChangedValidUserData(t *testing.T) {
	t.Parallel()

	newUserData := []byte("#cloud-config\nusers: []\n")

	resource := testServerV2(srvServerID)
	network := testSrvNetworkWithProject(srvProjectID)

	c := server.NewClientV2(common.ClientArgs{
		Client:    newSrvFakeClient(t, network, resource).Build(),
		Namespace: srvNamespace,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithSrvUpdate()))

	request := &openapi.ServerV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: resource.Name},
		Spec: openapi.ServerV2Spec{
			FlavorId: resource.Spec.FlavorID,
			ImageId:  resource.Spec.Image.ID,
			UserData: ptr.To(newUserData),
		},
	}

	result, err := c.UpdateV2(ctx, idstest.MustParseServerID(resource.Name), request)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, newUserData, *result.Spec.UserData)

	updated, err := c.GetV2Raw(ctx, resource.Name)
	require.NoError(t, err)
	require.Equal(t, newUserData, updated.Spec.UserData)
}

// TestServerUpdateV2RejectsChangedGzipUserDataWithCA verifies that changed
// user-data on update is validated with the CA-awareness flag derived from the
// server's current SSH certificate authority: gzip payloads cannot receive
// managed cloud-init augmentation, so they are rejected with HTTP 422.
func TestServerUpdateV2RejectsChangedGzipUserDataWithCA(t *testing.T) {
	t.Parallel()

	resource := testServerWithSSHCertificateAuthority()
	network := testSrvNetworkWithProject(srvProjectID)

	c := server.NewClientV2(common.ClientArgs{
		Client:    newSrvFakeClient(t, network, resource).Build(),
		Namespace: srvNamespace,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithSrvUpdate()))

	request := &openapi.ServerV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: resource.Name},
		Spec: openapi.ServerV2Spec{
			FlavorId: resource.Spec.FlavorID,
			ImageId:  resource.Spec.Image.ID,
			UserData: ptr.To([]byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}),
		},
	}

	_, err := c.UpdateV2(ctx, idstest.MustParseServerID(resource.Name), request)

	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
	require.ErrorContains(t, err, "gzip")
}

// TestServerCreateV2RejectsNotReadyImage verifies that create enforces the same
// image contract as update: an image that is not Ready is rejected with HTTP 422.
func TestServerCreateV2RejectsNotReadyImage(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectProjectFound(mockIdentity)

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().GetImage(gomock.Any(), identityids.MustParseOrganizationID(srvOrganizationID), idstest.MustParseImageID(srvImageID)).
		Return(&types.Image{ID: srvImageID, Status: types.ImageStatusPending}, nil)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(srvRegionID).Return(provider, nil)

	c := server.NewClientV2(common.ClientArgs{
		Client:    newSrvFakeClient(t, network).Build(),
		Namespace: srvNamespace,
		Identity:  mockIdentity,
		Providers: providers,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	_, err := c.CreateV2(ctx, minimalServerV2CreateRequest())

	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
	require.ErrorContains(t, err, "image is not ready")
}

// TestServerCreateV2RejectsArchitectureIncompatibleImage verifies that create
// rejects an image whose CPU architecture does not match the flavor's with
// HTTP 422, symmetric with the update-path validation.
func TestServerCreateV2RejectsArchitectureIncompatibleImage(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectProjectFound(mockIdentity)

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().GetImage(gomock.Any(), identityids.MustParseOrganizationID(srvOrganizationID), idstest.MustParseImageID(srvImageID)).
		Return(&types.Image{ID: srvImageID, Status: types.ImageStatusReady, Architecture: types.Aarch64, Virtualization: types.Any}, nil)
	provider.EXPECT().Flavors(gomock.Any()).
		Return(types.FlavorList{{ID: srvFlavorID, Architecture: types.X86_64}}, nil).AnyTimes()

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(srvRegionID).Return(provider, nil).AnyTimes()

	c := server.NewClientV2(common.ClientArgs{
		Client:    newSrvFakeClient(t, network).Build(),
		Namespace: srvNamespace,
		Identity:  mockIdentity,
		Providers: providers,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	_, err := c.CreateV2(ctx, minimalServerV2CreateRequest())

	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
	require.ErrorContains(t, err, "architecture")
}

// TestServerCreateV2AcceptsValidImage verifies that create succeeds when the
// image is Ready and compatible with the requested flavor.
func TestServerCreateV2AcceptsValidImage(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectProjectFound(mockIdentity)

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().GetImage(gomock.Any(), identityids.MustParseOrganizationID(srvOrganizationID), idstest.MustParseImageID(srvImageID)).
		Return(&types.Image{ID: srvImageID, Status: types.ImageStatusReady, Virtualization: types.Any}, nil)
	provider.EXPECT().Flavors(gomock.Any()).
		Return(types.FlavorList{{ID: srvFlavorID}}, nil).AnyTimes()

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(srvRegionID).Return(provider, nil).AnyTimes()

	c := server.NewClientV2(common.ClientArgs{
		Client:    newSrvFakeClient(t, network).Build(),
		Namespace: srvNamespace,
		Identity:  mockIdentity,
		Providers: providers,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	result, err := c.CreateV2(ctx, minimalServerV2CreateRequest())

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, idstest.MustParseImageID(srvImageID), result.Spec.ImageId)
}

// TestServerCreateV2RejectsRetiredFlavor verifies that a create referencing a
// flavor the region no longer offers fails loudly and identifiably with HTTP
// 422, rather than an anonymous 404 that reads as "server not found".
func TestServerCreateV2RejectsRetiredFlavor(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectProjectFound(mockIdentity)

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().GetImage(gomock.Any(), identityids.MustParseOrganizationID(srvOrganizationID), idstest.MustParseImageID(srvImageID)).
		Return(&types.Image{ID: srvImageID, Status: types.ImageStatusReady, Virtualization: types.Any}, nil)
	provider.EXPECT().Flavors(gomock.Any()).Return(types.FlavorList{}, nil).AnyTimes()

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(srvRegionID).Return(provider, nil).AnyTimes()

	c := server.NewClientV2(common.ClientArgs{
		Client:    newSrvFakeClient(t, network).Build(),
		Namespace: srvNamespace,
		Identity:  mockIdentity,
		Providers: providers,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	_, err := c.CreateV2(ctx, minimalServerV2CreateRequest())

	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
	require.ErrorContains(t, err, "no longer offered")
}

// TestServerCreateV2RejectsUnrecognizedImageVirtualization verifies that an
// image reporting a virtualization type this build does not recognize fails
// closed with HTTP 422: an unrecognized value is positive evidence of version
// skew or bad provider metadata and must not pass as universally compatible.
func TestServerCreateV2RejectsUnrecognizedImageVirtualization(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectProjectFound(mockIdentity)

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().GetImage(gomock.Any(), identityids.MustParseOrganizationID(srvOrganizationID), idstest.MustParseImageID(srvImageID)).
		Return(&types.Image{ID: srvImageID, Status: types.ImageStatusReady, Virtualization: types.ImageVirtualization("paravirtualized")}, nil)
	provider.EXPECT().Flavors(gomock.Any()).Return(types.FlavorList{{ID: srvFlavorID}}, nil).AnyTimes()

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(srvRegionID).Return(provider, nil).AnyTimes()

	c := server.NewClientV2(common.ClientArgs{
		Client:    newSrvFakeClient(t, network).Build(),
		Namespace: srvNamespace,
		Identity:  mockIdentity,
		Providers: providers,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	_, err := c.CreateV2(ctx, minimalServerV2CreateRequest())

	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
	require.ErrorContains(t, err, "not recognized")
}

// TestServerUpdateV2AppliesImageChangeWithRetiredFlavor verifies that an image
// update still goes through when the server's (immutable, in-use) flavor is no
// longer offered by the region: the flavor-dependent compatibility checks are
// skipped — the image below would fail them against any known flavor — and the
// new image is applied, so a retired flavor cannot strand the fleet.
func TestServerUpdateV2AppliesImageChangeWithRetiredFlavor(t *testing.T) {
	t.Parallel()

	const newImageID = "bbbbbbbb-bbbb-4bbb-abbb-bbbbbbbbbbbb"

	ctrl := gomock.NewController(t)
	resource := testServerV2(srvServerID)
	network := testSrvNetworkWithProject(srvProjectID)

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().GetImage(gomock.Any(), identityids.MustParseOrganizationID(srvOrganizationID), idstest.MustParseImageID(newImageID)).
		Return(&types.Image{ID: newImageID, Status: types.ImageStatusReady, Virtualization: types.Baremetal, Architecture: types.Aarch64}, nil)
	provider.EXPECT().Flavors(gomock.Any()).Return(types.FlavorList{}, nil)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(srvRegionID).Return(provider, nil)

	c := server.NewClientV2(common.ClientArgs{
		Client:    newSrvFakeClient(t, network, resource).Build(),
		Namespace: srvNamespace,
		Providers: providers,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithSrvUpdate()))

	request := &openapi.ServerV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: resource.Name},
		Spec: openapi.ServerV2Spec{
			FlavorId: resource.Spec.FlavorID,
			ImageId:  idstest.MustParseImageID(newImageID),
		},
	}

	result, err := c.UpdateV2(ctx, idstest.MustParseServerID(resource.Name), request)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, idstest.MustParseImageID(newImageID), result.Spec.ImageId)

	updated, err := c.GetV2Raw(ctx, resource.Name)
	require.NoError(t, err)
	require.Equal(t, idstest.MustParseImageID(newImageID), updated.Spec.Image.ID)
}

// TestServerUpdateV2RetiredFlavorStillRequiresReadyImage verifies that
// tolerating a retired flavor on update does not relax the image-only checks:
// a not-Ready target image is still rejected with HTTP 422.
func TestServerUpdateV2RetiredFlavorStillRequiresReadyImage(t *testing.T) {
	t.Parallel()

	const newImageID = "bbbbbbbb-bbbb-4bbb-abbb-bbbbbbbbbbbb"

	ctrl := gomock.NewController(t)
	resource := testServerV2(srvServerID)
	network := testSrvNetworkWithProject(srvProjectID)

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().GetImage(gomock.Any(), identityids.MustParseOrganizationID(srvOrganizationID), idstest.MustParseImageID(newImageID)).
		Return(&types.Image{ID: newImageID, Status: types.ImageStatusPending}, nil)
	provider.EXPECT().Flavors(gomock.Any()).Return(types.FlavorList{}, nil).AnyTimes()

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(srvRegionID).Return(provider, nil)

	c := server.NewClientV2(common.ClientArgs{
		Client:    newSrvFakeClient(t, network, resource).Build(),
		Namespace: srvNamespace,
		Providers: providers,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithSrvUpdate()))

	request := &openapi.ServerV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: resource.Name},
		Spec: openapi.ServerV2Spec{
			FlavorId: resource.Spec.FlavorID,
			ImageId:  idstest.MustParseImageID(newImageID),
		},
	}

	_, err := c.UpdateV2(ctx, idstest.MustParseServerID(resource.Name), request)

	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
	require.ErrorContains(t, err, "image is not ready")
}

func TestServerGetV2ReturnsMACAddress(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	resource := testServerWithSSHCertificateAuthority()
	resource.SetActiveCondition(regionv1.ActiveConditionReasonRunning)
	resource.Status.PrivateIP = ptr.To("192.168.0.42")
	resource.Status.PublicIP = ptr.To("203.0.113.10")
	resource.Status.MACAddress = ptr.To("fa:16:3e:12:34:56")

	k8sClient := newSrvFakeClient(t, resource).Build()
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithSrvUpdate())

	result, err := c.GetV2(ctx, idstest.MustParseServerID(resource.Name))

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, resource.Status.PrivateIP, result.Status.PrivateIP)
	require.Equal(t, resource.Status.PublicIP, result.Status.PublicIP)
	require.Equal(t, resource.Status.MACAddress, result.Status.MacAddress)
}

func TestServerSSHKeyReturnsIdentityKey(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	resource := testServerV2(srvServerID)
	identity := testIdentity("test-identity")
	openstackIdentity := testOpenstackIdentity("test-identity", "private-key")

	k8sClient := newSrvFakeClient(t, resource, identity, openstackIdentity).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithSrvUpdate())

	result, err := c.SSHKey(ctx, idstest.MustParseServerID(resource.Name))

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "private-key", result.PrivateKey)
}

func TestServerSSHKeyReturnsNotFoundWhenIdentityKeyNotInjected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*regionv1.Server)
	}{
		{
			name: "SSHCertificateAuthority",
			mutate: func(server *regionv1.Server) {
				server.Spec.SSHCertificateAuthorityID = ptr.To("ca-1")
			},
		},
		{
			name: "SSHInjectionNone",
			mutate: func(server *regionv1.Server) {
				server.Spec.SSHInjection = ptr.To(regionv1.ServerSSHInjectionNone)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			resource := testServerV2(srvServerID)
			test.mutate(resource)

			k8sClient := newSrvFakeClient(t, resource).Build()

			mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

			c := server.NewClientV2(common.ClientArgs{
				Client:    k8sClient,
				Namespace: srvNamespace,
				Identity:  mockIdentity,
			})

			ctx := rbac.NewContext(t.Context(), aclWithSrvUpdate())

			_, err := c.SSHKey(ctx, idstest.MustParseServerID(resource.Name))

			require.Error(t, err)
			require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
		})
	}
}

func testIdentity(identityID string) *regionv1.Identity {
	return &regionv1.Identity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      identityID,
			Namespace: srvNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel: srvOrganizationID,
				coreconstants.ProjectLabel:      srvProjectID,
				constants.RegionLabel:           "test-region",
			},
		},
	}
}

func testOpenstackIdentity(identityID, privateKey string) *regionv1.OpenstackIdentity {
	return &regionv1.OpenstackIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      identityID,
			Namespace: srvNamespace,
		},
		Spec: regionv1.OpenstackIdentitySpec{
			SSHPrivateKey: []byte(privateKey),
		},
	}
}

func testServerV2(serverID string) *regionv1.Server {
	return &regionv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serverID,
			Namespace: srvNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   srvOrganizationID,
				coreconstants.ProjectLabel:        srvProjectID,
				coreconstants.NameLabel:           serverID,
				constants.RegionLabel:             srvRegionID,
				constants.IdentityLabel:           "test-identity",
				constants.NetworkLabel:            srvNetworkID,
				constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
			},
		},
		Spec: regionv1.ServerSpec{
			FlavorID: idstest.MustParseFlavorID(srvFlavorID),
			Image:    &regionv1.ServerImage{ID: idstest.MustParseImageID(srvImageID)},
			Networks: []regionv1.ServerNetworkSpec{{ID: idstest.MustParseNetworkID(srvNetworkID)}},
		},
	}
}

func TestServerGetV2Raw_NotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	k8sClient := newSrvFakeClient(t).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	_, err := c.GetV2Raw(rbac.NewContext(t.Context(), aclWithSrvUpdate()), srvNonexistentID)

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

func TestServerGetV2Raw_MissingAPIVersionLabel(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	resource := &regionv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "server-no-version",
			Namespace: srvNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel: srvOrganizationID,
				coreconstants.ProjectLabel:      srvProjectID,
			},
		},
		Spec: regionv1.ServerSpec{
			Image:    &regionv1.ServerImage{ID: idstest.MustParseImageID(srvImageID)},
			Networks: []regionv1.ServerNetworkSpec{{ID: idstest.MustParseNetworkID(srvNetworkID)}},
		},
	}

	k8sClient := newSrvFakeClient(t, resource).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	_, err := c.GetV2Raw(rbac.NewContext(t.Context(), aclWithSrvUpdate()), resource.Name)

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
	require.NotEmpty(t, err.Error(), "expected non-empty error description in response body")
}

func TestServerGetV2Raw_WrongAPIVersion(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	resource := &regionv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "server-v1",
			Namespace: srvNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   srvOrganizationID,
				coreconstants.ProjectLabel:        srvProjectID,
				constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(1),
			},
		},
		Spec: regionv1.ServerSpec{
			Image:    &regionv1.ServerImage{ID: idstest.MustParseImageID(srvImageID)},
			Networks: []regionv1.ServerNetworkSpec{{ID: idstest.MustParseNetworkID(srvNetworkID)}},
		},
	}

	k8sClient := newSrvFakeClient(t, resource).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	_, err := c.GetV2Raw(rbac.NewContext(t.Context(), aclWithSrvUpdate()), resource.Name)

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

func TestServerGetV2Raw_NoReadPermission(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	resource := testServerV2("server-no-read")

	k8sClient := newSrvFakeClient(t, resource).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	// org present in ACL but no endpoints — read is denied
	ctx := rbac.NewContext(t.Context(), &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{{Id: srvOrganizationID}},
	})

	_, err := c.GetV2Raw(ctx, resource.Name)

	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err), "expected forbidden, got: %v", err)
}

func aclWithSrvReadOnly(orgID string) *identityapi.Acl {
	return &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{{
			Id: orgID,
			Endpoints: &identityapi.AclEndpoints{{
				Name:       "region:servers",
				Operations: identityapi.AclOperations{identityapi.Read},
			}},
		}},
	}
}

func TestServerCreateV2_NetworkNotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	k8sClient := newSrvFakeClient(t).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate())

	_, err := c.CreateV2(ctx, minimalServerV2CreateRequest())

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

func TestServerUpdateV2_NotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	k8sClient := newSrvFakeClient(t).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithSrvUpdate())

	request := &openapi.ServerV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: srvNonexistentID},
		Spec:     openapi.ServerV2Spec{FlavorId: idstest.MustParseFlavorID(srvFlavorID), ImageId: idstest.MustParseImageID(srvImageID)},
	}

	_, err := c.UpdateV2(ctx, idstest.MustParseServerID(srvNonexistentID), request)

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

func TestServerUpdateV2_NoUpdatePermission(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	resource := testServerV2(srvServerID)

	k8sClient := newSrvFakeClient(t, resource).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithSrvReadOnly(srvOrganizationID))

	request := &openapi.ServerV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: resource.Name},
		Spec:     openapi.ServerV2Spec{FlavorId: resource.Spec.FlavorID, ImageId: resource.Spec.Image.ID},
	}

	_, err := c.UpdateV2(ctx, idstest.MustParseServerID(resource.Name), request)

	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err), "expected forbidden, got: %v", err)
}

func TestServerUpdateV2_ServerBeingDeleted(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	resource := testServerV2(srvServerID)
	now := metav1.NewTime(time.Now())
	resource.DeletionTimestamp = &now
	resource.Finalizers = []string{"servers.region.unikorn-cloud.org/test"}

	k8sClient := newSrvFakeClient(t, resource).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithSrvUpdate()))

	request := &openapi.ServerV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: resource.Name},
		Spec:     openapi.ServerV2Spec{FlavorId: resource.Spec.FlavorID, ImageId: resource.Spec.Image.ID},
	}

	_, err := c.UpdateV2(ctx, idstest.MustParseServerID(resource.Name), request)

	require.Error(t, err)
	require.True(t, coreerrors.IsBadRequest(err), "expected bad request (server being deleted), got: %v", err)
}

func TestServerUpdateV2_NetworkGone(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	// server exists but its network has been deleted
	resource := testServerV2(srvServerID)

	k8sClient := newSrvFakeClient(t, resource).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithSrvUpdate()))

	request := &openapi.ServerV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: resource.Name},
		Spec:     openapi.ServerV2Spec{FlavorId: resource.Spec.FlavorID, ImageId: resource.Spec.Image.ID},
	}

	_, err := c.UpdateV2(ctx, idstest.MustParseServerID(resource.Name), request)

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found (network gone), got: %v", err)
}

func TestServerDeleteV2_NotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	k8sClient := newSrvFakeClient(t).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithSrvUpdate())

	err := c.DeleteV2(ctx, idstest.MustParseServerID(srvNonexistentID))

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

func TestServerDeleteV2_NoDeletePermission(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	resource := testServerV2(srvServerID)

	k8sClient := newSrvFakeClient(t, resource).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithSrvReadOnly(srvOrganizationID))

	err := c.DeleteV2(ctx, idstest.MustParseServerID(resource.Name))

	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err), "expected forbidden, got: %v", err)
}

// srvProjectACL grants the given region:servers operations at project scope, which
// is what ListV2 uses to both build its label selector and filter each result.
func srvProjectACL(ops ...identityapi.AclOperation) *identityapi.Acl {
	return &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{
			{
				Id: srvOrganizationID,
				Projects: &identityapi.AclProjectList{
					{
						Id: srvProjectID,
						Endpoints: identityapi.AclEndpoints{
							{Name: "region:servers", Operations: ops},
						},
					},
				},
			},
		},
	}
}

// TestServerListV2 verifies ListV2 returns the project's servers, name-sorted, with
// their status fields populated from the underlying resources.
func TestServerListV2(t *testing.T) {
	t.Parallel()

	serverB := testServerV2("server-b")
	serverA := testServerV2("server-a")

	k8sClient := newSrvFakeClient(t, serverB, serverA).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
	})

	ctx := rbac.NewContext(t.Context(), srvProjectACL(identityapi.Read))

	result, err := c.ListV2(ctx, openapi.GetApiV2ServersParams{})

	require.NoError(t, err)
	require.Len(t, result, 2)
	require.Equal(t, "server-a", result[0].Metadata.Id)
	require.Equal(t, "server-b", result[1].Metadata.Id)
	require.Equal(t, idstest.MustParseRegionID(srvRegionID), result[0].Status.RegionId)
	require.Equal(t, idstest.MustParseNetworkID(srvNetworkID), result[0].Status.NetworkId)
}

// TestServerListV2ExcludesUnauthorizedProject verifies a server in a project the
// caller cannot see is omitted from the listing.
func TestServerListV2ExcludesUnauthorizedProject(t *testing.T) {
	t.Parallel()

	visible := testServerV2("server-visible")

	hidden := testServerV2("server-hidden")
	hidden.Labels[coreconstants.ProjectLabel] = "99999999-9999-4999-a999-999999999999"

	k8sClient := newSrvFakeClient(t, visible, hidden).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
	})

	ctx := rbac.NewContext(t.Context(), srvProjectACL(identityapi.Read))

	result, err := c.ListV2(ctx, openapi.GetApiV2ServersParams{})

	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, "server-visible", result[0].Metadata.Id)
}

// TestServerListV2FilterByRegion verifies the regionID query parameter restricts the
// listing to servers labelled with that region.
func TestServerListV2FilterByRegion(t *testing.T) {
	t.Parallel()

	resource := testServerV2(srvServerID)

	k8sClient := newSrvFakeClient(t, resource).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
	})

	ctx := rbac.NewContext(t.Context(), srvProjectACL(identityapi.Read))

	result, err := c.ListV2(ctx, openapi.GetApiV2ServersParams{
		RegionID: &openapi.RegionIDQueryParameter{"different-region"},
	})

	require.NoError(t, err)
	require.Empty(t, result)
}

// TestServerListV2Empty verifies ListV2 returns no servers when none exist for the
// caller's scope.
func TestServerListV2Empty(t *testing.T) {
	t.Parallel()

	k8sClient := newSrvFakeClient(t).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
	})

	ctx := rbac.NewContext(t.Context(), srvProjectACL(identityapi.Read))

	result, err := c.ListV2(ctx, openapi.GetApiV2ServersParams{})

	require.NoError(t, err)
	require.Empty(t, result)
}

func TestServerStartV2_NotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	k8sClient := newSrvFakeClient(t).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithSrvUpdate())

	err := c.StartV2(ctx, idstest.MustParseServerID(srvNonexistentID))

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

// TestServerCreateV2DeterministicID verifies that two creates with the same
// network ID and server name produce identical Kubernetes resource names and that
// changing either component yields a different name.
func TestServerCreateV2DeterministicID(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectProjectFound(mockIdentity).AnyTimes()

	providers := newMockProvidersWithReadyImage(ctrl)

	k8sClient := newSrvFakeClient(t, network).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Providers: providers,
		Identity:  mockIdentity,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	first, err := c.CreateV2(ctx, minimalServerV2CreateRequest())
	require.NoError(t, err)
	require.NotNil(t, first)

	firstID := first.Metadata.Id

	// Same (networkID, name) must produce the same Kubernetes resource name.
	// The second create hits the AlreadyExists path and we verify the ID is stable.
	k8sClientFresh := newSrvFakeClient(t, network).Build()

	c2 := server.NewClientV2(common.ClientArgs{
		Client:    k8sClientFresh,
		Namespace: srvNamespace,
		Providers: providers,
		Identity:  mockIdentity,
	})

	ctx2 := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	second, err := c2.CreateV2(ctx2, minimalServerV2CreateRequest())
	require.NoError(t, err)
	require.Equal(t, firstID, second.Metadata.Id, "same (networkID, name) must yield the same resource ID")

	// Different name on the same network must produce a different ID.
	diffReq := minimalServerV2CreateRequest()
	diffReq.Metadata.Name = "other-server"

	k8sClientDiff := newSrvFakeClient(t, network).Build()

	c3 := server.NewClientV2(common.ClientArgs{
		Client:    k8sClientDiff,
		Namespace: srvNamespace,
		Providers: providers,
		Identity:  mockIdentity,
	})

	ctx3 := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	diff, err := c3.CreateV2(ctx3, diffReq)
	require.NoError(t, err)
	require.NotEqual(t, firstID, diff.Metadata.Id, "different server name must yield a different resource ID")

	// Same name on a different network must produce a different ID (namespace dimension).
	otherNetworkID := "bbbbcccc-1234-5678-9abc-def012345678"
	otherNetwork := &regionv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      otherNetworkID,
			Namespace: srvNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   srvOrganizationID,
				coreconstants.ProjectLabel:        srvProjectID,
				constants.RegionLabel:             srvRegionID,
				constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
			},
		},
	}

	sameNameOtherNetReq := minimalServerV2CreateRequest()
	sameNameOtherNetReq.Spec.NetworkId = idstest.MustParseNetworkID(otherNetworkID)

	k8sClientOtherNet := newSrvFakeClient(t, otherNetwork).Build()
	c4 := server.NewClientV2(common.ClientArgs{
		Client:    k8sClientOtherNet,
		Namespace: srvNamespace,
		Providers: providers,
		Identity:  mockIdentity,
	})

	ctx4 := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	sameNameOtherNet, err := c4.CreateV2(ctx4, sameNameOtherNetReq)
	require.NoError(t, err)
	require.NotEqual(t, firstID, sameNameOtherNet.Metadata.Id, "same server name on a different network must yield a different resource ID")
}

// TestServerCreateV2ConflictOnDuplicateName verifies that a second create with the
// same name on the same network is rejected with HTTP 409 Conflict.
func TestServerCreateV2ConflictOnDuplicateName(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	providers := newMockProvidersWithReadyImage(ctrl)

	expectProjectFound(mockIdentity).AnyTimes()

	k8sClient := newSrvFakeClient(t, network).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Providers: providers,
		Identity:  mockIdentity,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	_, err := c.CreateV2(ctx, minimalServerV2CreateRequest())
	require.NoError(t, err, "first create must succeed")

	ctx2 := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	_, err = c.CreateV2(ctx2, minimalServerV2CreateRequest())
	require.Error(t, err)
	require.True(t, coreerrors.IsConflict(err), "duplicate name on same network must return 409 Conflict, got: %v", err)
}

// TestServerUpdateV2RejectsRename verifies that an update request supplying a
// different name than the current server name is rejected with HTTP 422.
func TestServerUpdateV2RejectsRename(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)
	resource := testServerWithSSHCertificateAuthority()

	k8sClient := newSrvFakeClient(t, network, resource).Build()
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithSrvUpdate()))

	request := &openapi.ServerV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: "renamed-server"},
		Spec: openapi.ServerV2Spec{
			FlavorId: resource.Spec.FlavorID,
			ImageId:  resource.Spec.Image.ID,
		},
	}

	_, err := c.UpdateV2(ctx, idstest.MustParseServerID(resource.Name), request)
	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "rename attempt must return 422 Unprocessable Content, got: %v", err)
}

// withAvailableCondition stamps the server's Available condition with the given
// reason so the read conversion derives a provisioning status from it. The
// condition status mirrors what the reconciler would write (True only for
// Provisioned) but the conversion switches on the reason alone.
func withAvailableCondition(server *regionv1.Server, reason corev1alpha1.ProvisioningConditionReason) *regionv1.Server {
	status := corev1.ConditionFalse
	if reason == corev1alpha1.ConditionReasonProvisioned {
		status = corev1.ConditionTrue
	}

	server.SetProvisioningCondition(status, reason, "")

	return server
}

// withRebuildMarker records a rebuild marker for the fixture image in the
// given lifecycle state.
func withRebuildMarker(server *regionv1.Server, state regionv1.ServerRebuildState) *regionv1.Server {
	server.Status.Rebuild = &regionv1.ServerRebuildStatus{
		TargetImageID: idstest.MustParseImageID(srvImageID),
		State:         state,
	}

	return server
}

// TestServerGetV2RebuildPendingReportsProvisioning verifies that a server with a
// rebuild in flight (marker retained, Nova acting) whose Available condition
// already reads Provisioned is reported as provisioning at the v2 API — the
// rebuild's target image is not yet realized, so the server is not settled.
func TestServerGetV2RebuildPendingReportsProvisioning(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	resource := withRebuildMarker(withAvailableCondition(testServerV2(srvServerID), corev1alpha1.ConditionReasonProvisioned), regionv1.ServerRebuildStateRebuilding)

	k8sClient := newSrvFakeClient(t, resource).Build()
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithSrvUpdate())

	result, err := c.GetV2(ctx, idstest.MustParseServerID(resource.Name))

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, coreapi.ResourceProvisioningStatusProvisioning, result.Metadata.ProvisioningStatus)
}

// TestServerGetV2NoRebuildReportsProvisioned verifies that a settled server with
// no rebuild marker passes its converted Provisioned status through untouched.
func TestServerGetV2NoRebuildReportsProvisioned(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	resource := withAvailableCondition(testServerV2(srvServerID), corev1alpha1.ConditionReasonProvisioned)

	k8sClient := newSrvFakeClient(t, resource).Build()
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithSrvUpdate())

	result, err := c.GetV2(ctx, idstest.MustParseServerID(resource.Name))

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, coreapi.ResourceProvisioningStatusProvisioned, result.Metadata.ProvisioningStatus)
}

// TestServerGetV2RebuildPendingErroredStaysError verifies that a parked rebuild
// (marker retained, Available condition Errored) keeps its error status: the
// override must never mask a failure, so the park stays visible.
func TestServerGetV2RebuildPendingErroredStaysError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	resource := withRebuildMarker(withAvailableCondition(testServerV2(srvServerID), corev1alpha1.ConditionReasonErrored), regionv1.ServerRebuildStateFailed)

	k8sClient := newSrvFakeClient(t, resource).Build()
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithSrvUpdate())

	result, err := c.GetV2(ctx, idstest.MustParseServerID(resource.Name))

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, coreapi.ResourceProvisioningStatusError, result.Metadata.ProvisioningStatus)
}

// TestServerGetV2RebuildIntentNotAcceptedReportsProvisioning verifies that a
// recorded rebuild intent Nova has not yet accepted (state Initiated) reports
// the server as provisioning: the desired image is not realized, so the spec
// is not settled even before Nova acts (an armed rebuild that persistently
// 409s must not misreport as provisioned).
func TestServerGetV2RebuildIntentNotAcceptedReportsProvisioning(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	resource := withRebuildMarker(withAvailableCondition(testServerV2(srvServerID), corev1alpha1.ConditionReasonProvisioned), regionv1.ServerRebuildStateInitiated)

	k8sClient := newSrvFakeClient(t, resource).Build()
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithSrvUpdate())

	result, err := c.GetV2(ctx, idstest.MustParseServerID(resource.Name))

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, coreapi.ResourceProvisioningStatusProvisioning, result.Metadata.ProvisioningStatus)
}

// TestServerListV2RebuildPendingReportsProvisioning pins that the list read path
// shares the same derivation as get: a pending-rebuild server surfaces as
// provisioning through ListV2 too.
func TestServerListV2RebuildPendingReportsProvisioning(t *testing.T) {
	t.Parallel()

	resource := withRebuildMarker(withAvailableCondition(testServerV2(srvServerID), corev1alpha1.ConditionReasonProvisioned), regionv1.ServerRebuildStateRebuilding)

	k8sClient := newSrvFakeClient(t, resource).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
	})

	ctx := rbac.NewContext(t.Context(), srvProjectACL(identityapi.Read))

	result, err := c.ListV2(ctx, openapi.GetApiV2ServersParams{})

	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, coreapi.ResourceProvisioningStatusProvisioning, result[0].Metadata.ProvisioningStatus)
}
