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

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	identitymock "github.com/unikorn-cloud/identity/pkg/openapi/mock"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/server"
	"github.com/unikorn-cloud/region/pkg/openapi"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
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

// testSrvNetworkWithProject returns a v2 Network object with the given project label.
func testSrvNetworkWithProject(projID string) *regionv1.Network {
	return &regionv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      srvNetworkID,
			Namespace: srvNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   srvOrganizationID,
				coreconstants.ProjectLabel:        projID,
				constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
			},
		},
	}
}

// aclWithOrgScopeServerCreate grants network:read and region:servers/Create at
// organization scope so GetV2Raw passes and AllowProjectScopeCreate is reached.
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

func aclWithSrvUpdate(orgID string) *identityapi.Acl {
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
						Operations: identityapi.AclOperations{identityapi.Read, identityapi.Update},
					},
				},
			},
		},
	}
}

func expectProjectFound(mockIdentity *identitymock.MockClientWithResponsesInterface) {
	mockIdentity.EXPECT().
		GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), srvOrganizationID, srvProjectID).
		Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
		}, nil)
}

func newMockProvidersWithNoFlavors(ctrl *gomock.Controller) *mockproviders.MockProviders {
	mockProvider := mocktypes.NewMockProvider(ctrl)
	mockProvider.EXPECT().Flavors(gomock.Any()).Return(nil, nil)

	mockProviders := mockproviders.NewMockProviders(ctrl)
	mockProviders.EXPECT().LookupCloud(gomock.Any()).Return(mockProvider, nil)

	return mockProviders
}

func minimalServerV2CreateRequest() *openapi.ServerV2Create {
	return &openapi.ServerV2Create{
		Metadata: coreapi.ResourceWriteMetadata{Name: "test-server"},
		Spec: openapi.ServerV2CreateSpec{
			NetworkId: srvNetworkID,
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

func testSSHCertificateAuthorityWithProject(projID, caID string) *regionv1.SSHCertificateAuthority {
	return &regionv1.SSHCertificateAuthority{
		ObjectMeta: metav1.ObjectMeta{
			Name:      caID,
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

func testServerWithSSHCertificateAuthority(orgID, projID, serverID, caID string) *regionv1.Server {
	return &regionv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serverID,
			Namespace: srvNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   orgID,
				coreconstants.ProjectLabel:        projID,
				constants.RegionLabel:             "test-region",
				constants.IdentityLabel:           "test-identity",
				constants.NetworkLabel:            srvNetworkID,
				constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
			},
		},
		Spec: regionv1.ServerSpec{
			FlavorID: "flavor-1",
			Image: &regionv1.ServerImage{
				ID: "image-1",
			},
			Networks: []regionv1.ServerNetworkSpec{{
				ID: srvNetworkID,
			}},
			SSHCertificateAuthorityID: ptr.To(caID),
		},
	}
}

// TestServerCreateV2RBACOrgScopedProjectNotFound verifies that CreateV2 returns
// a 404 Not Found when the caller has org-scoped ACL but the project from the
// network labels does not exist in the identity service.
func TestServerCreateV2RBACOrgScopedProjectNotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject("nonexistent-project")

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
	ca := testSSHCertificateAuthorityWithProject("other-project", "ca-1")

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

func TestServerCreateV2SSHCertificateAuthorityRejectsUnsupportedUserData(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)
	ca := testSSHCertificateAuthorityWithProject(srvProjectID, "ca-1")

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
			ca := testSSHCertificateAuthorityWithProject(srvProjectID, "ca-1")

			k8sClient := newSrvFakeClient(t, network, ca).Build()

			mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
			expectProjectFound(mockIdentity)

			mockProviders := newMockProvidersWithNoFlavors(ctrl)

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

func TestServerCreateV2RejectsInvalidAllowedSourceAddress(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)

	k8sClient := newSrvFakeClient(t, network).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectProjectFound(mockIdentity)

	mockProviders := newMockProvidersWithNoFlavors(ctrl)

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
		GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), srvOrganizationID, srvProjectID).
		Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
		}, nil)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate()))

	infrastructureRef := "node-uuid-123"
	request := minimalServerV2CreateRequest()
	request.Spec.InfrastructureRef = &infrastructureRef

	result, err := c.CreateV2(ctx, request)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Status.InfrastructureRef)
	require.Equal(t, infrastructureRef, *result.Status.InfrastructureRef)

	created := &regionv1.Server{}
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKey{Namespace: srvNamespace, Name: result.Metadata.Id}, created))
	require.NotNil(t, created.Spec.InfrastructureRef)
	require.Equal(t, infrastructureRef, *created.Spec.InfrastructureRef)
}

func TestServerUpdateV2PreservesSSHCertificateAuthority(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)
	resource := testServerWithSSHCertificateAuthority(srvOrganizationID, srvProjectID, "server-1", "ca-1")

	k8sClient := newSrvFakeClient(t, network, resource).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithSrvUpdate(srvOrganizationID)))

	request := &openapi.ServerV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: resource.Name},
		Spec: openapi.ServerV2Spec{
			FlavorId: resource.Spec.FlavorID,
			ImageId:  resource.Spec.Image.ID,
			UserData: ptr.To([]byte("#cloud-config\nusers: []\n")),
		},
	}

	result, err := c.UpdateV2(ctx, resource.Name, request)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, resource.Spec.SSHCertificateAuthorityID, result.Status.SshCertificateAuthorityId)

	updated, err := c.GetV2Raw(ctx, resource.Name)
	require.NoError(t, err)
	require.Equal(t, resource.Spec.SSHCertificateAuthorityID, updated.Spec.SSHCertificateAuthorityID)
}

func TestServerGetV2ReturnsMACAddress(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	resource := testServerWithSSHCertificateAuthority(srvOrganizationID, srvProjectID, "server-1", "ca-1")
	resource.Status.Phase = regionv1.InstanceLifecyclePhaseRunning
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

	ctx := rbac.NewContext(t.Context(), aclWithSrvUpdate(srvOrganizationID))

	result, err := c.GetV2(ctx, resource.Name)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, resource.Status.PrivateIP, result.Status.PrivateIP)
	require.Equal(t, resource.Status.PublicIP, result.Status.PublicIP)
	require.Equal(t, resource.Status.MACAddress, result.Status.MacAddress)
}
