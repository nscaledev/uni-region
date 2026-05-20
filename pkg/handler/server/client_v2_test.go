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

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreresourceerrors "github.com/unikorn-cloud/core/pkg/errors"
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
	providersmock "github.com/unikorn-cloud/region/pkg/providers/mock"
	providertypes "github.com/unikorn-cloud/region/pkg/providers/types"
	providermock "github.com/unikorn-cloud/region/pkg/providers/types/mock"

	"k8s.io/apimachinery/pkg/api/resource"
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
	srvNetworkID      = "aaaabbbb-1234-5678-9abc-def012345678"
	srvRegionID       = "test-region"
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

func minimalServerV2CreateRequest() *openapi.ServerV2Create {
	return &openapi.ServerV2Create{
		Metadata: coreapi.ResourceWriteMetadata{Name: "test-server"},
		Spec: openapi.ServerV2CreateSpec{
			FlavorId:  "flavor-1",
			ImageId:   "image-1",
			NetworkId: srvNetworkID,
		},
	}
}

func testSrvReadyImage() *providertypes.Image {
	return &providertypes.Image{
		ID:             "image-1",
		Status:         providertypes.ImageStatusReady,
		SizeGiB:        20,
		Virtualization: providertypes.Any,
	}
}

func testSrvFlavorList() providertypes.FlavorList {
	return providertypes.FlavorList{
		{ID: "flavor-1", Disk: resource.NewScaledQuantity(40, resource.Giga), Baremetal: false},
	}
}

func expectValidServerImageProvider(t *testing.T, ctrl *gomock.Controller) *providersmock.MockProviders {
	t.Helper()

	provider := providermock.NewMockProvider(ctrl)
	provider.EXPECT().GetImage(gomock.Any(), srvOrganizationID, "image-1").Return(testSrvReadyImage(), nil)
	provider.EXPECT().Flavors(gomock.Any()).Return(testSrvFlavorList(), nil)

	providers := providersmock.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(srvRegionID).Return(provider, nil)

	return providers
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

func testServerWithSSHCertificateAuthority() *regionv1.Server {
	return &regionv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "server-1",
			Namespace: srvNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   srvOrganizationID,
				coreconstants.ProjectLabel:        srvProjectID,
				coreconstants.NameLabel:           "server-1",
				constants.RegionLabel:             srvRegionID,
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
			SSHCertificateAuthorityID: ptr.To("ca-1"),
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

func TestCreateV2RejectsInvalidImage(t *testing.T) {
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

	provider := providermock.NewMockProvider(ctrl)
	provider.EXPECT().
		GetImage(gomock.Any(), srvOrganizationID, "missing-image").
		Return(nil, coreresourceerrors.ErrResourceNotFound)

	providers := providersmock.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(srvRegionID).Return(provider, nil)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
		Providers: providers,
	})

	ctx := rbac.NewContext(t.Context(), aclWithOrgScopeServerCreate())

	request := minimalServerV2CreateRequest()
	request.Spec.ImageId = "missing-image"

	_, err := c.CreateV2(ctx, request)

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

func TestServerCreateV2SSHCertificateAuthorityNotFound(t *testing.T) {
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
		Providers: expectValidServerImageProvider(t, ctrl),
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
	mockIdentity.EXPECT().
		GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), srvOrganizationID, srvProjectID).
		Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
		}, nil)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
		Providers: expectValidServerImageProvider(t, ctrl),
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
	mockIdentity.EXPECT().
		GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), srvOrganizationID, srvProjectID).
		Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
		}, nil)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
		Providers: expectValidServerImageProvider(t, ctrl),
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
			mockIdentity.EXPECT().
				GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), srvOrganizationID, srvProjectID).
				Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
					HTTPResponse: &http.Response{StatusCode: http.StatusOK},
				}, nil)

			c := server.NewClientV2(common.ClientArgs{
				Client:    k8sClient,
				Namespace: srvNamespace,
				Identity:  mockIdentity,
				Providers: expectValidServerImageProvider(t, ctrl),
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
	mockIdentity.EXPECT().
		GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), srvOrganizationID, srvProjectID).
		Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
		}, nil)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
		Providers: expectValidServerImageProvider(t, ctrl),
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
		Providers: expectValidServerImageProvider(t, ctrl),
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

func TestUpdateV2RejectsInvalidImage(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	network := testSrvNetworkWithProject(srvProjectID)
	resource := testServerWithSSHCertificateAuthority()

	k8sClient := newSrvFakeClient(t, network, resource).Build()

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	provider := providermock.NewMockProvider(ctrl)
	provider.EXPECT().
		GetImage(gomock.Any(), srvOrganizationID, "missing-image").
		Return(nil, coreresourceerrors.ErrResourceNotFound)

	providers := providersmock.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(srvRegionID).Return(provider, nil)

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
		Providers: providers,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithSrvUpdate()))

	request := &openapi.ServerV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: resource.Name},
		Spec: openapi.ServerV2Spec{
			FlavorId: resource.Spec.FlavorID,
			ImageId:  "missing-image",
		},
	}

	_, err := c.UpdateV2(ctx, resource.Name, request)

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

func TestUpdateV2SkipsValidationWhenImageUnchanged(t *testing.T) {
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
		Providers: providersmock.NewMockProviders(ctrl),
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithSrvUpdate()))

	request := &openapi.ServerV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: resource.Name},
		Spec: openapi.ServerV2Spec{
			FlavorId: resource.Spec.FlavorID,
			ImageId:  resource.Spec.Image.ID,
		},
	}

	result, err := c.UpdateV2(ctx, resource.Name, request)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, resource.Spec.Image.ID, result.Spec.ImageId)
}

func TestServerUpdateV2PreservesSSHCertificateAuthority(t *testing.T) {
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

	resource := testServerWithSSHCertificateAuthority()
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

	ctx := rbac.NewContext(t.Context(), aclWithSrvUpdate())

	result, err := c.GetV2(ctx, resource.Name)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, resource.Status.PrivateIP, result.Status.PrivateIP)
	require.Equal(t, resource.Status.PublicIP, result.Status.PublicIP)
	require.Equal(t, resource.Status.MACAddress, result.Status.MacAddress)
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
				constants.RegionLabel:             "test-region",
				constants.IdentityLabel:           "test-identity",
				constants.NetworkLabel:            srvNetworkID,
				constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
			},
		},
		Spec: regionv1.ServerSpec{
			FlavorID: "flavor-1",
			Image:    &regionv1.ServerImage{ID: "image-1"},
			Networks: []regionv1.ServerNetworkSpec{{ID: srvNetworkID}},
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

	_, err := c.GetV2Raw(rbac.NewContext(t.Context(), aclWithSrvUpdate()), "nonexistent-server")

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
			Image:    &regionv1.ServerImage{ID: "image-1"},
			Networks: []regionv1.ServerNetworkSpec{{ID: srvNetworkID}},
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
			Image:    &regionv1.ServerImage{ID: "image-1"},
			Networks: []regionv1.ServerNetworkSpec{{ID: srvNetworkID}},
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
		Metadata: coreapi.ResourceWriteMetadata{Name: "nonexistent-server"},
		Spec:     openapi.ServerV2Spec{FlavorId: "flavor-1", ImageId: "image-1"},
	}

	_, err := c.UpdateV2(ctx, "nonexistent-server", request)

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

func TestServerUpdateV2_NoUpdatePermission(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	resource := testServerV2("server-1")

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

	_, err := c.UpdateV2(ctx, resource.Name, request)

	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err), "expected forbidden, got: %v", err)
}

func TestServerUpdateV2_ServerBeingDeleted(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	resource := testServerV2("server-1")
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

	_, err := c.UpdateV2(ctx, resource.Name, request)

	require.Error(t, err)
	require.True(t, coreerrors.IsBadRequest(err), "expected bad request (server being deleted), got: %v", err)
}

func TestServerUpdateV2_NetworkGone(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	// server exists but its network has been deleted
	resource := testServerV2("server-1")

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

	_, err := c.UpdateV2(ctx, resource.Name, request)

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

	err := c.DeleteV2(ctx, "nonexistent-server")

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

func TestServerDeleteV2_NoDeletePermission(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	resource := testServerV2("server-1")

	k8sClient := newSrvFakeClient(t, resource).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithSrvReadOnly(srvOrganizationID))

	err := c.DeleteV2(ctx, resource.Name)

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
	require.Equal(t, "test-region", result[0].Status.RegionId)
	require.Equal(t, srvNetworkID, result[0].Status.NetworkId)
}

// TestServerListV2ExcludesUnauthorizedProject verifies a server in a project the
// caller cannot see is omitted from the listing.
func TestServerListV2ExcludesUnauthorizedProject(t *testing.T) {
	t.Parallel()

	visible := testServerV2("server-visible")

	hidden := testServerV2("server-hidden")
	hidden.Labels[coreconstants.ProjectLabel] = "other-project"

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

	resource := testServerV2("server-1")

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

	err := c.StartV2(ctx, "nonexistent-server")

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
	mockIdentity.EXPECT().
		GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), srvOrganizationID, srvProjectID).
		Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
		}, nil).
		AnyTimes()

	provider := providermock.NewMockProvider(ctrl)
	provider.EXPECT().GetImage(gomock.Any(), srvOrganizationID, "image-1").Return(testSrvReadyImage(), nil).AnyTimes()
	provider.EXPECT().Flavors(gomock.Any()).Return(testSrvFlavorList(), nil).AnyTimes()

	providers := providersmock.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(srvRegionID).Return(provider, nil).AnyTimes()

	k8sClient := newSrvFakeClient(t, network).Build()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
		Providers: providers,
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
		Identity:  mockIdentity,
		Providers: providers,
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
		Identity:  mockIdentity,
		Providers: providers,
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
	sameNameOtherNetReq.Spec.NetworkId = otherNetworkID

	k8sClientOtherNet := newSrvFakeClient(t, otherNetwork).Build()
	c4 := server.NewClientV2(common.ClientArgs{
		Client:    k8sClientOtherNet,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
		Providers: providers,
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
	mockIdentity.EXPECT().
		GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), srvOrganizationID, srvProjectID).
		Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
		}, nil).
		AnyTimes()

	k8sClient := newSrvFakeClient(t, network).Build()

	provider := providermock.NewMockProvider(ctrl)
	provider.EXPECT().GetImage(gomock.Any(), srvOrganizationID, "image-1").Return(testSrvReadyImage(), nil).AnyTimes()
	provider.EXPECT().Flavors(gomock.Any()).Return(testSrvFlavorList(), nil).AnyTimes()

	providers := providersmock.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(srvRegionID).Return(provider, nil).AnyTimes()

	c := server.NewClientV2(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Identity:  mockIdentity,
		Providers: providers,
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

	_, err := c.UpdateV2(ctx, resource.Name, request)
	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "rename attempt must return 422 Unprocessable Content, got: %v", err)
}
