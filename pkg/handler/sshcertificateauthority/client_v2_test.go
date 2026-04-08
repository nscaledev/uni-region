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

package sshcertificateauthority_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/ssh"

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
	"github.com/unikorn-cloud/region/pkg/handler/sshcertificateauthority"
	"github.com/unikorn-cloud/region/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	organizationID = "foo"
	projectID      = "bar"
	namespace      = "test-namespace"
)

func newFakeClient(t *testing.T, objects ...runtime.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, regionv1.AddToScheme(scheme))

	builder := fake.NewClientBuilder().WithScheme(scheme)

	for _, o := range objects {
		builder = builder.WithRuntimeObjects(o)
	}

	return builder.Build()
}

func aclWithOrgScopeCreate(orgID string) *identityapi.Acl {
	return &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{
			{
				Id: orgID,
				Endpoints: &identityapi.AclEndpoints{
					{
						Name:       "region:sshcertificateauthorities:v2",
						Operations: identityapi.AclOperations{identityapi.Create},
					},
				},
			},
		},
	}
}

func aclWithReadDelete(orgID string) *identityapi.Acl {
	return &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{
			{
				Id: orgID,
				Endpoints: &identityapi.AclEndpoints{
					{
						Name:       "region:sshcertificateauthorities:v2",
						Operations: identityapi.AclOperations{identityapi.Read, identityapi.Delete},
					},
				},
			},
		},
	}
}

func minimalCreateRequest(publicKey string) *openapi.SshCertificateAuthorityV2Create {
	return &openapi.SshCertificateAuthorityV2Create{
		Metadata: coreapi.ResourceWriteMetadata{Name: "test-ssh-ca"},
		Spec: openapi.SshCertificateAuthorityV2CreateSpec{
			OrganizationId: organizationID,
			ProjectId:      projectID,
			PublicKey:      publicKey,
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

func mustAuthorizedKey(t *testing.T) string {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	publicKey, err := ssh.NewPublicKey(privateKey.Public())
	require.NoError(t, err)

	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey))) + " test-ca"
}

func TestCreateV2(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	mockIdentity.EXPECT().
		GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), organizationID, projectID).
		Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
		}, nil)

	c := sshcertificateauthority.New(common.ClientArgs{
		Client:    newFakeClient(t),
		Namespace: namespace,
		Identity:  mockIdentity,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeCreate(organizationID)))

	request := minimalCreateRequest("\n" + mustAuthorizedKey(t) + "\n")

	result, err := c.CreateV2(ctx, request)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, strings.TrimSpace(request.Spec.PublicKey), result.Spec.PublicKey)
}

func TestCreateV2InvalidKey(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	mockIdentity.EXPECT().
		GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), organizationID, projectID).
		Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
		}, nil)

	c := sshcertificateauthority.New(common.ClientArgs{
		Client:    newFakeClient(t),
		Namespace: namespace,
		Identity:  mockIdentity,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeCreate(organizationID)))

	_, err := c.CreateV2(ctx, minimalCreateRequest("definitely-not-an-ssh-key"))
	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
}

func TestCreateV2RBACOrgScopedProjectNotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	mockIdentity.EXPECT().
		GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), organizationID, "nonexistent-project").
		Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
		}, nil)

	c := sshcertificateauthority.New(common.ClientArgs{
		Client:   newFakeClient(t),
		Identity: mockIdentity,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithOrgScopeCreate(organizationID)))

	request := minimalCreateRequest(mustAuthorizedKey(t))
	request.Spec.ProjectId = "nonexistent-project"

	_, err := c.CreateV2(ctx, request)
	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

func TestDeleteV2InUse(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	resource := &regionv1.SSHCertificateAuthority{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ssh-ca-id",
			Namespace: namespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   organizationID,
				coreconstants.ProjectLabel:        projectID,
				constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
			},
			Finalizers: []string{"servers.region.unikorn-cloud.org/server-id"},
		},
		Spec: regionv1.SSHCertificateAuthoritySpec{
			PublicKey: mustAuthorizedKey(t),
		},
	}

	c := sshcertificateauthority.New(common.ClientArgs{
		Client:    newFakeClient(t, resource),
		Namespace: namespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), aclWithReadDelete(organizationID))

	err := c.DeleteV2(ctx, resource.Name)
	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err), "expected forbidden, got: %v", err)
}
