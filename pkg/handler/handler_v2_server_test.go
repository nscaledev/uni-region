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

//nolint:testpackage
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/unikorn-cloud/core/pkg/constants"
	identityv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	regionconstants "github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/server"
	"github.com/unikorn-cloud/region/pkg/handler/server/mock"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func fakeClientWithSchema(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, identityv1.AddToScheme(scheme))
	require.NoError(t, regionv1.AddToScheme(scheme))

	b := fake.NewClientBuilder().WithScheme(scheme)
	if len(objects) > 0 {
		b = b.WithObjects(objects...)
	}

	return b.Build()
}

type aclBuilder struct {
	org identityapi.AclOrganization
}

func newOrganisationACLBuilder(orgID string) *aclBuilder {
	return &aclBuilder{
		org: identityapi.AclOrganization{
			Id: orgID,
		},
	}
}

func (b *aclBuilder) addEndpoint(endpoint string, perms ...identityapi.AclOperation) *aclBuilder {
	var endpoints []identityapi.AclEndpoint
	if ep := b.org.Endpoints; ep != nil {
		endpoints = *ep
	}

	endpoints = append(endpoints, identityapi.AclEndpoint{
		Name:       endpoint,
		Operations: perms,
	})

	b.org.Endpoints = &endpoints

	return b
}

func (b *aclBuilder) buildContext(ctx context.Context) context.Context {
	return rbac.NewContext(ctx, &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{b.org},
	})
}

type labels map[string]string

func withMeta[T client.Object](obj T, name, homeNamespace string, labels map[string]string) T {
	obj.SetName(name)
	obj.SetNamespace(homeNamespace)
	obj.SetLabels(labels)

	return obj
}

func newServer(t *testing.T, name, namespace string, metalabels labels) *regionv1.Server {
	t.Helper()

	return withMeta(&regionv1.Server{
		Spec: regionv1.ServerSpec{
			Image: &regionv1.ServerImage{
				ID: "image1",
			},
		},
	}, name, namespace, metalabels)
}

func projectScopedLabels(orgID, projectID string, extra labels) labels {
	initial := labels{
		constants.OrganizationLabel: orgID,
		constants.ProjectLabel:      projectID,
	}

	maps.Copy(initial, extra)

	return initial
}

func knownGoodFixture(t *testing.T, serverName, homeNamespace, orgID string) []client.Object {
	t.Helper()

	return []client.Object{
		withMeta(&regionv1.Identity{}, "id1", homeNamespace, projectScopedLabels(orgID, "project1", labels{})),
		newServer(t, serverName, homeNamespace, projectScopedLabels(orgID, "project1", labels{
			regionconstants.IdentityLabel:           "id1",
			regionconstants.ResourceAPIVersionLabel: "2",
		})),
	}
}

func requireDeserialiseBody(t *testing.T, body io.Reader, object any) {
	t.Helper()

	responseBytes, err := io.ReadAll(body)
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(responseBytes, object))
}

func assertBodyIsEmptyServerList(t *testing.T, body io.Reader) {
	t.Helper()

	var list openapi.ServersResponse

	requireDeserialiseBody(t, body, &list)

	assert.Empty(t, list)
}

func TestServerV2_EmptyList(t *testing.T) {
	t.Parallel()

	namespace := "region-test-home"

	c := fakeClientWithSchema(t) // NB no objects
	handler := NewServerV2Handler(c, namespace)

	ctx := newOrganisationACLBuilder("org-empty-list").
		addEndpoint("region:servers").
		buildContext(t.Context())
	response := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v2/servers", nil)

	handler.GetApiV2Servers(response, request, openapi.GetApiV2ServersParams{})

	require.Equal(t, http.StatusOK, response.Result().StatusCode)
	assertBodyIsEmptyServerList(t, response.Result().Body)
}

func TestServerV2_NotAllowedList(t *testing.T) {
	t.Parallel()

	namespace := "region-test-home"

	c := fakeClientWithSchema(t, knownGoodFixture(t, "server1", namespace, "org-not-allowed-test")...)
	handler := NewServerV2Handler(c, namespace)

	ctx := newOrganisationACLBuilder("org1").
		addEndpoint("region:servers").
		buildContext(t.Context())

	response := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v2/servers", nil)

	handler.GetApiV2Servers(response, request, openapi.GetApiV2ServersParams{})

	require.Equal(t, http.StatusOK, response.Result().StatusCode)
	assertBodyIsEmptyServerList(t, response.Result().Body)
}

func newSnapshotRequest(ctx context.Context) *http.Request {
	requestBody := bytes.NewBufferString(`
	{
	  "metadata": {"name": "foobar"}
	}`)

	return httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v2/servers", requestBody)
}

func providerGetter(provider *mock.MockProvider) server.GetProviderFunc {
	return func(_ context.Context, _ client.Client, _, _ string) (server.Provider, error) {
		return provider, nil
	}
}

func TestServerV2_Snapshot_NotAllowedWithoutPermissions(t *testing.T) {
	t.Parallel()

	const (
		namespace  = "region-test-home"
		orgID      = "org-not-allowed-permissions"
		serverName = "server1"
	)

	c := fakeClientWithSchema(t, knownGoodFixture(t, serverName, namespace, orgID)...)
	handler := NewServerV2Handler(c, namespace)

	// We can't guarantee the order things are done in the handler, and in particular, the region provider
	// may be requested before permissions are checked. So, make sure there is a provider, though we don't
	// expect it to be called.
	provider := mock.NewTestMockProvider(t)
	handler.getProvider = providerGetter(provider)

	testcases := []struct {
		name    string
		makeCtx func(context.Context) context.Context
	}{
		{
			name:    "no_perms",
			makeCtx: newOrganisationACLBuilder(orgID).buildContext,
		},
		{
			name: "only_region_server_read",
			makeCtx: newOrganisationACLBuilder(orgID).
				addEndpoint("region:servers", identityapi.Read).
				buildContext,
		},
		{
			name: "only_image_create",
			makeCtx: newOrganisationACLBuilder(orgID).
				addEndpoint("region:images", identityapi.Create).
				buildContext,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := tc.makeCtx(t.Context())

			response := httptest.NewRecorder()
			request := newSnapshotRequest(ctx)

			handler.PostApiV2ServersServerIDSnapshot(response, request, serverName)

			require.Equal(t, http.StatusForbidden, response.Result().StatusCode)
		})
	}
}

func TestServerV2_Snapshot_HappyPath(t *testing.T) {
	t.Parallel()

	const (
		namespace  = "region-test-home"
		orgID      = "org-happy-path"
		serverName = "server1"
	)

	original := &types.Image{
		ID: "image1", // to match the server's image ID
	}
	snapshot := &types.Image{
		Name: "foobar",
		ID:   "snapshot1", // to match the server's image ID
	}

	c := fakeClientWithSchema(t, knownGoodFixture(t, serverName, namespace, orgID)...)

	provider := mock.NewTestMockProvider(t)
	// on the first ask, expect to be asked for the "original" image (that the server is using)
	provider.EXPECT().GetImage(gomock.Any(), orgID, "image1").
		Return(original, nil)

	provider.EXPECT().CreateSnapshot(
		gomock.Any(),
		gomock.AssignableToTypeOf(&regionv1.Identity{}),
		gomock.AssignableToTypeOf(&regionv1.Server{}),
		gomock.AssignableToTypeOf(&types.Image{})).
		Return(snapshot, nil)

	handler := NewServerV2Handler(c, namespace)
	handler.getProvider = providerGetter(provider)

	ctx := newOrganisationACLBuilder(orgID).
		addEndpoint("region:images", identityapi.Create).
		addEndpoint("region:servers", identityapi.Read).
		buildContext(t.Context())

	response := httptest.NewRecorder()
	request := newSnapshotRequest(ctx)

	handler.PostApiV2ServersServerIDSnapshot(response, request, serverName)

	require.Equal(t, http.StatusCreated, response.Result().StatusCode)

	// check that it got the name we asked and the ID we were told
	var read openapi.Image

	requireDeserialiseBody(t, response.Result().Body, &read)
	require.Equal(t, "foobar", read.Metadata.Name)
	require.Equal(t, "snapshot1", read.Metadata.Id)
}
