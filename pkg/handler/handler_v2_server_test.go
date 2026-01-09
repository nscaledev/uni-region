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
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	identityv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	regionconstants "github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func newServer(t *testing.T, name, namespace, orgID, projectID string) *regionv1.Server {
	t.Helper()

	return &regionv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				constants.OrganizationLabel:             orgID,
				constants.ProjectLabel:                  projectID,
				regionconstants.ResourceAPIVersionLabel: "2", // necessary for GetRawV2 to "find" this object
			},
		},
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

	c := fakeClientWithSchema(t, newServer(t, "server1", namespace, "org-not-allowed-test", ""))
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

func TestServerV2_Snapshot_NotAllowedWithoutPermissions(t *testing.T) {
	t.Parallel()

	namespace := "region-test-home"
	orgID := "org1"

	c := fakeClientWithSchema(t, newServer(t, "server1", namespace, "org1", ""))
	handler := NewServerV2Handler(c, namespace)

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
			request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v2/servers", nil)

			handler.PostApiV2ServersServerIDSnapshot(response, request, "server1")

			require.Equal(t, http.StatusForbidden, response.Result().StatusCode)
		})
	}
}

func TestServerV2_Snapshot_HappyPath(t *testing.T) {
	t.Parallel()

	namespace := "region-test-home"
	orgID := "org1"
	projectID := "project1"

	c := fakeClientWithSchema(t, newServer(t, "server1", namespace, orgID, projectID))
	handler := NewServerV2Handler(c, namespace)

	ctx := newOrganisationACLBuilder(orgID).
		addEndpoint("region:images", identityapi.Create).
		addEndpoint("region:servers", identityapi.Read).
		buildContext(t.Context())

	response := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v2/servers", nil)

	handler.PostApiV2ServersServerIDSnapshot(response, request, "server1")

	// fixme: this is just testing that it hits the stub, for the minute
	require.Equal(t, http.StatusUnprocessableEntity, response.Result().StatusCode)
}
