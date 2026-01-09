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

	identityv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
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

func contextWithOrgPerms(t *testing.T, orgID, endpoint string, ops []identityapi.AclOperation) context.Context {
	t.Helper()

	acl := &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{
			identityapi.AclOrganization{
				Id: orgID,
				Endpoints: &identityapi.AclEndpoints{
					identityapi.AclEndpoint{
						Name:       endpoint,
						Operations: ops,
					},
				},
			},
		},
	}

	return rbac.NewContext(t.Context(), acl)
}

func newServer(t *testing.T, name string) *regionv1.Server {
	t.Helper()

	return &regionv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
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

	ctx := contextWithOrgPerms(t, "org1", "region:servers:v2", nil)
	response := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v2/servers", nil)

	handler.GetApiV2Servers(response, request, openapi.GetApiV2ServersParams{})

	require.Equal(t, http.StatusOK, response.Result().StatusCode)
	assertBodyIsEmptyServerList(t, response.Result().Body)
}

func TestServerV2_NotAllowedList(t *testing.T) {
	t.Parallel()

	namespace := "region-test-home"

	c := fakeClientWithSchema(t, newServer(t, "server1"))
	handler := NewServerV2Handler(c, namespace)

	ctx := contextWithOrgPerms(t, "org1", "region:servers:v2", nil)
	response := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v2/servers", nil)

	handler.GetApiV2Servers(response, request, openapi.GetApiV2ServersParams{})

	require.Equal(t, http.StatusOK, response.Result().StatusCode)
	assertBodyIsEmptyServerList(t, response.Result().Body)
}
