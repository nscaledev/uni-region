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

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	identityv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	regionconstants "github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	idstest "github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/openapi"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	mockprovider "github.com/unikorn-cloud/region/pkg/providers/types/mock"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// srvTestImageID is a valid UUID used where a typed image ID is required as API input.
const srvTestImageID = "e1111111-1111-4111-a111-111111111111"

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

func (b *aclBuilder) addProjectEndpoint(projectID, endpoint string, perms ...identityapi.AclOperation) *aclBuilder {
	var projects identityapi.AclProjectList
	if b.org.Projects != nil {
		projects = *b.org.Projects
	}

	projects = append(projects, identityapi.AclProject{
		Id: projectID,
		Endpoints: identityapi.AclEndpoints{
			{Name: endpoint, Operations: perms},
		},
	})

	b.org.Projects = &projects

	return b
}

func (b *aclBuilder) buildContext(ctx context.Context) context.Context {
	return rbac.NewContext(ctx, &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{b.org},
	})
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
				ID: idstest.MustParseImageID(srvTestImageID),
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

	const fixtureProjectID = "22222222-2222-4222-a222-222222222222"

	return []client.Object{
		withMeta(&regionv1.Identity{}, "id1", homeNamespace, projectScopedLabels(orgID, fixtureProjectID, labels{})),
		newServer(t, serverName, homeNamespace, projectScopedLabels(orgID, fixtureProjectID, labels{
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

	ctrl := gomock.NewController(t)
	providers := mockproviders.NewMockProviders(ctrl)

	c := fakeClientWithSchema(t) // NB no objects

	clientArgs := common.ClientArgs{
		Client:    c,
		Namespace: namespace,
		Providers: providers,
	}

	handler := NewServerV2Handler(clientArgs)

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

	ctrl := gomock.NewController(t)
	providers := mockproviders.NewMockProviders(ctrl)

	c := fakeClientWithSchema(t, knownGoodFixture(t, "server1", namespace, "org-not-allowed-test")...)

	clientArgs := common.ClientArgs{
		Client:    c,
		Namespace: namespace,
		Providers: providers,
	}

	handler := NewServerV2Handler(clientArgs)

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

func newServerV2CreateRequest(ctx context.Context, t *testing.T, name, flavorID, imageID, networkID string, infrastructureRef *string) *http.Request {
	t.Helper()

	request := &openapi.ServerV2Create{
		Metadata: coreapi.ResourceWriteMetadata{
			Name: name,
		},
		Spec: openapi.ServerV2CreateSpec{
			FlavorId:          idstest.MustParseFlavorID(flavorID),
			ImageId:           idstest.MustParseImageID(imageID),
			InfrastructureRef: infrastructureRef,
			NetworkId:         idstest.MustParseNetworkID(networkID),
		},
	}

	if infrastructureRef != nil {
		request.Spec.SshInjection = ptr.To(openapi.SshInjectionNone)
	}

	body, err := json.Marshal(request)
	require.NoError(t, err)

	return httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v2/servers", bytes.NewReader(body))
}

type pinnedOnlyFlavorLookupExpectation int

const (
	expectNoPinnedOnlyFlavorLookup pinnedOnlyFlavorLookupExpectation = iota
	expectPinnedOnlyFlavorLookup
)

type pinnedOnlyServerV2CreateFixture struct {
	handler   *ServerV2Handler
	flavorID  string
	networkID string
}

func newPinnedOnlyServerV2CreateFixture(t *testing.T, lookup pinnedOnlyFlavorLookupExpectation) (context.Context, *pinnedOnlyServerV2CreateFixture) {
	t.Helper()

	var (
		namespace = "region-test-home"
		orgID     = "77777777-7777-4777-a777-777777777777"
		projectID = uuid.New().String()
		regionID  = uuid.New().String()
		networkID = uuid.New().String()
		flavorID  = uuid.New().String()
	)

	ctrl := gomock.NewController(t)

	providers := mockproviders.NewMockProviders(ctrl)

	if lookup == expectPinnedOnlyFlavorLookup {
		provider := mockprovider.NewMockProvider(ctrl)
		provider.EXPECT().Flavors(gomock.Any()).Return(types.FlavorList{
			{ID: flavorID, PinnedOnly: true},
		}, nil)

		providers.EXPECT().LookupCloud(regionID).Return(provider, nil)
	}

	net := withMeta(&regionv1.Network{}, networkID, namespace, labels{
		constants.OrganizationLabel:             orgID,
		constants.ProjectLabel:                  projectID,
		regionconstants.RegionLabel:             regionID,
		regionconstants.IdentityLabel:           "id1",
		regionconstants.ResourceAPIVersionLabel: "2",
	})

	c := fakeClientWithSchema(t, net)

	handler := NewServerV2Handler(common.ClientArgs{
		Client:    c,
		Namespace: namespace,
		Providers: providers,
	})

	ctx := newOrganisationACLBuilder(orgID).
		addEndpoint("region:networks:v2", identityapi.Read).
		addProjectEndpoint(projectID, "region:servers", identityapi.Create).
		buildContext(t.Context())

	return ctx, &pinnedOnlyServerV2CreateFixture{
		handler:   handler,
		flavorID:  flavorID,
		networkID: networkID,
	}
}

func TestServerV2_Snapshot_NotAllowedWithoutPermissions(t *testing.T) {
	t.Parallel()

	const (
		namespace  = "region-test-home"
		orgID      = "55555555-5555-4555-a555-555555555555"
		serverName = "a1111111-1111-4111-a111-111111111111"
	)

	ctrl := gomock.NewController(t)

	provider := mockprovider.NewMockProvider(ctrl)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(gomock.Any()).Return(provider, nil)

	c := fakeClientWithSchema(t, knownGoodFixture(t, serverName, namespace, orgID)...)

	clientArgs := common.ClientArgs{
		Client:    c,
		Namespace: namespace,
		Providers: providers,
	}

	handler := NewServerV2Handler(clientArgs)

	// We can't guarantee the order things are done in the handler, and in particular, the region provider
	// may be requested before permissions are checked. So, make sure there is a provider, though we don't
	// expect it to be called.
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

			handler.PostApiV2ServersServerIDSnapshot(response, request, idstest.MustParseServerID(serverName))

			require.Equal(t, http.StatusForbidden, response.Result().StatusCode)
		})
	}
}

func TestServerV2_Snapshot_HappyPath(t *testing.T) {
	t.Parallel()

	const (
		namespace  = "region-test-home"
		orgID      = "66666666-6666-4666-a666-666666666666"
		serverName = "a1111111-1111-4111-a111-111111111111"
	)

	original := &types.Image{
		ID: srvTestImageID, // to match the server's image ID
	}
	snapshot := &types.Image{
		Name: "foobar",    // matches the request
		ID:   "snapshot1", // to match the server's image ID
	}

	c := fakeClientWithSchema(t, knownGoodFixture(t, serverName, namespace, orgID)...)

	ctrl := gomock.NewController(t)

	provider := mockprovider.NewMockProvider(ctrl)
	provider.EXPECT().GetImage(gomock.Any(), identityids.MustParseOrganizationID(orgID), idstest.MustParseImageID(srvTestImageID)).Return(original, nil)
	provider.EXPECT().CreateSnapshot(
		gomock.Any(),
		gomock.AssignableToTypeOf(&regionv1.Identity{}),
		gomock.AssignableToTypeOf(&regionv1.Server{}),
		gomock.AssignableToTypeOf(&types.Image{})).
		DoAndReturn(func(_ context.Context, _ *regionv1.Identity, _ *regionv1.Server, image *types.Image) (*types.Image, error) {
			s := *snapshot
			s.Tags = image.Tags // copy these over, to simulate a round-trip through the provider.

			return &s, nil
		})

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(gomock.Any()).Return(provider, nil)

	clientArgs := common.ClientArgs{
		Client:    c,
		Namespace: namespace,
		Providers: providers,
	}

	handler := NewServerV2Handler(clientArgs)

	ctx := newOrganisationACLBuilder(orgID).
		addEndpoint("region:images", identityapi.Create).
		addEndpoint("region:servers", identityapi.Read).
		buildContext(t.Context())

	response := httptest.NewRecorder()
	request := newSnapshotRequest(ctx)

	handler.PostApiV2ServersServerIDSnapshot(response, request, idstest.MustParseServerID(serverName))

	require.Equal(t, http.StatusCreated, response.Result().StatusCode)

	// check that it got the name we asked and the ID we were told
	var read openapi.Image

	requireDeserialiseBody(t, response.Result().Body, &read)
	require.Equal(t, "foobar", read.Metadata.Name)
	require.Equal(t, "snapshot1", read.Metadata.Id)
	require.NotNil(t, read.Metadata.Tags)
	require.Contains(t, *read.Metadata.Tags, coreapi.Tag{
		Name:  regionconstants.ImageSourceTag,
		Value: regionconstants.ImageSourceSnapshot,
	})
}

func TestServerV2_Create_PinnedOnlyFlavorWithoutInfrastructureRef(t *testing.T) {
	t.Parallel()

	ctx, fixture := newPinnedOnlyServerV2CreateFixture(t, expectPinnedOnlyFlavorLookup)

	response := httptest.NewRecorder()
	request := newServerV2CreateRequest(ctx, t, "test-server", fixture.flavorID, srvTestImageID, fixture.networkID, nil)

	fixture.handler.PostApiV2Servers(response, request)

	require.Equal(t, http.StatusUnprocessableEntity, response.Result().StatusCode)

	var errorResponse coreapi.Error

	requireDeserialiseBody(t, response.Result().Body, &errorResponse)
	require.Equal(t, coreapi.UnprocessableContent, errorResponse.Error)
	require.Equal(t, "flavor requires infrastructureRef to be set", errorResponse.ErrorDescription)
}

func TestServerV2_Create_PinnedOnlyFlavorWithInfrastructureRef(t *testing.T) {
	t.Parallel()

	ctx, fixture := newPinnedOnlyServerV2CreateFixture(t, expectNoPinnedOnlyFlavorLookup)
	ctx = withPrincipal(ctx)
	infrastructureRef := "node-42"

	response := httptest.NewRecorder()
	request := newServerV2CreateRequest(ctx, t, "test-server", fixture.flavorID, srvTestImageID, fixture.networkID, &infrastructureRef)

	fixture.handler.PostApiV2Servers(response, request)

	require.Equal(t, http.StatusCreated, response.Result().StatusCode)

	var read openapi.ServerV2Read

	requireDeserialiseBody(t, response.Result().Body, &read)
	require.Equal(t, "test-server", read.Metadata.Name)
	require.Equal(t, fixture.flavorID, read.Spec.FlavorId.String())
	require.NotNil(t, read.Status.InfrastructureRef)
	require.Equal(t, infrastructureRef, *read.Status.InfrastructureRef)
}
