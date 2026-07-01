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

package network_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	identitymock "github.com/unikorn-cloud/identity/pkg/openapi/mock"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	networkhandler "github.com/unikorn-cloud/region/pkg/handler/network"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/openapi"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"
	networkprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/network"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace    = "test-namespace"
	testRegionID     = "55555555-5555-4555-a555-555555555555"
	testOrganization = "4d3db1f4-6e01-4a5e-a37f-91d55b5a07ae"
	testProject      = "9b1e7c82-3d4f-4a6b-b5e2-c8f1a2d3e4f5"
	testAllocationID = "a1b2c3d4-e5f6-4890-abcd-ef1234567890"
	testActor        = "test@example.com"
	testTokenSubject = "token-actor"
)

func testClient(t *testing.T, objects ...runtime.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, regionv1.AddToScheme(scheme))

	restMapper := apimeta.NewDefaultRESTMapper([]schema.GroupVersion{regionv1.SchemeGroupVersion})
	restMapper.Add(regionv1.SchemeGroupVersion.WithKind("Network"), apimeta.RESTScopeNamespace)

	builder := fake.NewClientBuilder().WithScheme(scheme).WithRESTMapper(restMapper)
	for _, object := range objects {
		builder = builder.WithRuntimeObjects(object)
	}

	return builder.Build()
}

func testRegion() *regionv1.Region {
	return &regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testRegionID,
			Namespace: testNamespace,
		},
		Spec: regionv1.RegionSpec{
			Provider: regionv1.ProviderOpenstack,
		},
	}
}

func networkCreateRequest() *openapi.NetworkV2Create {
	return &openapi.NetworkV2Create{
		Metadata: coreapi.ResourceWriteMetadata{
			Name: "test-network",
		},
		Spec: openapi.NetworkV2CreateSpec{
			OrganizationId: testOrganization,
			ProjectId:      testProject,
			RegionId:       regionids.MustParseRegionID(testRegionID),
			Prefix:         "10.0.0.0/24",
			DnsNameservers: []openapi.Ipv4Address{"8.8.8.8"},
		},
	}
}

func networkCreateACL() *identityapi.Acl {
	return &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{
			{
				Id: testOrganization,
				Projects: &identityapi.AclProjectList{
					{
						Id: testProject,
						Endpoints: identityapi.AclEndpoints{
							{
								Name:       "region:networks:v2",
								Operations: identityapi.AclOperations{identityapi.Create},
							},
						},
					},
				},
			},
		},
	}
}

func withPrincipal(ctx context.Context) context.Context {
	ctx = authorization.NewContext(ctx, &authorization.Info{
		Userinfo: &identityapi.Userinfo{
			Sub: testTokenSubject,
		},
	})

	return principal.NewContext(ctx, &principal.Principal{
		Actor: testActor,
	})
}

func expectAllocationCreate(t *testing.T, mockIdentity *identitymock.MockClientWithResponsesInterface) {
	t.Helper()

	mockIdentity.EXPECT().
		PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsWithResponse(gomock.Any(), identityids.MustParseOrganizationID(testOrganization), identityids.MustParseProjectID(testProject), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ identityids.OrganizationID, _ identityids.ProjectID, body identityapi.AllocationWrite, _ ...identityapi.RequestEditorFn) (*identityapi.PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsResponse, error) {
			require.Equal(t, identityapi.ResourceAllocationList{
				{Kind: "networks", Committed: 1, Reserved: 0},
			}, body.Spec.Allocations)

			return &identityapi.PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsResponse{
				HTTPResponse: &http.Response{StatusCode: http.StatusCreated},
				JSON201: &identityapi.AllocationRead{
					Metadata: coreapi.ProjectScopedResourceReadMetadata{
						Id:             testAllocationID,
						OrganizationId: testOrganization,
						ProjectId:      testProject,
					},
				},
			}, nil
		})
}

func expectAllocationDelete(mockIdentity *identitymock.MockClientWithResponsesInterface) {
	mockIdentity.EXPECT().
		DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDWithResponse(gomock.Any(), identityids.MustParseOrganizationID(testOrganization), identityids.MustParseProjectID(testProject), identityids.MustParseAllocationID(testAllocationID)).
		Return(&identityapi.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusAccepted},
		}, nil)
}

func getNetwork(t *testing.T, cli client.Client, networkID string) *regionv1.Network {
	t.Helper()

	network := &regionv1.Network{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: testNamespace, Name: networkID}, network))

	return network
}

func TestDeprovision_UnreadyIdentityDeletesAllocation(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	region := testRegion()
	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().Region(gomock.Any()).Return(region, nil)
	// Deprovision now always delegates to the provider; the provider is
	// responsible for no-opping when the identity was never realized.
	provider.EXPECT().DeleteNetwork(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil).Times(2)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectAllocationCreate(t, mockIdentity)
	expectAllocationDelete(mockIdentity)

	cli := testClient(t, region)
	handlerClient := networkhandler.New(common.ClientArgs{
		Client:    cli,
		Namespace: testNamespace,
		Providers: providers,
		Identity:  mockIdentity,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), networkCreateACL()))
	created, err := handlerClient.CreateV2(ctx, networkCreateRequest())
	require.NoError(t, err)

	network := getNetwork(t, cli, created.Metadata.Id)
	require.Equal(t, constants.MarshalAPIVersion(2), network.Labels[constants.ResourceAPIVersionLabel])
	require.Equal(t, testAllocationID, network.Annotations[coreconstants.AllocationAnnotation])
	require.Equal(t, testOrganization, network.Labels[coreconstants.OrganizationPrincipalLabel])
	require.Equal(t, testProject, network.Labels[coreconstants.ProjectPrincipalLabel])
	require.Nil(t, network.Status.Openstack)

	identity := &regionv1.Identity{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{
		Namespace: testNamespace,
		Name:      network.Labels[constants.IdentityLabel],
	}, identity))

	condition, err := identity.StatusConditionRead(unikornv1core.ConditionAvailable)
	require.Error(t, err)
	require.Nil(t, condition)

	provisioner := networkprovisioner.NewForTest(network, providers, mockIdentity)
	require.NoError(t, provisioner.Deprovision(coreclient.NewContext(t.Context(), cli)))
}
