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

package loadbalancer_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
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
	"github.com/unikorn-cloud/region/pkg/handler/loadbalancer"
	"github.com/unikorn-cloud/region/pkg/openapi"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	lbOrganizationID = "foo"
	lbProjectID      = "bar"
	lbRegionID       = "region-1"
	lbIdentityID     = "identity-1"
	lbNamespace      = "test-namespace"
	lbNetworkID      = "network-1"
	lbLoadBalancerID = "lb-1"
	lbAllocationID   = "allocation-1"
)

func newLBFakeClientBuilder(t *testing.T, objects ...runtime.Object) *fake.ClientBuilder {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, regionv1.AddToScheme(scheme))

	// These tests exercise identity allocation creation/update, which calls
	// manager.GenerateResourceReference and needs RESTMapping for custom
	// resources. The fake client defaults to an empty REST mapper.
	// A REST mapper with entries for referenced types is assumed by
	// manager.GenerateResourceReference.
	restMapper := apimeta.NewDefaultRESTMapper([]schema.GroupVersion{regionv1.SchemeGroupVersion})
	restMapper.Add(regionv1.SchemeGroupVersion.WithKind("Network"), apimeta.RESTScopeNamespace)
	restMapper.Add(regionv1.SchemeGroupVersion.WithKind("LoadBalancer"), apimeta.RESTScopeNamespace)

	builder := fake.NewClientBuilder().WithScheme(scheme).WithRESTMapper(restMapper)

	for _, object := range objects {
		builder = builder.WithRuntimeObjects(object)
	}

	return builder
}

func getLoadBalancer(t *testing.T, cli client.Client, loadBalancerID string) *regionv1.LoadBalancer {
	t.Helper()

	resource := &regionv1.LoadBalancer{}

	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: lbNamespace, Name: loadBalancerID}, resource))

	return resource
}

func ipAddress(t *testing.T, value string) unikornv1core.IPv4Address {
	t.Helper()

	ip := net.ParseIP(value)
	require.NotNil(t, ip)

	return unikornv1core.IPv4Address{IP: ip.To4()}
}

func ipPrefix(t *testing.T, value string) unikornv1core.IPv4Prefix {
	t.Helper()

	_, prefix, err := net.ParseCIDR(value)
	require.NoError(t, err)

	return unikornv1core.IPv4Prefix{IPNet: *prefix}
}

func testLBNetworkWithProject(projectID string) *regionv1.Network {
	_, prefix, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		panic(err)
	}

	return &regionv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:            lbNetworkID,
			Namespace:       lbNamespace,
			ResourceVersion: "1",
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   lbOrganizationID,
				coreconstants.ProjectLabel:        projectID,
				constants.RegionLabel:             lbRegionID,
				constants.IdentityLabel:           lbIdentityID,
				constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
			},
		},
		Spec: regionv1.NetworkSpec{
			Prefix: &unikornv1core.IPv4Prefix{IPNet: *prefix},
		},
	}
}

func testLoadBalancerResource(t *testing.T, publicIP bool) *regionv1.LoadBalancer {
	t.Helper()

	idleTimeout := 30

	return &regionv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{
			Name:            lbLoadBalancerID,
			Namespace:       lbNamespace,
			ResourceVersion: "1",
			Labels: map[string]string{
				coreconstants.OrganizationLabel:          lbOrganizationID,
				coreconstants.ProjectLabel:               lbProjectID,
				coreconstants.OrganizationPrincipalLabel: lbOrganizationID,
				coreconstants.ProjectPrincipalLabel:      lbProjectID,
				constants.RegionLabel:                    lbRegionID,
				constants.IdentityLabel:                  lbIdentityID,
				constants.NetworkLabel:                   lbNetworkID,
				constants.ResourceAPIVersionLabel:        constants.MarshalAPIVersion(2),
			},
			Annotations: map[string]string{
				coreconstants.AllocationAnnotation:       lbAllocationID,
				coreconstants.CreatorAnnotation:          "token-actor",
				coreconstants.CreatorPrincipalAnnotation: "test@example.com",
			},
		},
		Spec: regionv1.LoadBalancerSpec{
			RequestedVIPAddress: ptr.To(ipAddress(t, "10.0.0.50")),
			PublicIP:            publicIP,
			Listeners: []regionv1.LoadBalancerListener{
				{
					Name:               "http",
					Protocol:           regionv1.LoadBalancerListenerProtocolTCP,
					Port:               80,
					AllowedCIDRs:       []unikornv1core.IPv4Prefix{ipPrefix(t, "0.0.0.0/0")},
					IdleTimeoutSeconds: &idleTimeout,
					Pool: regionv1.LoadBalancerPool{
						ProxyProtocolV2: false,
						Members: []regionv1.LoadBalancerMember{
							{
								Address: ipAddress(t, "10.0.0.10"),
								Port:    8080,
							},
						},
						HealthCheck: &regionv1.LoadBalancerHealthCheck{
							IntervalSeconds:    10,
							TimeoutSeconds:     5,
							HealthyThreshold:   2,
							UnhealthyThreshold: 2,
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
			Sub: "token-actor",
		},
	})

	return principal.NewContext(ctx, &principal.Principal{
		Actor: "test@example.com",
	})
}

func projectACL(loadBalancerOps ...identityapi.AclOperation) *identityapi.Acl {
	endpoints := identityapi.AclEndpoints{
		{
			Name:       "region:networks:v2",
			Operations: identityapi.AclOperations{identityapi.Read},
		},
	}

	if len(loadBalancerOps) != 0 {
		endpoints = append(endpoints, identityapi.AclEndpoint{
			Name:       "region:loadbalancers:v2",
			Operations: loadBalancerOps,
		})
	}

	return &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{
			{
				Id: lbOrganizationID,
				Projects: &identityapi.AclProjectList{
					{
						Id:        lbProjectID,
						Endpoints: endpoints,
					},
				},
			},
		},
	}
}

func orgScopeCreateACL() *identityapi.Acl {
	return &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{
			{
				Id: lbOrganizationID,
				Endpoints: &identityapi.AclEndpoints{
					{
						Name:       "region:networks:v2",
						Operations: identityapi.AclOperations{identityapi.Read},
					},
					{
						Name:       "region:loadbalancers:v2",
						Operations: identityapi.AclOperations{identityapi.Create},
					},
				},
			},
		},
	}
}

func minimalCreateRequest() *openapi.LoadBalancerV2Create {
	publicIP := true
	vipAddress := openapi.Ipv4Address("10.0.0.50")
	proxyProtocolV2 := false
	idleTimeoutSeconds := 30
	intervalSeconds := 10
	timeoutSeconds := 5
	healthyThreshold := 2
	unhealthyThreshold := 2

	return &openapi.LoadBalancerV2Create{
		Metadata: coreapi.ResourceWriteMetadata{
			Name: "web-lb",
		},
		Spec: openapi.LoadBalancerV2CreateSpec{
			OrganizationId: lbOrganizationID,
			ProjectId:      lbProjectID,
			RegionId:       lbRegionID,
			NetworkId:      lbNetworkID,
			PublicIP:       &publicIP,
			VipAddress:     &vipAddress,
			Listeners: []openapi.LoadBalancerListenerV2{
				{
					Name:               "http",
					Protocol:           openapi.LoadBalancerListenerProtocolV2Tcp,
					Port:               80,
					AllowedCidrs:       &[]string{"0.0.0.0/0"},
					IdleTimeoutSeconds: &idleTimeoutSeconds,
					Pool: openapi.LoadBalancerPoolV2{
						ProxyProtocolV2: &proxyProtocolV2,
						Members: []openapi.LoadBalancerMemberV2{
							{
								Address: "10.0.0.10",
								Port:    8080,
							},
						},
						HealthCheck: &openapi.LoadBalancerHealthCheckV2{
							IntervalSeconds:    &intervalSeconds,
							TimeoutSeconds:     &timeoutSeconds,
							HealthyThreshold:   &healthyThreshold,
							UnhealthyThreshold: &unhealthyThreshold,
						},
					},
				},
			},
		},
	}
}

func minimalUpdateRequest() *openapi.LoadBalancerV2Update {
	request := minimalCreateRequest()

	return &openapi.LoadBalancerV2Update{
		Metadata: request.Metadata,
		Spec: openapi.LoadBalancerV2Spec{
			PublicIP:  request.Spec.PublicIP,
			Listeners: request.Spec.Listeners,
		},
	}
}

func expectAllocationCreate(t *testing.T, mockIdentity *identitymock.MockClientWithResponsesInterface, expected identityapi.ResourceAllocationList) {
	t.Helper()

	mockIdentity.EXPECT().
		PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsWithResponse(gomock.Any(), lbOrganizationID, lbProjectID, gomock.Any()).
		DoAndReturn(func(_ context.Context, _, _ string, body identityapi.AllocationWrite, _ ...identityapi.RequestEditorFn) (*identityapi.PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsResponse, error) {
			require.Equal(t, expected, body.Spec.Allocations)

			return &identityapi.PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsResponse{
				HTTPResponse: &http.Response{StatusCode: http.StatusCreated},
				JSON201: &identityapi.AllocationRead{
					Metadata: coreapi.ProjectScopedResourceReadMetadata{
						Id:             lbAllocationID,
						Name:           "allocation",
						OrganizationId: lbOrganizationID,
						ProjectId:      lbProjectID,
					},
				},
			}, nil
		})
}

func expectAllocationUpdate(t *testing.T, mockIdentity *identitymock.MockClientWithResponsesInterface, expected identityapi.ResourceAllocationList) {
	t.Helper()

	mockIdentity.EXPECT().
		PutApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDWithResponse(gomock.Any(), lbOrganizationID, lbProjectID, lbAllocationID, gomock.Any()).
		DoAndReturn(func(_ context.Context, _, _, _ string, body identityapi.AllocationWrite, _ ...identityapi.RequestEditorFn) (*identityapi.PutApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDResponse, error) {
			require.Equal(t, expected, body.Spec.Allocations)

			return &identityapi.PutApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDResponse{
				HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			}, nil
		})
}

func TestCreateV2(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectAllocationCreate(t, mockIdentity, identityapi.ResourceAllocationList{
		{Kind: "loadbalancers", Committed: 1, Reserved: 0},
		{Kind: "publicips", Committed: 1, Reserved: 0},
	})

	network := testLBNetworkWithProject(lbProjectID)
	cli := newLBFakeClientBuilder(t, network).Build()
	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
		Identity:  mockIdentity,
	})

	ctx := withPrincipal(rbac.NewContext(t.Context(), projectACL(identityapi.Create)))

	result, err := client.CreateV2(ctx, minimalCreateRequest())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Spec.PublicIP)
	require.True(t, *result.Spec.PublicIP)
	require.Equal(t, lbNetworkID, result.Status.NetworkId)

	resource := getLoadBalancer(t, cli, result.Metadata.Id)
	require.Equal(t, lbAllocationID, resource.Annotations[coreconstants.AllocationAnnotation])
	require.True(t, resource.Spec.PublicIP)
	require.NotNil(t, resource.Spec.RequestedVIPAddress)
}

func TestCreateV2AllowsEmptyPoolMembers(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectAllocationCreate(t, mockIdentity, identityapi.ResourceAllocationList{
		{Kind: "loadbalancers", Committed: 1, Reserved: 0},
		{Kind: "publicips", Committed: 1, Reserved: 0},
	})

	network := testLBNetworkWithProject(lbProjectID)
	cli := newLBFakeClientBuilder(t, network).Build()
	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
		Identity:  mockIdentity,
	})

	request := minimalCreateRequest()
	request.Spec.Listeners[0].Pool.Members = []openapi.LoadBalancerMemberV2{}

	result, err := client.CreateV2(withPrincipal(rbac.NewContext(t.Context(), projectACL(identityapi.Create))), request)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Spec.Listeners[0].Pool.Members)
	require.Empty(t, result.Spec.Listeners[0].Pool.Members)

	resource := getLoadBalancer(t, cli, result.Metadata.Id)
	require.NotNil(t, resource.Spec.Listeners[0].Pool.Members)
	require.Empty(t, resource.Spec.Listeners[0].Pool.Members)
}

func TestCreateV2RejectsVIPAddressOutsideNetworkCIDR(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	network := testLBNetworkWithProject(lbProjectID)
	cli := newLBFakeClientBuilder(t, network).Build()
	lbClient := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
		Identity:  mockIdentity,
	})

	request := minimalCreateRequest()
	vipAddress := openapi.Ipv4Address("10.0.1.50")
	request.Spec.VipAddress = &vipAddress

	_, err := lbClient.CreateV2(withPrincipal(rbac.NewContext(t.Context(), projectACL(identityapi.Create))), request)
	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)

	loadBalancers := &regionv1.LoadBalancerList{}
	require.NoError(t, cli.List(t.Context(), loadBalancers, client.InNamespace(lbNamespace)))
	require.Empty(t, loadBalancers.Items)
}

func TestCreateV2AllowsOmittedVIPAddress(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectAllocationCreate(t, mockIdentity, identityapi.ResourceAllocationList{
		{Kind: "loadbalancers", Committed: 1, Reserved: 0},
		{Kind: "publicips", Committed: 1, Reserved: 0},
	})

	network := testLBNetworkWithProject(lbProjectID)
	cli := newLBFakeClientBuilder(t, network).Build()
	lbClient := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
		Identity:  mockIdentity,
	})

	request := minimalCreateRequest()
	request.Spec.VipAddress = nil

	result, err := lbClient.CreateV2(withPrincipal(rbac.NewContext(t.Context(), projectACL(identityapi.Create))), request)
	require.NoError(t, err)
	require.NotNil(t, result)

	resource := getLoadBalancer(t, cli, result.Metadata.Id)
	require.Nil(t, resource.Spec.RequestedVIPAddress)
}

func TestListV2(t *testing.T) {
	t.Parallel()

	resource := testLoadBalancerResource(t, true)
	cli := newLBFakeClientBuilder(t, resource).Build()

	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
	})

	result, err := client.ListV2(rbac.NewContext(t.Context(), projectACL(identityapi.Read)), openapi.GetApiV2LoadbalancersParams{})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, lbLoadBalancerID, result[0].Metadata.Id)
	require.Equal(t, lbNetworkID, result[0].Status.NetworkId)
	require.NotNil(t, result[0].Spec.PublicIP)
	require.True(t, *result[0].Spec.PublicIP)
}

func TestGetV2(t *testing.T) {
	t.Parallel()

	resource := testLoadBalancerResource(t, true)
	cli := newLBFakeClientBuilder(t, resource).Build()

	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
	})

	result, err := client.GetV2(rbac.NewContext(t.Context(), projectACL(identityapi.Read)), lbLoadBalancerID)
	require.NoError(t, err)
	require.Equal(t, lbLoadBalancerID, result.Metadata.Id)
	require.Equal(t, lbRegionID, result.Status.RegionId)
}

func TestGetV2ReturnsEmptyPoolMembers(t *testing.T) {
	t.Parallel()

	resource := testLoadBalancerResource(t, true)
	resource.Spec.Listeners[0].Pool.Members = []regionv1.LoadBalancerMember{}

	cli := newLBFakeClientBuilder(t, resource).Build()
	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
	})

	result, err := client.GetV2(rbac.NewContext(t.Context(), projectACL(identityapi.Read)), lbLoadBalancerID)
	require.NoError(t, err)
	require.NotNil(t, result.Spec.Listeners[0].Pool.Members)
	require.Empty(t, result.Spec.Listeners[0].Pool.Members)

	data, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(data), "\"members\":[]")
}

func TestUpdateV2(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectAllocationUpdate(t, mockIdentity, identityapi.ResourceAllocationList{
		{Kind: "loadbalancers", Committed: 1, Reserved: 0},
		{Kind: "publicips", Committed: 1, Reserved: 0},
	})

	network := testLBNetworkWithProject(lbProjectID)
	resource := testLoadBalancerResource(t, false)
	cli := newLBFakeClientBuilder(t, network, resource).Build()

	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
		Identity:  mockIdentity,
	})

	request := minimalUpdateRequest()
	publicIP := true
	request.Spec.PublicIP = &publicIP

	ctx := withPrincipal(rbac.NewContext(t.Context(), projectACL(identityapi.Read, identityapi.Update)))

	result, err := client.UpdateV2(ctx, lbLoadBalancerID, request)
	require.NoError(t, err)
	require.NotNil(t, result.Spec.PublicIP)
	require.True(t, *result.Spec.PublicIP)

	updated := getLoadBalancer(t, cli, lbLoadBalancerID)
	require.True(t, updated.Spec.PublicIP)
}

func TestUpdateV2AllowsEmptyPoolMembers(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectAllocationUpdate(t, mockIdentity, identityapi.ResourceAllocationList{
		{Kind: "loadbalancers", Committed: 1, Reserved: 0},
	})

	network := testLBNetworkWithProject(lbProjectID)
	resource := testLoadBalancerResource(t, false)
	cli := newLBFakeClientBuilder(t, network, resource).Build()

	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
		Identity:  mockIdentity,
	})

	request := minimalUpdateRequest()
	publicIP := false
	request.Spec.PublicIP = &publicIP
	request.Spec.Listeners[0].Pool.Members = []openapi.LoadBalancerMemberV2{}

	result, err := client.UpdateV2(withPrincipal(rbac.NewContext(t.Context(), projectACL(identityapi.Read, identityapi.Update))), lbLoadBalancerID, request)
	require.NoError(t, err)
	require.NotNil(t, result.Spec.Listeners[0].Pool.Members)
	require.Empty(t, result.Spec.Listeners[0].Pool.Members)

	updated := getLoadBalancer(t, cli, lbLoadBalancerID)
	require.NotNil(t, updated.Spec.Listeners[0].Pool.Members)
	require.Empty(t, updated.Spec.Listeners[0].Pool.Members)
}

func TestDeleteV2(t *testing.T) {
	t.Parallel()

	resource := testLoadBalancerResource(t, true)
	cli := newLBFakeClientBuilder(t, resource).Build()

	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
	})

	ctx := rbac.NewContext(t.Context(), projectACL(identityapi.Read, identityapi.Delete))

	require.NoError(t, client.DeleteV2(ctx, lbLoadBalancerID))

	_, err := client.GetV2Raw(ctx, lbLoadBalancerID)
	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

func TestCreateV2RBACOrgScopedProjectNotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	mockIdentity.EXPECT().
		GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), lbOrganizationID, "missing-project").
		Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
		}, nil)

	network := testLBNetworkWithProject("missing-project")
	cli := newLBFakeClientBuilder(t, network).Build()
	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
		Identity:  mockIdentity,
	})

	request := minimalCreateRequest()
	request.Spec.ProjectId = "missing-project"

	_, err := client.CreateV2(rbac.NewContext(t.Context(), orgScopeCreateACL()), request)
	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

func TestCreateV2NoCreatePermission(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	network := testLBNetworkWithProject(lbProjectID)
	cli := newLBFakeClientBuilder(t, network).Build()
	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
		Identity:  mockIdentity,
	})

	_, err := client.CreateV2(rbac.NewContext(t.Context(), projectACL()), minimalCreateRequest())
	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err), "expected forbidden, got: %v", err)
}

func TestCreateV2ScopeMismatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*openapi.LoadBalancerV2Create)
	}{
		{
			name: "Organization",
			mutate: func(request *openapi.LoadBalancerV2Create) {
				request.Spec.OrganizationId = "other-org"
			},
		},
		{
			name: "Project",
			mutate: func(request *openapi.LoadBalancerV2Create) {
				request.Spec.ProjectId = "other-project"
			},
		},
		{
			name: "Region",
			mutate: func(request *openapi.LoadBalancerV2Create) {
				request.Spec.RegionId = "other-region"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			network := testLBNetworkWithProject(lbProjectID)
			cli := newLBFakeClientBuilder(t, network).Build()
			client := loadbalancer.New(common.ClientArgs{
				Client:    cli,
				Namespace: lbNamespace,
			})

			request := minimalCreateRequest()
			test.mutate(request)

			_, err := client.CreateV2(withPrincipal(rbac.NewContext(t.Context(), projectACL(identityapi.Create))), request)
			require.Error(t, err)
			require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
		})
	}
}

func TestCreateV2MalformedVIPAddress(t *testing.T) {
	t.Parallel()

	network := testLBNetworkWithProject(lbProjectID)
	cli := newLBFakeClientBuilder(t, network).Build()
	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
	})

	request := minimalCreateRequest()
	vipAddress := openapi.Ipv4Address("definitely-not-an-ip")
	request.Spec.VipAddress = &vipAddress

	_, err := client.CreateV2(withPrincipal(rbac.NewContext(t.Context(), projectACL(identityapi.Create))), request)
	require.Error(t, err)
	require.True(t, coreerrors.IsBadRequest(err), "expected 400 bad request, got: %v", err)
}

func TestCreateV2RejectsUDPProxyProtocolV2(t *testing.T) {
	t.Parallel()

	network := testLBNetworkWithProject(lbProjectID)
	cli := newLBFakeClientBuilder(t, network).Build()
	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
	})

	request := minimalCreateRequest()
	request.Spec.Listeners[0].Protocol = openapi.LoadBalancerListenerProtocolV2Udp
	proxyProtocolV2 := true
	request.Spec.Listeners[0].Pool.ProxyProtocolV2 = &proxyProtocolV2
	request.Spec.Listeners[0].IdleTimeoutSeconds = nil

	_, err := client.CreateV2(withPrincipal(rbac.NewContext(t.Context(), projectACL(identityapi.Create))), request)
	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
}

func TestCreateV2RejectsUDPIdleTimeout(t *testing.T) {
	t.Parallel()

	network := testLBNetworkWithProject(lbProjectID)
	cli := newLBFakeClientBuilder(t, network).Build()
	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
	})

	request := minimalCreateRequest()
	request.Spec.Listeners[0].Protocol = openapi.LoadBalancerListenerProtocolV2Udp

	_, err := client.CreateV2(withPrincipal(rbac.NewContext(t.Context(), projectACL(identityapi.Create))), request)
	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
}

func TestCreateV2RejectsInvalidHealthCheckWindow(t *testing.T) {
	t.Parallel()

	network := testLBNetworkWithProject(lbProjectID)
	cli := newLBFakeClientBuilder(t, network).Build()
	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
	})

	request := minimalCreateRequest()
	timeoutSeconds := 10
	request.Spec.Listeners[0].Pool.HealthCheck.TimeoutSeconds = &timeoutSeconds

	_, err := client.CreateV2(withPrincipal(rbac.NewContext(t.Context(), projectACL(identityapi.Create))), request)
	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
}

func TestCreateV2RejectsDuplicateListenerNames(t *testing.T) {
	t.Parallel()

	network := testLBNetworkWithProject(lbProjectID)
	cli := newLBFakeClientBuilder(t, network).Build()
	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
	})

	request := minimalCreateRequest()
	request.Spec.Listeners = append(request.Spec.Listeners, request.Spec.Listeners[0])
	request.Spec.Listeners[1].Port = 81

	_, err := client.CreateV2(withPrincipal(rbac.NewContext(t.Context(), projectACL(identityapi.Create))), request)
	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
}

func TestCreateV2RejectsListenerNameStartingWithDigit(t *testing.T) {
	t.Parallel()

	network := testLBNetworkWithProject(lbProjectID)
	cli := newLBFakeClientBuilder(t, network).Build()
	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
	})

	request := minimalCreateRequest()
	request.Spec.Listeners[0].Name = "1http"

	_, err := client.CreateV2(withPrincipal(rbac.NewContext(t.Context(), projectACL(identityapi.Create))), request)
	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
}

func TestCreateV2RejectsDuplicateListenerProtocolPorts(t *testing.T) {
	t.Parallel()

	network := testLBNetworkWithProject(lbProjectID)
	cli := newLBFakeClientBuilder(t, network).Build()
	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
	})

	request := minimalCreateRequest()
	request.Spec.Listeners = append(request.Spec.Listeners, request.Spec.Listeners[0])
	request.Spec.Listeners[1].Name = "http-copy"

	_, err := client.CreateV2(withPrincipal(rbac.NewContext(t.Context(), projectACL(identityapi.Create))), request)
	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
}

func TestCreateV2RejectsDuplicatePoolMembers(t *testing.T) {
	t.Parallel()

	network := testLBNetworkWithProject(lbProjectID)
	cli := newLBFakeClientBuilder(t, network).Build()
	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
	})

	request := minimalCreateRequest()
	request.Spec.Listeners[0].Pool.Members = append(request.Spec.Listeners[0].Pool.Members, request.Spec.Listeners[0].Pool.Members[0])

	_, err := client.CreateV2(withPrincipal(rbac.NewContext(t.Context(), projectACL(identityapi.Create))), request)
	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
}

func TestUpdateV2RejectsListenerProtocolMutation(t *testing.T) {
	t.Parallel()

	network := testLBNetworkWithProject(lbProjectID)
	resource := testLoadBalancerResource(t, false)
	cli := newLBFakeClientBuilder(t, network, resource).Build()
	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
	})

	request := minimalUpdateRequest()
	request.Spec.PublicIP = ptr.To(false)
	request.Spec.Listeners[0].Protocol = openapi.LoadBalancerListenerProtocolV2Udp
	request.Spec.Listeners[0].IdleTimeoutSeconds = nil

	_, err := client.UpdateV2(withPrincipal(rbac.NewContext(t.Context(), projectACL(identityapi.Read, identityapi.Update))), lbLoadBalancerID, request)
	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
}

func TestUpdateV2RejectsListenerPortMutation(t *testing.T) {
	t.Parallel()

	network := testLBNetworkWithProject(lbProjectID)
	resource := testLoadBalancerResource(t, false)
	cli := newLBFakeClientBuilder(t, network, resource).Build()
	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
	})

	request := minimalUpdateRequest()
	request.Spec.PublicIP = ptr.To(false)
	request.Spec.Listeners[0].Port = 81

	_, err := client.UpdateV2(withPrincipal(rbac.NewContext(t.Context(), projectACL(identityapi.Read, identityapi.Update))), lbLoadBalancerID, request)
	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
}

func TestDeleteV2AlreadyDeleting(t *testing.T) {
	t.Parallel()

	resource := testLoadBalancerResource(t, true)
	now := metav1.NewTime(time.Now())
	resource.DeletionTimestamp = &now
	resource.Finalizers = []string{"loadbalancers.region.unikorn-cloud.org/test"}

	cli := newLBFakeClientBuilder(t, resource).Build()
	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
	})

	err := client.DeleteV2(rbac.NewContext(t.Context(), projectACL(identityapi.Read, identityapi.Delete)), lbLoadBalancerID)
	require.NoError(t, err)
}

func TestUpdateV2ConflictRollsBackAllocation(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	expectAllocationUpdate(t, mockIdentity, identityapi.ResourceAllocationList{
		{Kind: "loadbalancers", Committed: 1, Reserved: 0},
		{Kind: "publicips", Committed: 1, Reserved: 0},
	})
	expectAllocationUpdate(t, mockIdentity, identityapi.ResourceAllocationList{
		{Kind: "loadbalancers", Committed: 1, Reserved: 0},
	})

	network := testLBNetworkWithProject(lbProjectID)
	resource := testLoadBalancerResource(t, false)
	cli := newLBFakeClientBuilder(t, network, resource).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(_ context.Context, _ client.WithWatch, _ client.Object, _ client.Patch, _ ...client.PatchOption) error {
				return apierrors.NewConflict(schema.GroupResource{Group: regionv1.GroupName, Resource: "loadbalancers"}, lbLoadBalancerID, nil)
			},
		}).
		Build()

	client := loadbalancer.New(common.ClientArgs{
		Client:    cli,
		Namespace: lbNamespace,
		Identity:  mockIdentity,
	})

	request := minimalUpdateRequest()
	publicIP := true
	request.Spec.PublicIP = &publicIP

	_, err := client.UpdateV2(withPrincipal(rbac.NewContext(t.Context(), projectACL(identityapi.Read, identityapi.Update))), lbLoadBalancerID, request)
	require.Error(t, err)
	require.True(t, coreerrors.IsConflict(err), "expected 409 conflict, got: %v", err)
}
