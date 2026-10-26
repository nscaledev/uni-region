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
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	corev1alpha1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	identityauth "github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	identitymock "github.com/unikorn-cloud/identity/pkg/openapi/mock"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/handlertest"
	"github.com/unikorn-cloud/region/pkg/handler/network"
	idstest "github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/openapi"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	namespace          = "base"
	organizationID     = "11111111-1111-4111-a111-111111111111"
	projectID          = "22222222-2222-4222-a222-222222222222"
	nonexistentProject = "33333333-3333-4333-a333-333333333333"
	networkID          = "44444444-4444-4444-a444-444444444444"
	reference          = "cat"
	testNamespace      = "test-namespace"
)

// aclWithOrgScopeCreate grants region:networks:v2/Create at organization scope,
// so CreateV2 must verify the project via the identity API.
func aclWithOrgScopeCreate() *identityapi.Acl {
	return &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{
			{
				Id: organizationID,
				Endpoints: &identityapi.AclEndpoints{
					{
						Name:       "region:networks:v2",
						Operations: identityapi.AclOperations{identityapi.Create},
					},
				},
			},
		},
	}
}

// minimalNetworkV2CreateRequest returns a NetworkV2Create request body with
// the given organization and project IDs.
func minimalNetworkV2CreateRequest(orgID, projID string) *openapi.NetworkV2Create {
	return &openapi.NetworkV2Create{
		Metadata: coreapi.ResourceWriteMetadata{
			Name: "test-network",
		},
		Spec: openapi.NetworkV2CreateSpec{
			OrganizationId: orgID,
			ProjectId:      projID,
		},
	}
}

// setupFixtures sets up all the required apparatus to actually test
// anything, proving how annoying organization namespaces are!
func setupFixtures(t *testing.T) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, regionv1.AddToScheme(scheme))

	network := &regionv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      networkID,
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   organizationID,
				coreconstants.ProjectLabel:        projectID,
				constants.ResourceAPIVersionLabel: "2",
			},
		},
	}

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(network).Build()
}

func getNetwork(t *testing.T, cli client.Client) *regionv1.Network {
	t.Helper()

	network := &regionv1.Network{}

	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: networkID}, network))

	return network
}

func newNetworkFakeClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, regionv1.AddToScheme(scheme))

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func networkUpdateContext() *identityapi.Acl {
	return &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{
			{
				Id: organizationID,
				Endpoints: &identityapi.AclEndpoints{
					{
						Name:       "region:networks:v2",
						Operations: identityapi.AclOperations{identityapi.Read, identityapi.Update},
					},
				},
			},
		},
	}
}

// TestCreateV2RBACOrgScopedProjectNotFound verifies that CreateV2 returns a
// 404 Not Found when the caller has org-scoped ACL but supplies a project ID
// that does not exist.
func TestCreateV2RBACOrgScopedProjectNotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	mockIdentity.EXPECT().
		GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), identityids.MustParseOrganizationID(organizationID), identityids.MustParseProjectID(nonexistentProject)).
		Return(&identityapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
		}, nil)

	c := network.New(common.ClientArgs{Identity: mockIdentity})

	ctx := rbac.NewContext(t.Context(), aclWithOrgScopeCreate())

	_, err := c.CreateV2(ctx, minimalNetworkV2CreateRequest(organizationID, nonexistentProject))

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

// TestCreateV2RBACNoPermissions verifies that CreateV2 returns a forbidden
// error when the caller has no relevant permissions.
func TestCreateV2RBACNoPermissions(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	// No EXPECT calls, the identity API must not be contacted.

	c := network.New(common.ClientArgs{Identity: mockIdentity})

	ctx := rbac.NewContext(t.Context(), &identityapi.Acl{})

	_, err := c.CreateV2(ctx, minimalNetworkV2CreateRequest(organizationID, projectID))

	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err), "expected forbidden, got: %v", err)
}

// TestCreateV2BlockedPrefix verifies that a network prefix overlapping one of
// the region's blocked prefixes is rejected before anything is created.
func TestCreateV2BlockedPrefix(t *testing.T) {
	t.Parallel()

	const regionID = "55555555-5555-4555-a555-555555555555"

	region := &regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      regionID,
		},
		Spec: regionv1.RegionSpec{
			Provider: regionv1.ProviderSimulated,
			BlockedNetworkPrefixes: []corev1alpha1.IPv4Prefix{
				{IPNet: net.IPNet{IP: net.IPv4(10, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)}},
			},
		},
	}

	cli := newNetworkFakeClient(t, region)

	ctrl := gomock.NewController(t)

	// No EXPECT calls, the identity API must not be contacted.
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)

	c := network.New(common.ClientArgs{
		Client:    cli,
		Namespace: namespace,
		Identity:  mockIdentity,
	})

	ctx := rbac.NewContext(t.Context(), &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{
			{
				Id: organizationID,
				Projects: &identityapi.AclProjectList{
					{
						Id: projectID,
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
	})

	request := minimalNetworkV2CreateRequest(organizationID, projectID)
	request.Spec.RegionId = idstest.MustParseRegionID(regionID)
	request.Spec.Prefix = "10.0.0.0/24"

	_, err := c.CreateV2(ctx, request)
	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422, got: %v", err)

	identities := &regionv1.IdentityList{}
	require.NoError(t, cli.List(t.Context(), identities))
	require.Empty(t, identities.Items)

	networks := &regionv1.NetworkList{}
	require.NoError(t, cli.List(t.Context(), networks))
	require.Empty(t, networks.Items)
}

func TestUpdateV2PreservesReservations(t *testing.T) {
	t.Parallel()

	_, prefix, err := net.ParseCIDR("10.0.0.0/24")
	require.NoError(t, err)

	tests := []struct {
		name                         string
		reservations                 *regionv1.NetworkReservations
		expectedStatusReservations   *openapi.NetworkReservations
		expectedPersistedReservation *regionv1.NetworkReservations
	}{
		{
			name: "ExplicitReservations",
			reservations: &regionv1.NetworkReservations{
				PrefixLength:                 25,
				ProviderReservedPrefixLength: ptr.To(28),
			},
			expectedStatusReservations: &openapi.NetworkReservations{
				PrefixLength:                 25,
				ProviderReservedPrefixLength: ptr.To(28),
			},
			expectedPersistedReservation: &regionv1.NetworkReservations{
				PrefixLength:                 25,
				ProviderReservedPrefixLength: ptr.To(28),
			},
		},
		{
			name: "ImplicitReservationsUseDefaults",
			expectedStatusReservations: &openapi.NetworkReservations{
				PrefixLength:                 constants.DefaultNetworkReservationPrefixLength,
				ProviderReservedPrefixLength: ptr.To(constants.DefaultNetworkProviderReservedPrefixLength),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			current := &regionv1.Network{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "55555555-5555-4555-a555-555555555555",
					Namespace:       testNamespace,
					ResourceVersion: "1",
					Labels: map[string]string{
						coreconstants.OrganizationLabel:   organizationID,
						coreconstants.ProjectLabel:        projectID,
						constants.RegionLabel:             "region-1",
						constants.IdentityLabel:           "identity-1",
						constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
					},
					Annotations: map[string]string{
						coreconstants.AllocationAnnotation: "allocation-1",
					},
				},
				Spec: regionv1.NetworkSpec{
					Prefix: &corev1alpha1.IPv4Prefix{
						IPNet: *prefix,
					},
					Reservations: test.reservations,
					DNSNameservers: []corev1alpha1.IPv4Address{
						{IP: net.ParseIP("8.8.8.8")},
					},
				},
			}

			k8sClient := newNetworkFakeClient(t, current)
			c := network.New(common.ClientArgs{
				Client:    k8sClient,
				Namespace: testNamespace,
			})

			ctx := rbac.NewContext(t.Context(), networkUpdateContext())
			ctx = identityauth.NewContext(ctx, &identityauth.Info{
				Userinfo: &identityapi.Userinfo{Sub: "user-1"},
			})
			ctx = principal.NewContext(ctx, &principal.Principal{
				Actor:          "actor@example.com",
				OrganizationID: organizationID,
				ProjectID:      projectID,
			})

			updated, err := c.Update(ctx, idstest.MustParseNetworkID(current.Name), &openapi.NetworkV2Update{
				Metadata: coreapi.ResourceWriteMetadata{
					Name: "test-network",
				},
				Spec: openapi.NetworkV2Spec{
					DnsNameservers: []string{"1.1.1.1"},
				},
			})
			require.NoError(t, err)
			require.Equal(t, test.expectedStatusReservations, updated.Status.Reservations)

			persisted := &regionv1.Network{}
			require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKey{Name: current.Name, Namespace: testNamespace}, persisted))
			require.Equal(t, test.expectedPersistedReservation, persisted.Spec.Reservations)
			require.Len(t, persisted.Spec.DNSNameservers, 1)
			require.Equal(t, "1.1.1.1", persisted.Spec.DNSNameservers[0].String())
		})
	}
}

// TestUpdateV2ConflictReturns409 verifies that Update maps a Kubernetes
// optimistic-lock conflict from the underlying patch to an HTTP 409, rather
// than letting it surface as an unhandled 500. The region controller actively
// reconciles a freshly provisioned network, so the resourceVersion can move
// between the read and the patch.
func TestUpdateV2ConflictReturns409(t *testing.T) {
	t.Parallel()

	_, prefix, err := net.ParseCIDR("10.0.0.0/24")
	require.NoError(t, err)

	current := &regionv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "55555555-5555-4555-a555-555555555555",
			Namespace:       testNamespace,
			ResourceVersion: "1",
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   organizationID,
				coreconstants.ProjectLabel:        projectID,
				constants.RegionLabel:             "region-1",
				constants.IdentityLabel:           "identity-1",
				constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
			},
			Annotations: map[string]string{
				coreconstants.AllocationAnnotation: "allocation-1",
			},
		},
		Spec: regionv1.NetworkSpec{
			Prefix: &corev1alpha1.IPv4Prefix{
				IPNet: *prefix,
			},
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, regionv1.AddToScheme(scheme))

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(current).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(_ context.Context, _ client.WithWatch, _ client.Object, _ client.Patch, _ ...client.PatchOption) error {
				return apierrors.NewConflict(schema.GroupResource{Group: regionv1.GroupName, Resource: "networks"}, current.Name, nil)
			},
		}).
		Build()

	c := network.New(common.ClientArgs{
		Client:    k8sClient,
		Namespace: testNamespace,
	})

	ctx := rbac.NewContext(t.Context(), networkUpdateContext())
	ctx = identityauth.NewContext(ctx, &identityauth.Info{
		Userinfo: &identityapi.Userinfo{Sub: "user-1"},
	})
	ctx = principal.NewContext(ctx, &principal.Principal{
		Actor:          "actor@example.com",
		OrganizationID: organizationID,
		ProjectID:      projectID,
	})

	_, err = c.Update(ctx, idstest.MustParseNetworkID(current.Name), &openapi.NetworkV2Update{
		Metadata: coreapi.ResourceWriteMetadata{
			Name: "test-network",
		},
		Spec: openapi.NetworkV2Spec{
			DnsNameservers: []string{"1.1.1.1"},
		},
	})
	require.Error(t, err)
	require.True(t, coreerrors.IsConflict(err), "expected 409 conflict, got: %v", err)
}

func TestGetV2ReturnsEffectiveReservationsForImplicitNetworks(t *testing.T) {
	t.Parallel()

	_, prefix, err := net.ParseCIDR("10.0.0.0/24")
	require.NoError(t, err)

	tests := []struct {
		name     string
		expected *openapi.NetworkReservations
	}{
		{
			name: "ImplicitReservationsUseDefaults",
			expected: &openapi.NetworkReservations{
				PrefixLength:                 constants.DefaultNetworkReservationPrefixLength,
				ProviderReservedPrefixLength: ptr.To(constants.DefaultNetworkProviderReservedPrefixLength),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			current := &regionv1.Network{
				ObjectMeta: metav1.ObjectMeta{
					Name:      networkID,
					Namespace: testNamespace,
					Labels: map[string]string{
						coreconstants.OrganizationLabel:   organizationID,
						coreconstants.ProjectLabel:        projectID,
						constants.RegionLabel:             "region-1",
						constants.IdentityLabel:           "identity-1",
						constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
					},
				},
				Spec: regionv1.NetworkSpec{
					Prefix: &corev1alpha1.IPv4Prefix{
						IPNet: *prefix,
					},
				},
			}

			k8sClient := newNetworkFakeClient(t, current)
			c := network.New(common.ClientArgs{
				Client:    k8sClient,
				Namespace: testNamespace,
			})

			ctx := rbac.NewContext(t.Context(), networkUpdateContext())

			read, err := c.GetV2(ctx, idstest.MustParseNetworkID(current.Name))
			require.NoError(t, err)
			require.Equal(t, test.expected, read.Status.Reservations)
		})
	}
}

// TestReferences tests reference creation and deletion works and is idempotent.
func TestReferences(t *testing.T) {
	t.Parallel()

	acl := &identityapi.Acl{
		Global: &identityapi.AclEndpoints{
			{
				Name: "region:networks:v2",
				Operations: identityapi.AclOperations{
					identityapi.Read,
				},
			},
			{
				Name: "region:networks:v2/references",
				Operations: identityapi.AclOperations{
					identityapi.Create,
					identityapi.Delete,
				},
			},
		},
	}

	ctx := rbac.NewContext(t.Context(), acl)

	cli := setupFixtures(t)

	clientArgs := common.ClientArgs{
		Client:    cli,
		Namespace: namespace,
	}

	client := network.New(clientArgs)

	require.NoError(t, client.ReferenceCreateV2(ctx, idstest.MustParseNetworkID(networkID), reference))

	resource := getNetwork(t, cli)
	require.Len(t, resource.Finalizers, 1)
	require.True(t, controllerutil.ContainsFinalizer(resource, reference))

	require.NoError(t, client.ReferenceCreateV2(ctx, idstest.MustParseNetworkID(networkID), reference))

	resource = getNetwork(t, cli)
	require.Len(t, resource.Finalizers, 1)
	require.True(t, controllerutil.ContainsFinalizer(resource, reference))

	require.NoError(t, client.ReferenceDeleteV2(ctx, idstest.MustParseNetworkID(networkID), reference))

	resource = getNetwork(t, cli)
	require.Empty(t, resource.Finalizers)

	require.NoError(t, client.ReferenceDeleteV2(ctx, idstest.MustParseNetworkID(networkID), reference))

	resource = getNetwork(t, cli)
	require.Empty(t, resource.Finalizers)
}

func referencesContext(t *testing.T) context.Context {
	t.Helper()

	return rbac.NewContext(t.Context(), &identityapi.Acl{
		Global: &identityapi.AclEndpoints{
			{
				Name:       "region:networks:v2",
				Operations: identityapi.AclOperations{identityapi.Read, identityapi.Delete},
			},
			{
				Name:       "region:networks:v2/references",
				Operations: identityapi.AclOperations{identityapi.Create, identityapi.Delete},
			},
		},
	})
}

// staleNetworkClients applies before to the stored network, snapshots it as
// the copy a guard read would see, then applies after, so the read lags the
// store by one write.
func staleNetworkClients(t *testing.T, before, after func(*regionv1.Network)) (client.WithWatch, *regionv1.Network) {
	t.Helper()

	store, ok := setupFixtures(t).(client.WithWatch)
	require.True(t, ok)

	update := func(mutate func(*regionv1.Network)) {
		n := getNetwork(t, store)
		mutate(n)
		require.NoError(t, store.Update(t.Context(), n))
	}

	update(before)

	stale := getNetwork(t, store)

	update(after)

	return store, stale
}

func addReference(n *regionv1.Network) { controllerutil.AddFinalizer(n, reference) }

func removeReference(n *regionv1.Network) { controllerutil.RemoveFinalizer(n, reference) }

func noChange(*regionv1.Network) {}

// TestReferenceCreateV2StaleReadStillAdds covers a remove followed by an add
// where the add's read still saw the reference present.
func TestReferenceCreateV2StaleReadStillAdds(t *testing.T) {
	t.Parallel()

	store, stale := staleNetworkClients(t, addReference, removeReference)

	c := network.New(common.ClientArgs{Client: handlertest.StaleRead(store, stale), Namespace: namespace})

	require.NoError(t, c.ReferenceCreateV2(referencesContext(t), idstest.MustParseNetworkID(networkID), reference))
	require.True(t, controllerutil.ContainsFinalizer(getNetwork(t, store), reference))
}

// TestReferenceDeleteV2StaleReadStillRemoves covers an add followed by a
// remove where the remove's read had not yet seen the add.
func TestReferenceDeleteV2StaleReadStillRemoves(t *testing.T) {
	t.Parallel()

	store, stale := staleNetworkClients(t, noChange, addReference)

	c := network.New(common.ClientArgs{Client: handlertest.StaleRead(store, stale), Namespace: namespace})

	require.NoError(t, c.ReferenceDeleteV2(referencesContext(t), idstest.MustParseNetworkID(networkID), reference))
	require.False(t, controllerutil.ContainsFinalizer(getNetwork(t, store), reference))
}

// TestReferenceCreateV2StaleReadDeletingNetwork covers an add whose read
// missed the deletion starting: the retry sees the live copy and refuses, and
// no reference is added.
func TestReferenceCreateV2StaleReadDeletingNetwork(t *testing.T) {
	t.Parallel()

	store, stale := staleNetworkClients(t, noChange, func(n *regionv1.Network) {
		controllerutil.AddFinalizer(n, "blocker")
	})

	// Deleting a network that still has finalizers sets its deletion
	// timestamp, and the object stays until they clear.
	require.NoError(t, store.Delete(t.Context(), getNetwork(t, store)))

	c := network.New(common.ClientArgs{Client: handlertest.StaleRead(store, stale), Namespace: namespace})

	err := c.ReferenceCreateV2(referencesContext(t), idstest.MustParseNetworkID(networkID), reference)
	require.Error(t, err)
	require.True(t, coreerrors.IsBadRequest(err), "expected 400 invalid request, got: %v", err)
	require.False(t, controllerutil.ContainsFinalizer(getNetwork(t, store), reference))
}

// TestReferenceDeleteV2AfterNetworkGoneReturnsNil covers a remove racing the
// network's deletion: the patch misses the network, and the remove still
// succeeds so repeated removal stays idempotent.
func TestReferenceDeleteV2AfterNetworkGoneReturnsNil(t *testing.T) {
	t.Parallel()

	store, stale := staleNetworkClients(t, noChange, noChange)

	// The network carries no finalizers, so deleting it removes it outright.
	require.NoError(t, store.Delete(t.Context(), getNetwork(t, store)))

	c := network.New(common.ClientArgs{Client: handlertest.StaleRead(store, stale), Namespace: namespace})

	require.NoError(t, c.ReferenceDeleteV2(referencesContext(t), idstest.MustParseNetworkID(networkID), reference))
}

// TestReferenceCreateV2RepeatedConflictReturns409 verifies a conflict that
// survives the retried read is reported as 409.
func TestReferenceCreateV2RepeatedConflictReturns409(t *testing.T) {
	t.Parallel()

	store, ok := setupFixtures(t).(client.WithWatch)
	require.True(t, ok)

	conflicting := interceptor.NewClient(store, interceptor.Funcs{
		Patch: func(_ context.Context, _ client.WithWatch, obj client.Object, _ client.Patch, _ ...client.PatchOption) error {
			return apierrors.NewConflict(schema.GroupResource{Group: regionv1.GroupName, Resource: "networks"}, obj.GetName(), nil)
		},
	})

	c := network.New(common.ClientArgs{Client: conflicting, Namespace: namespace})

	err := c.ReferenceCreateV2(referencesContext(t), idstest.MustParseNetworkID(networkID), reference)
	require.Error(t, err)
	require.True(t, coreerrors.IsConflict(err), "expected 409 conflict, got: %v", err)
}
