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

package region_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/region"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/openapi"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	globalRegionName   = "11111111-1111-4111-a111-111111111111"
	privateRegionName1 = "22222222-2222-4222-a222-222222222222"
	privateRegionName2 = "33333333-3333-4333-a333-333333333333"
	privateRegionName3 = "44444444-4444-4444-a444-444444444444"

	// regionDoesNotExist is a valid-but-unused UUID for negative/not-found cases.
	regionDoesNotExist = "99999999-9999-4999-a999-999999999999"

	organizationID1 = "foo"
	organizationID2 = "bar"
	organizationID3 = "baz"
	organizationID4 = "none"

	testNamespace = "test"
)

func regionsFixture() *regionv1.RegionList {
	return &regionv1.RegionList{
		Items: []regionv1.Region{
			// I am a global region.
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: globalRegionName,
				},
			},
			// I am limited to a few organizations.
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: privateRegionName1,
				},
				Spec: regionv1.RegionSpec{
					Security: &regionv1.RegionSecuritySpec{
						Organizations: []regionv1.RegionSecurityOrganizationSpec{
							{ID: organizationID1},
							{ID: organizationID2},
						},
					},
				},
			},
			// I am limited to a single organization.
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: privateRegionName2,
				},
				Spec: regionv1.RegionSpec{
					Security: &regionv1.RegionSecuritySpec{
						Organizations: []regionv1.RegionSecurityOrganizationSpec{
							{ID: organizationID2},
						},
					},
				},
			},
			// I am limited to a different single organization.
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: privateRegionName3,
				},
				Spec: regionv1.RegionSpec{
					Security: &regionv1.RegionSecuritySpec{
						Organizations: []regionv1.RegionSecurityOrganizationSpec{
							{ID: organizationID3},
						},
					},
				},
			},
		},
	}
}

// aclFixture builds an ACL context for a regular user in the given organizations.
func aclFixture(t *testing.T, organizationIDs ...string) context.Context {
	t.Helper()

	orgs := make(identityapi.AclOrganizationList, len(organizationIDs))

	for i, id := range organizationIDs {
		orgs[i] = identityapi.AclOrganization{
			Id: id,
			Endpoints: &identityapi.AclEndpoints{
				{Name: "region:regions", Operations: identityapi.AclOperations{identityapi.Read}},
			},
		}
	}

	acl := &identityapi.Acl{
		Organizations: &orgs,
	}

	return rbac.NewContext(t.Context(), acl)
}

// globalACLFixture builds an ACL context for a platform admin or service with global scope.
func globalACLFixture(t *testing.T) context.Context {
	t.Helper()

	acl := &identityapi.Acl{
		Global: &identityapi.AclEndpoints{
			{Name: "region:regions", Operations: identityapi.AclOperations{identityapi.Read}},
		},
	}

	return rbac.NewContext(t.Context(), acl)
}

// TestRegionFilteringSinglePrivate tests users can see a single private region and
// all public ones.
func TestRegionFilteringSinglePrivate(t *testing.T) {
	t.Parallel()

	ctx := aclFixture(t, organizationID1)
	regions := regionsFixture()

	region.FilterRegions(ctx, regions)
	require.Len(t, regions.Items, 2)
	require.Equal(t, globalRegionName, regions.Items[0].Name)
	require.Equal(t, privateRegionName1, regions.Items[1].Name)
}

// TestRegionFilteringMultiplePrivate tests users can see multiple private regions
// and all public ones.
func TestRegionFilteringMultiplePrivate(t *testing.T) {
	t.Parallel()

	ctx := aclFixture(t, organizationID2)
	regions := regionsFixture()

	region.FilterRegions(ctx, regions)
	require.Len(t, regions.Items, 3)
	require.Equal(t, globalRegionName, regions.Items[0].Name)
	require.Equal(t, privateRegionName1, regions.Items[1].Name)
	require.Equal(t, privateRegionName2, regions.Items[2].Name)
}

// TestRegionFilteringNoPrivate tests users with no matching private regions only
// see public ones.
func TestRegionFilteringNoPrivate(t *testing.T) {
	t.Parallel()

	ctx := aclFixture(t, organizationID4)
	regions := regionsFixture()

	region.FilterRegions(ctx, regions)
	require.Len(t, regions.Items, 1)
	require.Equal(t, globalRegionName, regions.Items[0].Name)
}

// TestRegionFilteringGlobalScope tests that platform admins and services with global
// scope see all regions including private ones.
func TestRegionFilteringGlobalScope(t *testing.T) {
	t.Parallel()

	ctx := globalACLFixture(t)
	regions := regionsFixture()

	region.FilterRegions(ctx, regions)
	require.Len(t, regions.Items, 4)
}

// regionClientFixture creates a region.Client backed by a fake Kubernetes client
// pre-populated with the given region objects.
func regionClientFixture(t *testing.T, regions ...regionv1.Region) *region.Client {
	t.Helper()

	scheme := runtime.NewScheme()

	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("adding client-go scheme: %v", err)
	}

	if err := regionv1.AddToScheme(scheme); err != nil {
		t.Fatalf("adding unikorn scheme: %v", err)
	}

	builder := fake.NewClientBuilder().WithScheme(scheme)

	for i := range regions {
		regions[i].Namespace = testNamespace
		builder = builder.WithObjects(&regions[i])
	}

	return region.NewClient(common.ClientArgs{
		Client:    builder.Build(),
		Namespace: testNamespace,
	})
}

// TestCheckAccessGlobalRegion verifies any organization can access a region with no
// security constraints.
func TestCheckAccessGlobalRegion(t *testing.T) {
	t.Parallel()

	c := regionClientFixture(t, regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{Name: globalRegionName},
	})

	require.NoError(t, c.CheckAccess(aclFixture(t, organizationID4), regionids.MustParseRegionID(globalRegionName)))
}

// TestCheckAccessAllowedOrg verifies an organization in the allowed list can access
// a restricted region.
func TestCheckAccessAllowedOrg(t *testing.T) {
	t.Parallel()

	c := regionClientFixture(t, regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{Name: privateRegionName1},
		Spec: regionv1.RegionSpec{
			Security: &regionv1.RegionSecuritySpec{
				Organizations: []regionv1.RegionSecurityOrganizationSpec{
					{ID: organizationID1},
					{ID: organizationID2},
				},
			},
		},
	})

	require.NoError(t, c.CheckAccess(aclFixture(t, organizationID1), regionids.MustParseRegionID(privateRegionName1)))
}

// TestCheckAccessDeniedOrg verifies an organization not in the allowed list receives
// HTTPNotFound rather than HTTPForbidden.
func TestCheckAccessDeniedOrg(t *testing.T) {
	t.Parallel()

	c := regionClientFixture(t, regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{Name: privateRegionName1},
		Spec: regionv1.RegionSpec{
			Security: &regionv1.RegionSecuritySpec{
				Organizations: []regionv1.RegionSecurityOrganizationSpec{
					{ID: organizationID1},
				},
			},
		},
	})

	require.Error(t, c.CheckAccess(aclFixture(t, organizationID4), regionids.MustParseRegionID(privateRegionName1)))
}

// TestCheckAccessGlobalScope verifies platform admins and services with global scope
// can access any region including restricted ones.
func TestCheckAccessGlobalScope(t *testing.T) {
	t.Parallel()

	c := regionClientFixture(t, regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{Name: privateRegionName1},
		Spec: regionv1.RegionSpec{
			Security: &regionv1.RegionSecuritySpec{
				Organizations: []regionv1.RegionSecurityOrganizationSpec{
					{ID: organizationID1},
				},
			},
		},
	})

	require.NoError(t, c.CheckAccess(globalACLFixture(t), regionids.MustParseRegionID(privateRegionName1)))
}

// TestCheckAccessMissingRegion verifies a non-existent region ID returns an error.
func TestCheckAccessMissingRegion(t *testing.T) {
	t.Parallel()

	c := regionClientFixture(t)

	require.Error(t, c.CheckAccess(aclFixture(t, organizationID1), regionids.MustParseRegionID("44444444-4444-4444-a444-444444444444")))
}

// regionClientWithObjects creates a region.Client backed by a fake Kubernetes client
// pre-populated with arbitrary objects (e.g. Regions alongside the Secret a Kubernetes
// region's detail view dereferences). Callers must set each object's namespace.
func regionClientWithObjects(t *testing.T, objects ...runtime.Object) *region.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, regionv1.AddToScheme(scheme))

	builder := fake.NewClientBuilder().WithScheme(scheme)

	for _, o := range objects {
		builder = builder.WithRuntimeObjects(o)
	}

	return region.NewClient(common.ClientArgs{
		Client:    builder.Build(),
		Namespace: testNamespace,
	})
}

func simulatedRegion(name string, organizationIDs ...string) regionv1.Region {
	resource := regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec:       regionv1.RegionSpec{Provider: regionv1.ProviderSimulated},
	}

	if len(organizationIDs) > 0 {
		orgs := make([]regionv1.RegionSecurityOrganizationSpec, len(organizationIDs))
		for i, id := range organizationIDs {
			orgs[i] = regionv1.RegionSecurityOrganizationSpec{ID: id}
		}

		resource.Spec.Security = &regionv1.RegionSecuritySpec{Organizations: orgs}
	}

	return resource
}

// regionIDs collects the resource IDs from a list of region reads so assertions can
// be order-independent (List does not impose an ordering guarantee).
func regionIDs(in openapi.Regions) []string {
	out := make([]string, len(in))
	for i := range in {
		out[i] = in[i].Metadata.Id
	}

	return out
}

// TestListIncludesAccessibleprivate verifies List returns public regions plus the
// private regions the caller's organization is permitted to see.
func TestListIncludesAccessiblePrivate(t *testing.T) {
	t.Parallel()

	c := regionClientFixture(t,
		simulatedRegion(globalRegionName),
		simulatedRegion(privateRegionName1, organizationID1, organizationID2),
		simulatedRegion(privateRegionName3, organizationID3),
	)

	result, err := c.List(aclFixture(t, organizationID1))

	require.NoError(t, err)
	require.Len(t, result, 2)
	require.ElementsMatch(t, []string{globalRegionName, privateRegionName1}, regionIDs(result))
}

// TestListExcludesInaccessiblePrivate verifies a caller whose organization matches no
// private region sees only the public ones.
func TestListExcludesInaccessiblePrivate(t *testing.T) {
	t.Parallel()

	c := regionClientFixture(t,
		simulatedRegion(globalRegionName),
		simulatedRegion(privateRegionName1, organizationID1),
	)

	result, err := c.List(aclFixture(t, organizationID4))

	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, globalRegionName, result[0].Metadata.Id)
	require.Equal(t, openapi.RegionTypeSimulated, result[0].Spec.Type)
}

// TestListGlobalScope verifies a platform admin or service with global scope sees
// every region regardless of its security constraints.
func TestListGlobalScope(t *testing.T) {
	t.Parallel()

	c := regionClientFixture(t,
		simulatedRegion(globalRegionName),
		simulatedRegion(privateRegionName1, organizationID1),
		simulatedRegion(privateRegionName2, organizationID2),
	)

	result, err := c.List(globalACLFixture(t))

	require.NoError(t, err)
	require.Len(t, result, 3)
}

// TestGetDetailSimulated verifies GetDetail returns the region detail for an
// accessible region without provider-specific configuration.
func TestGetDetailSimulated(t *testing.T) {
	t.Parallel()

	c := regionClientFixture(t, simulatedRegion(globalRegionName))

	result, err := c.GetDetail(aclFixture(t, organizationID1), regionids.MustParseRegionID(globalRegionName))

	require.NoError(t, err)
	require.Equal(t, globalRegionName, result.Metadata.Id)
	require.Equal(t, openapi.RegionTypeSimulated, result.Spec.Type)
	require.Nil(t, result.Spec.Kubernetes)
}

// TestGetDetailKubernetesEmbedsKubeconfig verifies GetDetail resolves the referenced
// kubeconfig secret and returns its contents base64 encoded.
func TestGetDetailKubernetesEmbedsKubeconfig(t *testing.T) {
	t.Parallel()

	const (
		regionName    = "55555555-5555-4555-a555-555555555555"
		kubeconfigRef = "k8s-region-kubeconfig"
	)

	kubeconfig := []byte("apiVersion: v1\nkind: Config\n")

	resource := regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{Name: regionName, Namespace: testNamespace},
		Spec: regionv1.RegionSpec{
			Provider: regionv1.ProviderKubernetes,
			Kubernetes: &regionv1.RegionKubernetesSpec{
				KubeconfigSecret: &regionv1.NamespacedObject{
					Namespace: testNamespace,
					Name:      kubeconfigRef,
				},
				DomainName: "example.com",
			},
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: kubeconfigRef, Namespace: testNamespace},
		Data:       map[string][]byte{"kubeconfig": kubeconfig},
	}

	c := regionClientWithObjects(t, &resource, secret)

	result, err := c.GetDetail(aclFixture(t, organizationID1), regionids.MustParseRegionID(regionName))

	require.NoError(t, err)
	require.Equal(t, openapi.RegionTypeKubernetes, result.Spec.Type)
	require.NotNil(t, result.Spec.Kubernetes)
	require.Equal(t, base64.RawURLEncoding.EncodeToString(kubeconfig), result.Spec.Kubernetes.Kubeconfig)
	require.NotNil(t, result.Spec.Kubernetes.DomainName)
	require.Equal(t, "example.com", *result.Spec.Kubernetes.DomainName)
}

// TestGetDetailKubernetesMissingKubeconfigKey verifies GetDetail surfaces an error
// when the referenced secret exists but lacks the kubeconfig key.
func TestGetDetailKubernetesMissingKubeconfigKey(t *testing.T) {
	t.Parallel()

	const (
		regionName    = "55555555-5555-4555-a555-555555555555"
		kubeconfigRef = "k8s-region-kubeconfig"
	)

	resource := regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{Name: regionName, Namespace: testNamespace},
		Spec: regionv1.RegionSpec{
			Provider: regionv1.ProviderKubernetes,
			Kubernetes: &regionv1.RegionKubernetesSpec{
				KubeconfigSecret: &regionv1.NamespacedObject{
					Namespace: testNamespace,
					Name:      kubeconfigRef,
				},
			},
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: kubeconfigRef, Namespace: testNamespace},
		Data:       map[string][]byte{"not-kubeconfig": []byte("data")},
	}

	c := regionClientWithObjects(t, &resource, secret)

	_, err := c.GetDetail(aclFixture(t, organizationID1), regionids.MustParseRegionID(regionName))

	require.Error(t, err)
}

// TestGetDetailNotFound verifies GetDetail returns a not-found error for a region
// that does not exist.
func TestGetDetailNotFound(t *testing.T) {
	t.Parallel()

	c := regionClientFixture(t)

	_, err := c.GetDetail(aclFixture(t, organizationID1), regionids.MustParseRegionID(regionDoesNotExist))

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}

// TestGetDetailAccessDenied verifies GetDetail returns a not-found error (not a
// forbidden error) when the caller's organization cannot see a restricted region,
// so existence is not leaked.
func TestGetDetailAccessDenied(t *testing.T) {
	t.Parallel()

	c := regionClientFixture(t, simulatedRegion(privateRegionName1, organizationID1))

	_, err := c.GetDetail(aclFixture(t, organizationID4), regionids.MustParseRegionID(privateRegionName1))

	require.Error(t, err)
	require.True(t, coreerrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}
