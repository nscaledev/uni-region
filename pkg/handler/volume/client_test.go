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

package volume_test

import (
	"context"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	corev1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/volume"
	idstest "github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/openapi"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	providertypes "github.com/unikorn-cloud/region/pkg/providers/types"
	mockprovider "github.com/unikorn-cloud/region/pkg/providers/types/mock"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace      = "test-namespace"
	testOrganizationID = "11111111-1111-4111-a111-111111111111"
	testProjectID      = "22222222-2222-4222-a222-222222222222"
	testRegionID       = "33333333-3333-4333-a333-333333333333"
	testIdentityID     = "44444444-4444-4444-a444-444444444444"
	testNetworkID      = "55555555-5555-4555-a555-555555555555"
	testVolumeID       = "66666666-6666-4666-a666-666666666666"
	testServerID       = "77777777-7777-4777-a777-777777777777"
	testVolumeClassID  = "fast"
	volumeEndpoint     = "region:volumes:v2"
)

func testClient(t *testing.T, providers *mockproviders.MockProviders, objects ...client.Object) (*volume.Client, client.Client) {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, regionv1.AddToScheme(scheme))

	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

	return volume.New(common.ClientArgs{
		Client:    cli,
		Namespace: testNamespace,
		Providers: providers,
	}), cli
}

func testNetwork() *regionv1.Network {
	return &regionv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testNetworkID,
			Namespace: testNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   testOrganizationID,
				coreconstants.ProjectLabel:        testProjectID,
				constants.RegionLabel:             testRegionID,
				constants.IdentityLabel:           testIdentityID,
				constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
			},
		},
	}
}

func testVolume(name string) *regionv1.Volume {
	return &regionv1.Volume{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testVolumeID,
			Namespace: testNamespace,
			Labels: map[string]string{
				coreconstants.NameLabel:           name,
				coreconstants.OrganizationLabel:   testOrganizationID,
				coreconstants.ProjectLabel:        testProjectID,
				constants.RegionLabel:             testRegionID,
				constants.IdentityLabel:           testIdentityID,
				constants.NetworkLabel:            testNetworkID,
				constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
			},
		},
		Spec: regionv1.VolumeSpec{
			NetworkID:     testNetworkID,
			VolumeClassID: testVolumeClassID,
			Size:          resource.MustParse("20Gi"),
		},
	}
}

func testContext(t *testing.T, operations ...identityapi.AclOperation) context.Context {
	t.Helper()

	ctx := rbac.NewContext(t.Context(), &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{{
			Id: testOrganizationID,
			Projects: &identityapi.AclProjectList{{
				Id: testProjectID,
				Endpoints: identityapi.AclEndpoints{
					{Name: "region:networks:v2", Operations: identityapi.AclOperations{identityapi.Read}},
					{Name: volumeEndpoint, Operations: operations},
				},
			}},
		}},
	})

	ctx = authorization.NewContext(ctx, &authorization.Info{Userinfo: &identityapi.Userinfo{Sub: "token-actor"}})

	return principal.NewContext(ctx, &principal.Principal{Actor: "test@example.com"})
}

func expectVolumeClasses(ctrl *gomock.Controller, providers *mockproviders.MockProviders, classes providertypes.VolumeClassList) {
	provider := mockprovider.NewMockCommonProvider(ctrl)
	providers.EXPECT().LookupCommon(testRegionID).Return(provider, nil)
	provider.EXPECT().VolumeClasses(gomock.Any()).Return(classes, nil)
}

func TestCreateV2DerivesScopeAndPersistsCapacity(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	providers := mockproviders.NewMockProviders(ctrl)
	expectVolumeClasses(ctrl, providers, providertypes.VolumeClassList{{ID: testVolumeClassID}})

	volumeClient, cli := testClient(t, providers, testNetwork())
	tags := coreapi.TagList{{Name: "environment", Value: "test"}}

	result, err := volumeClient.CreateV2(testContext(t, identityapi.Read, identityapi.Create), &openapi.VolumeV2Create{
		Metadata: coreapi.ResourceWriteMetadata{Name: "data", Tags: &tags},
		Spec: openapi.VolumeV2Spec{
			NetworkId:     idstest.MustParseNetworkID(testNetworkID),
			VolumeClassId: testVolumeClassID,
			SizeGiB:       20,
		},
	})
	require.NoError(t, err)
	require.Equal(t, int64(20), result.Spec.SizeGiB)
	require.Nil(t, result.Status.SizeGiB)
	require.Equal(t, coreapi.ResourceProvisioningStatusPending, result.Metadata.ProvisioningStatus)

	volumes := &regionv1.VolumeList{}
	require.NoError(t, cli.List(t.Context(), volumes, client.InNamespace(testNamespace)))
	require.Len(t, volumes.Items, 1)

	stored := &volumes.Items[0]
	require.Equal(t, testRegionID, stored.Labels[constants.RegionLabel])
	require.Equal(t, testIdentityID, stored.Labels[constants.IdentityLabel])
	require.Equal(t, testNetworkID, stored.Labels[constants.NetworkLabel])
	require.Equal(t, testOrganizationID, stored.Labels[coreconstants.OrganizationLabel])
	require.Equal(t, testProjectID, stored.Labels[coreconstants.ProjectLabel])
	require.Equal(t, testNetworkID, stored.Spec.NetworkID)
	require.Equal(t, testVolumeClassID, stored.Spec.VolumeClassID)
	require.Equal(t, int64(20), stored.Spec.Size.Value()/(1<<30))
	require.Equal(t, corev1.TagList{{Name: "environment", Value: "test"}}, stored.Spec.Tags)
	require.Contains(t, stored.Finalizers, coreconstants.Finalizer)
	require.Equal(t, []metav1.OwnerReference{{
		APIVersion:         regionv1.SchemeGroupVersion.String(),
		Kind:               "Network",
		Name:               testNetworkID,
		BlockOwnerDeletion: ptr.To(true),
	}}, stored.OwnerReferences)
	require.NotContains(t, stored.Annotations, coreconstants.AllocationAnnotation)
}

func TestCreateV2ValidatesVolumeClass(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		classID   string
		size      int64
		classes   providertypes.VolumeClassList
		wantError bool
	}{
		{
			name:    "valid",
			classID: testVolumeClassID,
			size:    20,
			classes: providertypes.VolumeClassList{{
				ID:             testVolumeClassID,
				MinimumSizeGiB: ptr.To(int64(10)),
				MaximumSizeGiB: ptr.To(int64(30)),
			}},
		},
		{
			name:    "below minimum",
			classID: testVolumeClassID,
			size:    9,
			classes: providertypes.VolumeClassList{{
				ID:             testVolumeClassID,
				MinimumSizeGiB: ptr.To(int64(10)),
			}},
			wantError: true,
		},
		{
			name:    "above maximum",
			classID: testVolumeClassID,
			size:    31,
			classes: providertypes.VolumeClassList{{
				ID:             testVolumeClassID,
				MaximumSizeGiB: ptr.To(int64(30)),
			}},
			wantError: true,
		},
		{
			name:      "unknown class",
			classID:   "missing",
			size:      20,
			classes:   providertypes.VolumeClassList{{ID: testVolumeClassID}},
			wantError: true,
		},
		{
			name:      "quantity overflow",
			classID:   testVolumeClassID,
			size:      math.MaxInt64/(1<<30) + 1,
			classes:   providertypes.VolumeClassList{{ID: testVolumeClassID}},
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			providers := mockproviders.NewMockProviders(ctrl)
			expectVolumeClasses(ctrl, providers, test.classes)

			volumeClient, _ := testClient(t, providers, testNetwork())
			_, err := volumeClient.CreateV2(testContext(t, identityapi.Read, identityapi.Create), &openapi.VolumeV2Create{
				Metadata: coreapi.ResourceWriteMetadata{Name: "data"},
				Spec: openapi.VolumeV2Spec{
					NetworkId:     idstest.MustParseNetworkID(testNetworkID),
					VolumeClassId: test.classID,
					SizeGiB:       test.size,
				},
			})

			if test.wantError {
				require.True(t, coreerrors.IsUnprocessableContent(err))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestListAndGetV2ProjectBaseStatusWithoutAttachments(t *testing.T) {
	t.Parallel()

	observedSize := resource.MustParse("25Gi")
	resource := testVolume("beta")
	resource.Spec.Tags = corev1.TagList{{Name: "environment", Value: "test"}}
	resource.Spec.ClaimRef = &regionv1.VolumeClaimRef{Kind: regionv1.VolumeClaimKindServer, ID: testServerID}
	resource.Status.Size = &observedSize
	resource.Status.Conditions = []metav1.Condition{{
		Type:   string(corev1.ConditionAvailable),
		Status: metav1.ConditionTrue,
		Reason: string(corev1.ConditionReasonProvisioned),
	}}

	volumeClient, _ := testClient(t, nil, resource)
	ctx := testContext(t, identityapi.Read)
	tag := coreapi.TagSelectorParameter{"environment=test"}

	result, err := volumeClient.ListV2(ctx, openapi.GetApiV2VolumesParams{
		Tag:       &tag,
		RegionID:  &openapi.RegionIDQueryParameter{testRegionID},
		NetworkID: &openapi.NetworkIDQueryParameter{testNetworkID},
	})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, coreapi.ResourceProvisioningStatusProvisioned, result[0].Metadata.ProvisioningStatus)
	require.Equal(t, ptr.To(int64(25)), result[0].Status.SizeGiB)

	got, err := volumeClient.GetV2(ctx, idstest.MustParseVolumeID(testVolumeID))
	require.NoError(t, err)
	require.Equal(t, testOrganizationID, got.Metadata.OrganizationId)
	require.Equal(t, testProjectID, got.Metadata.ProjectId)
	require.Equal(t, testRegionID, got.Status.RegionId.String())
	require.Equal(t, testNetworkID, got.Spec.NetworkId.String())
}

func TestUpdateV2ChangesOnlyMetadataAndTags(t *testing.T) {
	t.Parallel()

	resource := testVolume("before")
	resource.Annotations = map[string]string{coreconstants.AllocationAnnotation: "allocation-id"}
	resource.Spec.ClaimRef = &regionv1.VolumeClaimRef{Kind: regionv1.VolumeClaimKindServer, ID: testServerID}

	volumeClient, cli := testClient(t, nil, testNetwork(), resource)
	tags := coreapi.TagList{{Name: "environment", Value: "updated"}}
	description := "updated description"

	result, err := volumeClient.UpdateV2(testContext(t, identityapi.Read, identityapi.Update), idstest.MustParseVolumeID(testVolumeID), &openapi.VolumeV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: "after", Description: &description, Tags: &tags},
	})
	require.NoError(t, err)
	require.Equal(t, "after", result.Metadata.Name)
	require.Equal(t, int64(20), result.Spec.SizeGiB)
	require.Equal(t, testVolumeClassID, result.Spec.VolumeClassId)

	stored := &regionv1.Volume{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: testNamespace, Name: testVolumeID}, stored))
	require.Equal(t, testNetworkID, stored.Spec.NetworkID)
	require.Equal(t, testVolumeClassID, stored.Spec.VolumeClassID)
	require.Equal(t, int64(20), stored.Spec.Size.Value()/(1<<30))
	require.Equal(t, resource.Spec.ClaimRef, stored.Spec.ClaimRef)
	require.Equal(t, "allocation-id", stored.Annotations[coreconstants.AllocationAnnotation])
	require.Equal(t, corev1.TagList{{Name: "environment", Value: "updated"}}, stored.Spec.Tags)
}

func TestDeleteV2RejectsAttachedVolumes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*regionv1.Volume)
	}{
		{
			name: "claim",
			mutate: func(resource *regionv1.Volume) {
				resource.Spec.ClaimRef = &regionv1.VolumeClaimRef{Kind: regionv1.VolumeClaimKindServer, ID: testServerID}
			},
		},
		{
			name: "resource reference",
			mutate: func(resource *regionv1.Volume) {
				resource.Finalizers = []string{"servers.region.unikorn-cloud.org/" + testServerID}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			resource := testVolume("attached")
			test.mutate(resource)
			volumeClient, cli := testClient(t, nil, resource)

			err := volumeClient.DeleteV2(testContext(t, identityapi.Read, identityapi.Delete), idstest.MustParseVolumeID(testVolumeID))
			require.True(t, coreerrors.IsForbidden(err))
			require.EqualError(t, err, "volume is attached and must be detached before deletion")
			require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: testNamespace, Name: testVolumeID}, &regionv1.Volume{}))
		})
	}
}

func TestCreateV2RequiresCreatePermission(t *testing.T) {
	t.Parallel()

	volumeClient, cli := testClient(t, nil, testNetwork())
	_, err := volumeClient.CreateV2(testContext(t, identityapi.Read), &openapi.VolumeV2Create{
		Metadata: coreapi.ResourceWriteMetadata{Name: "data"},
		Spec: openapi.VolumeV2Spec{
			NetworkId:     idstest.MustParseNetworkID(testNetworkID),
			VolumeClassId: testVolumeClassID,
			SizeGiB:       20,
		},
	})
	require.True(t, coreerrors.IsForbidden(err))

	volumes := &regionv1.VolumeList{}
	require.NoError(t, cli.List(t.Context(), volumes, client.InNamespace(testNamespace)))
	require.Empty(t, volumes.Items)
}

func TestGetV2RejectsCrossProjectAccess(t *testing.T) {
	t.Parallel()

	resource := testVolume("hidden")
	resource.Labels[coreconstants.ProjectLabel] = "88888888-8888-4888-a888-888888888888"
	volumeClient, _ := testClient(t, nil, resource)

	_, err := volumeClient.GetV2(testContext(t, identityapi.Read), idstest.MustParseVolumeID(testVolumeID))
	require.True(t, coreerrors.IsForbidden(err))
}

func TestListV2ExcludesCrossProjectVolumes(t *testing.T) {
	t.Parallel()

	visible := testVolume("visible")
	hidden := testVolume("hidden")
	hidden.Name = "99999999-9999-4999-a999-999999999999"
	hidden.Labels[coreconstants.ProjectLabel] = "88888888-8888-4888-a888-888888888888"
	volumeClient, _ := testClient(t, nil, visible, hidden)

	result, err := volumeClient.ListV2(testContext(t, identityapi.Read), openapi.GetApiV2VolumesParams{})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, testVolumeID, result[0].Metadata.Id)
}

func TestDeleteV2DeletesUnattachedVolume(t *testing.T) {
	t.Parallel()

	volumeClient, cli := testClient(t, nil, testVolume("available"))
	require.NoError(t, volumeClient.DeleteV2(testContext(t, identityapi.Read, identityapi.Delete), idstest.MustParseVolumeID(testVolumeID)))

	err := cli.Get(t.Context(), client.ObjectKey{Namespace: testNamespace, Name: testVolumeID}, &regionv1.Volume{})
	require.True(t, kerrors.IsNotFound(err))
}
