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
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	identitymock "github.com/unikorn-cloud/identity/pkg/openapi/mock"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	providertypes "github.com/unikorn-cloud/region/pkg/providers/types"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"
	volume "github.com/unikorn-cloud/region/pkg/provisioners/managers/volume"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace    = "test-ns"
	testRegionID     = "region-1"
	testIdentityID   = "identity-1"
	testVolumeID     = "11111111-1111-4111-8111-111111111111"
	testOrganization = "00000000-0000-4000-8000-000000000001"
	testProject      = "00000000-0000-4000-8000-000000000002"
	testAllocationID = "00000000-0000-4000-8000-000000000003"
	testServerID     = "11111111-1111-4111-8111-111111111112"
	testOldServerID  = "11111111-1111-4111-8111-111111111113"
)

var (
	errProviderCreate   = errors.New("provider create failed")
	errProviderDelete   = errors.New("provider delete failed")
	errProviderLookup   = errors.New("provider lookup failed")
	errAllocationDelete = errors.New("allocation delete failed")
	errStatusConflict   = errors.New("concurrent status update")
)

type conflictOnceClient struct {
	client.Client

	onConflict func(context.Context) error
	conflicted bool
}

type conflictOnceStatusWriter struct {
	client.SubResourceWriter

	client *conflictOnceClient
}

type conflictOnceVolumeUpdateClient struct {
	client.Client

	onConflict func(context.Context) error
	conflicted bool
}

func (c *conflictOnceClient) Status() client.SubResourceWriter {
	return &conflictOnceStatusWriter{
		SubResourceWriter: c.Client.Status(),
		client:            c,
	}
}

func (w *conflictOnceStatusWriter) Update(ctx context.Context, object client.Object, options ...client.SubResourceUpdateOption) error {
	if w.client.conflicted {
		return w.SubResourceWriter.Update(ctx, object, options...)
	}

	w.client.conflicted = true
	if err := w.client.onConflict(ctx); err != nil {
		return err
	}

	return kerrors.NewConflict(unikornv1.Resource("servers"), object.GetName(), errStatusConflict)
}

func (c *conflictOnceVolumeUpdateClient) Update(ctx context.Context, object client.Object, options ...client.UpdateOption) error {
	if c.conflicted {
		return c.Client.Update(ctx, object, options...)
	}

	c.conflicted = true
	if err := c.onConflict(ctx); err != nil {
		return err
	}

	return kerrors.NewConflict(unikornv1.Resource("volumes"), object.GetName(), errStatusConflict)
}

func testVolume(withAllocation bool) *unikornv1.Volume {
	resource := &unikornv1.Volume{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testVolumeID,
			Namespace: testNamespace,
			Labels: map[string]string{
				constants.RegionLabel:           testRegionID,
				constants.IdentityLabel:         testIdentityID,
				coreconstants.OrganizationLabel: testOrganization,
				coreconstants.ProjectLabel:      testProject,
			},
		},
	}

	if withAllocation {
		resource.Annotations = map[string]string{
			coreconstants.AllocationAnnotation: testAllocationID,
		}
	}

	return resource
}

func testIdentity(ready bool) *unikornv1.Identity {
	identity := &unikornv1.Identity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testIdentityID,
			Namespace: testNamespace,
		},
	}

	if ready {
		identity.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "")
	}

	return identity
}

func testServer(ready bool) *unikornv1.Server {
	server := &unikornv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testServerID,
			Namespace: testNamespace,
		},
	}

	if ready {
		server.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "")
	}

	return server
}

func controllerContext(t *testing.T, objects ...client.Object) context.Context {
	t.Helper()

	scheme, err := coreclient.NewScheme(unikornv1.AddToScheme)
	require.NoError(t, err)

	cli := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&unikornv1.Server{}).WithObjects(objects...).Build()

	return coreclient.NewContext(t.Context(), cli)
}

func volumeMocks(t *testing.T) (*mocktypes.MockProvider, *mockproviders.MockProviders) {
	t.Helper()

	ctrl := gomock.NewController(t)
	provider := mocktypes.NewMockProvider(ctrl)
	providerSet := mockproviders.NewMockProviders(ctrl)

	return provider, providerSet
}

func identityNamed() gomock.Matcher {
	return gomock.Cond(func(identity *unikornv1.Identity) bool {
		return identity != nil && identity.Name == testIdentityID
	})
}

func serverNamed() gomock.Matcher {
	return serverNamedID(testServerID)
}

func serverNamedID(id string) gomock.Matcher {
	return gomock.Cond(func(server *unikornv1.Server) bool { return server != nil && server.Name == id })
}

func expectAllocationDelete(mockIdentity *identitymock.MockClientWithResponsesInterface, status int) *gomock.Call {
	return mockIdentity.EXPECT().
		DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDWithResponse(
			gomock.Any(),
			identityids.MustParseOrganizationID(testOrganization),
			identityids.MustParseProjectID(testProject),
			identityids.MustParseAllocationID(testAllocationID),
		).
		Return(&identityapi.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDResponse{
			HTTPResponse: &http.Response{StatusCode: status},
		}, nil)
}

func TestProvisionCreatesVolume(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	identity := testIdentity(true)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	gomock.InOrder(
		provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().DetachVolume(gomock.Any(), identityNamed(), resource).Return(nil),
	)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	require.NoError(t, provisioner.Provision(controllerContext(t, resource, identity)))
}

func TestProvisionAttachesClaimedVolumeToReadyServer(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	resource.Spec.ClaimRef = &unikornv1.VolumeClaimRef{Kind: unikornv1.VolumeClaimKindServer, ID: testServerID}
	identity := testIdentity(true)
	server := testServer(true)
	server.Spec.Volumes = []unikornv1.ServerVolumeSpec{{ID: testVolumeID}}
	device := "/dev/vdb"

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	gomock.InOrder(
		provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().AttachVolume(gomock.Any(), identityNamed(), serverNamed(), resource).Return(&providertypes.ServerVolumeAttachment{Device: &device}, nil),
	)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	ctx := controllerContext(t, resource, identity, server)
	require.NoError(t, provisioner.Provision(ctx))
	cli, err := coreclient.FromContext(ctx)

	require.NoError(t, err)

	updatedServer := &unikornv1.Server{}

	require.NoError(t, cli.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: testServerID}, updatedServer))
	require.Equal(t, []unikornv1.ServerVolumeStatus{{
		ID:                 testVolumeID,
		ProvisioningStatus: unikornv1.AttachmentProvisioned,
		Device:             &device,
	}}, updatedServer.Status.Volumes)
}

func TestProvisionProjectsStatusBeforeDetachingConflictingAttachment(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	resource.Spec.ClaimRef = &unikornv1.VolumeClaimRef{Kind: unikornv1.VolumeClaimKindServer, ID: testServerID}
	identity := testIdentity(true)
	server := testServer(true)
	server.Spec.Volumes = []unikornv1.ServerVolumeSpec{{ID: testVolumeID}}

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	gomock.InOrder(
		provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().AttachVolume(gomock.Any(), identityNamed(), serverNamed(), resource).Return(nil, coreerrors.ErrConflict),
		provider.EXPECT().DetachVolume(gomock.Any(), identityNamed(), resource).Return(provisioners.ErrYield),
	)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	ctx := controllerContext(t, resource, identity, server)
	require.ErrorIs(t, provisioner.Provision(ctx), provisioners.ErrYield)

	cli, err := coreclient.FromContext(ctx)
	require.NoError(t, err)

	updatedServer := &unikornv1.Server{}
	require.NoError(t, cli.Get(ctx, client.ObjectKeyFromObject(server), updatedServer))
	require.Equal(t, unikornv1.AttachmentDeprovisioning, updatedServer.Status.Volumes[0].ProvisioningStatus)
}

func TestProvisionDoesNotProjectAttachmentStatusBeforeVolumeConverges(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	resource.Spec.ClaimRef = &unikornv1.VolumeClaimRef{Kind: unikornv1.VolumeClaimKindServer, ID: testServerID}
	identity := testIdentity(true)
	server := testServer(true)
	server.Spec.Volumes = []unikornv1.ServerVolumeSpec{{ID: testVolumeID}}

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(provisioners.ErrYield)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	ctx := controllerContext(t, resource, identity, server)
	require.ErrorIs(t, provisioner.Provision(ctx), provisioners.ErrYield)
	require.Nil(t, resource.Status.ObservedGeneration)

	cli, err := coreclient.FromContext(ctx)
	require.NoError(t, err)

	updatedServer := &unikornv1.Server{}
	require.NoError(t, cli.Get(ctx, client.ObjectKeyFromObject(server), updatedServer))
	require.Empty(t, updatedServer.Status.Volumes)
}

func TestProvisionRetriesServerStatusConflictAndPreservesOtherVolume(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	resource.Spec.ClaimRef = &unikornv1.VolumeClaimRef{Kind: unikornv1.VolumeClaimKindServer, ID: testServerID}
	identity := testIdentity(true)
	server := testServer(true)
	server.Spec.Volumes = []unikornv1.ServerVolumeSpec{{ID: testVolumeID}, {ID: testOldServerID}}

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	gomock.InOrder(
		provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().AttachVolume(gomock.Any(), identityNamed(), serverNamed(), resource).Return(&providertypes.ServerVolumeAttachment{}, nil),
	)

	scheme, err := coreclient.NewScheme(unikornv1.AddToScheme)
	require.NoError(t, err)

	baseClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&unikornv1.Server{}).WithObjects(resource, identity, server).Build()
	conflictClient := &conflictOnceClient{Client: baseClient}
	conflictClient.onConflict = func(ctx context.Context) error {
		latest := &unikornv1.Server{}
		if err := baseClient.Get(ctx, client.ObjectKeyFromObject(server), latest); err != nil {
			return err
		}

		latest.Status.Volumes = append(latest.Status.Volumes, unikornv1.ServerVolumeStatus{ID: testOldServerID, ProvisioningStatus: unikornv1.AttachmentProvisioned})

		return baseClient.Status().Update(ctx, latest)
	}

	provisioner := volume.NewForTest(resource, providerSet, nil)
	ctx := coreclient.NewContext(t.Context(), conflictClient)
	require.NoError(t, provisioner.Provision(ctx))

	updatedServer := &unikornv1.Server{}
	require.NoError(t, baseClient.Get(ctx, client.ObjectKeyFromObject(server), updatedServer))
	require.ElementsMatch(t, []unikornv1.ServerVolumeStatus{
		{ID: testOldServerID, ProvisioningStatus: unikornv1.AttachmentProvisioned},
		{ID: testVolumeID, ProvisioningStatus: unikornv1.AttachmentProvisioned},
	}, updatedServer.Status.Volumes)
}

func TestProvisionDetachesVolumeWhenClaimIsRemoved(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	identity := testIdentity(true)
	server := testServer(true)
	server.Status.Volumes = []unikornv1.ServerVolumeStatus{{ID: testVolumeID, ProvisioningStatus: unikornv1.AttachmentProvisioned}}

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	gomock.InOrder(
		provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().DetachVolume(gomock.Any(), identityNamed(), resource).Return(nil),
	)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	ctx := controllerContext(t, resource, identity, server)
	require.NoError(t, provisioner.Provision(ctx))
	cli, err := coreclient.FromContext(ctx)

	require.NoError(t, err)

	updatedServer := &unikornv1.Server{}

	require.NoError(t, cli.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: testServerID}, updatedServer))
	require.Empty(t, updatedServer.Status.Volumes)
}

func TestProvisionDetachesVolumeWhenServerIntentIsRemoved(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	resource.Spec.ClaimRef = &unikornv1.VolumeClaimRef{Kind: unikornv1.VolumeClaimKindServer, ID: testServerID}
	identity := testIdentity(true)
	server := testServer(true)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	require.ErrorIs(t, provisioner.Provision(controllerContext(t, resource, identity, server)), provisioners.ErrYield)
	require.Nil(t, resource.Spec.ClaimRef)
}

func TestProvisionReleasesClaimWhenServerIsDeleting(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	resource.Spec.ClaimRef = &unikornv1.VolumeClaimRef{Kind: unikornv1.VolumeClaimKindServer, ID: testServerID}
	identity := testIdentity(true)
	server := testServer(true)
	server.Spec.Volumes = []unikornv1.ServerVolumeSpec{{ID: testVolumeID}}
	deleting := metav1.Now()
	server.DeletionTimestamp = &deleting
	server.Finalizers = []string{"test"}

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	require.ErrorIs(t, provisioner.Provision(controllerContext(t, resource, identity, server)), provisioners.ErrYield)
	require.Nil(t, resource.Spec.ClaimRef)
}

func TestProvisionDetachesPreviousAttachmentBeforeAttachingClaimedServer(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	resource.Spec.ClaimRef = &unikornv1.VolumeClaimRef{Kind: unikornv1.VolumeClaimKindServer, ID: testServerID}
	identity := testIdentity(true)
	oldServer := testServer(true)
	oldServer.Name = testOldServerID
	newServer := testServer(true)
	newServer.Spec.Volumes = []unikornv1.ServerVolumeSpec{{ID: testVolumeID}}

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil).Times(2)
	gomock.InOrder(
		provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().AttachVolume(gomock.Any(), identityNamed(), serverNamed(), resource).Return(nil, coreerrors.ErrConflict),
		provider.EXPECT().DetachVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().AttachVolume(gomock.Any(), identityNamed(), serverNamed(), resource).Return(&providertypes.ServerVolumeAttachment{}, nil),
	)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	ctx := controllerContext(t, resource, identity, oldServer, newServer)
	require.ErrorIs(t, provisioner.Provision(ctx), provisioners.ErrYield)
	require.Nil(t, resource.Status.ObservedGeneration)
	require.NoError(t, provisioner.Provision(ctx))
}

func TestProvisionWaitsForClaimedServer(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	resource.Spec.ClaimRef = &unikornv1.VolumeClaimRef{Kind: unikornv1.VolumeClaimKindServer, ID: testServerID}
	identity := testIdentity(true)
	server := testServer(false)
	server.Spec.Volumes = []unikornv1.ServerVolumeSpec{{ID: testVolumeID}}

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	ctx := controllerContext(t, resource, identity, server)
	err := provisioner.Provision(ctx)
	require.ErrorIs(t, err, provisioners.ErrYield)
	cli, err := coreclient.FromContext(ctx)
	require.NoError(t, err)

	updatedServer := &unikornv1.Server{}
	require.NoError(t, cli.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: testServerID}, updatedServer))
	require.Equal(t, unikornv1.AttachmentProvisioning, updatedServer.Status.Volumes[0].ProvisioningStatus)
}

func TestProvisionWaitsForClaimedServerToExist(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	resource.Spec.ClaimRef = &unikornv1.VolumeClaimRef{Kind: unikornv1.VolumeClaimKindServer, ID: testServerID}
	identity := testIdentity(true)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	gomock.InOrder(
		provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().DetachVolume(gomock.Any(), identityNamed(), resource).Return(nil),
	)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	ctx := controllerContext(t, resource, identity)
	err := provisioner.Provision(ctx)
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Nil(t, resource.Status.ObservedGeneration)

	cli, err := coreclient.FromContext(ctx)
	require.NoError(t, err)

	stored := &unikornv1.Volume{}
	require.NoError(t, cli.Get(ctx, client.ObjectKeyFromObject(resource), stored))
	require.Equal(t, resource.Spec.ClaimRef, stored.Spec.ClaimRef)
}

func TestProvisionDetachesAfterReleasingUnrequestedServerClaim(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	resource.Spec.ClaimRef = &unikornv1.VolumeClaimRef{Kind: unikornv1.VolumeClaimKindServer, ID: testServerID}
	identity := testIdentity(true)
	server := testServer(true)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil).Times(2)
	gomock.InOrder(
		provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().DetachVolume(gomock.Any(), identityNamed(), resource).Return(nil),
	)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	ctx := controllerContext(t, resource, identity, server)
	err := provisioner.Provision(ctx)
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Nil(t, resource.Spec.ClaimRef)
	require.NoError(t, provisioner.Provision(ctx))
}

func TestProvisionRetainsNewClaimWhenReleasingUnrequestedServerClaimConflicts(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	resource.Spec.ClaimRef = &unikornv1.VolumeClaimRef{Kind: unikornv1.VolumeClaimKindServer, ID: testServerID}
	identity := testIdentity(true)
	server := testServer(true)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil)

	scheme, err := coreclient.NewScheme(unikornv1.AddToScheme)
	require.NoError(t, err)

	baseClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(resource, identity, server).Build()
	conflictClient := &conflictOnceVolumeUpdateClient{Client: baseClient}
	conflictClient.onConflict = func(ctx context.Context) error {
		latest := &unikornv1.Volume{}
		if err := baseClient.Get(ctx, client.ObjectKeyFromObject(resource), latest); err != nil {
			return err
		}

		latest.Spec.ClaimRef = &unikornv1.VolumeClaimRef{Kind: unikornv1.VolumeClaimKindServer, ID: testOldServerID}

		return baseClient.Update(ctx, latest)
	}

	provisioner := volume.NewForTest(resource, providerSet, nil)
	ctx := coreclient.NewContext(t.Context(), conflictClient)
	require.ErrorIs(t, provisioner.Provision(ctx), provisioners.ErrYield)

	stored := &unikornv1.Volume{}
	require.NoError(t, baseClient.Get(ctx, client.ObjectKeyFromObject(resource), stored))
	require.Equal(t, &unikornv1.VolumeClaimRef{Kind: unikornv1.VolumeClaimKindServer, ID: testOldServerID}, stored.Spec.ClaimRef)
}

func TestProvisionRetriesErroredServer(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	resource.Spec.ClaimRef = &unikornv1.VolumeClaimRef{Kind: unikornv1.VolumeClaimKindServer, ID: testServerID}
	identity := testIdentity(true)
	server := testServer(false)
	server.Spec.Volumes = []unikornv1.ServerVolumeSpec{{ID: testVolumeID}}
	server.SetProvisioningCondition(corev1.ConditionFalse, unikornv1core.ConditionReasonErrored, "server provisioning failed")

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	ctx := controllerContext(t, resource, identity, server)
	err := provisioner.Provision(ctx)
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.False(t, provisioners.IsTerminal(err))
	cli, err := coreclient.FromContext(ctx)
	require.NoError(t, err)

	updatedServer := &unikornv1.Server{}
	require.NoError(t, cli.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: testServerID}, updatedServer))
	require.Equal(t, unikornv1.AttachmentErrored, updatedServer.Status.Volumes[0].ProvisioningStatus)
}

func TestProvisionRetriesAttachment(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	resource.Spec.ClaimRef = &unikornv1.VolumeClaimRef{Kind: unikornv1.VolumeClaimKindServer, ID: testServerID}
	identity := testIdentity(true)
	server := testServer(true)
	server.Spec.Volumes = []unikornv1.ServerVolumeSpec{{ID: testVolumeID}}

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil).Times(2)
	gomock.InOrder(
		provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().AttachVolume(gomock.Any(), identityNamed(), serverNamed(), resource).Return(nil, provisioners.ErrYield),
		provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().AttachVolume(gomock.Any(), identityNamed(), serverNamed(), resource).Return(&providertypes.ServerVolumeAttachment{}, nil),
	)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	ctx := controllerContext(t, resource, identity, server)
	require.ErrorIs(t, provisioner.Provision(ctx), provisioners.ErrYield)
	cli, err := coreclient.FromContext(ctx)
	require.NoError(t, err)

	updatedServer := &unikornv1.Server{}
	require.NoError(t, cli.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: testServerID}, updatedServer))
	require.Equal(t, unikornv1.AttachmentProvisioning, updatedServer.Status.Volumes[0].ProvisioningStatus)
	require.NoError(t, provisioner.Provision(ctx))
	require.NoError(t, cli.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: testServerID}, updatedServer))
	require.Equal(t, unikornv1.AttachmentProvisioned, updatedServer.Status.Volumes[0].ProvisioningStatus)
}

func TestProvisionReconcilesProvisionedVolume(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	resource.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "provisioned")

	identity := testIdentity(true)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	gomock.InOrder(
		provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().DetachVolume(gomock.Any(), identityNamed(), resource).Return(nil),
	)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	require.NoError(t, provisioner.Provision(controllerContext(t, resource, identity)))
}

func TestProvisionWaitsForIdentity(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	identity := testIdentity(false)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	err := provisioner.Provision(controllerContext(t, resource, identity))
	require.ErrorIs(t, err, provisioners.ErrYield)
}

func TestProvisionReturnsProviderYield(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	identity := testIdentity(true)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(provisioners.ErrYield)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	err := provisioner.Provision(controllerContext(t, resource, identity))
	require.ErrorIs(t, err, provisioners.ErrYield)
}

func TestProvisionReturnsProviderError(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	identity := testIdentity(true)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	provider.EXPECT().CreateVolume(gomock.Any(), identityNamed(), resource).Return(errProviderCreate)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	err := provisioner.Provision(controllerContext(t, resource, identity))
	require.ErrorIs(t, err, errProviderCreate)
}

func TestDeprovisionDeletesProviderForUnreadyIdentity(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	identity := testIdentity(false)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	gomock.InOrder(
		provider.EXPECT().DetachVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().DeleteVolume(gomock.Any(), identityNamed(), resource).Return(nil),
	)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	require.NoError(t, provisioner.Deprovision(controllerContext(t, resource, identity)))
}

func TestDeprovisionProviderFailurePreservesAllocation(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(true)
	identity := testIdentity(false)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	gomock.InOrder(
		provider.EXPECT().DetachVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().DeleteVolume(gomock.Any(), identityNamed(), resource).Return(errProviderDelete),
	)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	err := provisioner.Deprovision(controllerContext(t, resource, identity))
	require.ErrorIs(t, err, errProviderDelete)
	require.Equal(t, testAllocationID, resource.Annotations[coreconstants.AllocationAnnotation])
}

func TestDeprovisionProviderAlreadyAbsentReleasesAllocation(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	provider := mocktypes.NewMockProvider(ctrl)
	providerSet := mockproviders.NewMockProviders(ctrl)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	resource := testVolume(true)
	identity := testIdentity(false)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	gomock.InOrder(
		provider.EXPECT().DetachVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().DeleteVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		expectAllocationDelete(mockIdentity, http.StatusAccepted),
	)

	provisioner := volume.NewForTest(resource, providerSet, mockIdentity)
	require.NoError(t, provisioner.Deprovision(controllerContext(t, resource, identity)))
}

func TestDeprovisionUnsupportedProviderPreservesAllocation(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	providerSet := mockproviders.NewMockProviders(ctrl)
	resource := testVolume(true)
	identity := testIdentity(false)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(nil, providers.ErrRegionWrongKind)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	err := provisioner.Deprovision(controllerContext(t, resource, identity))
	require.ErrorIs(t, err, providers.ErrRegionWrongKind)
	require.Equal(t, testAllocationID, resource.Annotations[coreconstants.AllocationAnnotation])
}

func TestDeprovisionProviderLookupFailurePreservesAllocation(t *testing.T) {
	t.Parallel()

	_, providerSet := volumeMocks(t)
	resource := testVolume(true)
	identity := testIdentity(false)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(nil, errProviderLookup)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	err := provisioner.Deprovision(controllerContext(t, resource, identity))
	require.ErrorIs(t, err, errProviderLookup)
	require.Equal(t, testAllocationID, resource.Annotations[coreconstants.AllocationAnnotation])
}

func TestDeprovisionAllocationAlreadyGone(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	provider := mocktypes.NewMockProvider(ctrl)
	providerSet := mockproviders.NewMockProviders(ctrl)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	resource := testVolume(true)
	identity := testIdentity(false)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	gomock.InOrder(
		provider.EXPECT().DetachVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().DeleteVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		expectAllocationDelete(mockIdentity, http.StatusNotFound),
	)

	provisioner := volume.NewForTest(resource, providerSet, mockIdentity)
	require.NoError(t, provisioner.Deprovision(controllerContext(t, resource, identity)))
}

func TestDeprovisionMissingAllocationMetadata(t *testing.T) {
	t.Parallel()

	provider, providerSet := volumeMocks(t)
	resource := testVolume(false)
	identity := testIdentity(false)

	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil)
	gomock.InOrder(
		provider.EXPECT().DetachVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().DeleteVolume(gomock.Any(), identityNamed(), resource).Return(nil),
	)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	require.NoError(t, provisioner.Deprovision(controllerContext(t, resource, identity)))
}

func TestDeprovisionMissingIdentityPreservesAllocation(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	providerSet := mockproviders.NewMockProviders(ctrl)
	resource := testVolume(true)

	provisioner := volume.NewForTest(resource, providerSet, nil)
	err := provisioner.Deprovision(controllerContext(t, resource))
	require.True(t, kerrors.IsNotFound(err))
	require.Equal(t, testAllocationID, resource.Annotations[coreconstants.AllocationAnnotation])
}

func TestDeprovisionRetriesAllocationCleanupAfterProviderCleanup(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	provider := mocktypes.NewMockProvider(ctrl)
	providerSet := mockproviders.NewMockProviders(ctrl)
	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	resource := testVolume(true)
	identity := testIdentity(false)

	firstAllocationDelete := mockIdentity.EXPECT().
		DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDWithResponse(
			gomock.Any(),
			identityids.MustParseOrganizationID(testOrganization),
			identityids.MustParseProjectID(testProject),
			identityids.MustParseAllocationID(testAllocationID),
		).
		Return(nil, errAllocationDelete)

	gomock.InOrder(
		providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil),
		provider.EXPECT().DetachVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().DeleteVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		firstAllocationDelete,
		providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil),
		provider.EXPECT().DetachVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		provider.EXPECT().DeleteVolume(gomock.Any(), identityNamed(), resource).Return(nil),
		expectAllocationDelete(mockIdentity, http.StatusAccepted),
	)

	provisioner := volume.NewForTest(resource, providerSet, mockIdentity)
	ctx := controllerContext(t, resource, identity)

	err := provisioner.Deprovision(ctx)
	require.ErrorIs(t, err, errAllocationDelete)
	require.Equal(t, testAllocationID, resource.Annotations[coreconstants.AllocationAnnotation])

	require.NoError(t, provisioner.Deprovision(ctx))
}
