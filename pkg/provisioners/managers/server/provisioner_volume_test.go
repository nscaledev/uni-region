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

package server_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"
	serverprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/server"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const attachmentVolumeID = "11111111-1111-4111-8111-111111111111"

const replacementVolumeID = "22222222-2222-4222-8222-222222222222"

func attachmentVolume() *regionv1.Volume {
	volume := &regionv1.Volume{
		ObjectMeta: metav1.ObjectMeta{
			Name:      attachmentVolumeID,
			Namespace: "default",
			Labels: map[string]string{
				constants.RegionLabel:   testRegionID,
				constants.IdentityLabel: testIdentityID,
			},
		},
	}
	volume.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "")

	return volume
}

func serverVolumeReference(t *testing.T, cli client.Client, server *regionv1.Server) string {
	t.Helper()

	reference, err := manager.GenerateResourceReference(cli, server)
	require.NoError(t, err)

	return reference
}

func claimVolumeForServer(volume *regionv1.Volume, server *regionv1.Server, reference string) {
	volume.Spec.ClaimRef = &regionv1.VolumeClaimRef{
		Kind: regionv1.VolumeClaimKindServer,
		ID:   server.Name,
	}
	controllerutil.AddFinalizer(volume, reference)
}

func getAttachmentVolume(t *testing.T, cli client.Client) *regionv1.Volume {
	t.Helper()

	volume := &regionv1.Volume{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: "default", Name: attachmentVolumeID}, volume))

	return volume
}

func attachmentProvisioner(t *testing.T, server *regionv1.Server, provider *mocktypes.MockProvider) *serverprovisioner.Provisioner {
	t.Helper()

	providerSet := mockproviders.NewMockProviders(gomock.NewController(t))
	providerSet.EXPECT().LookupCloud(testRegionID).Return(provider, nil).AnyTimes()

	return serverprovisioner.NewForTest(server, providerSet, nil)
}

func TestProvisionClaimsVolumeBeforeAttach(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	server := testProvisionServer(func(server *regionv1.Server) {
		server.Spec.Volumes = []regionv1.ServerVolumeSpec{{ID: attachmentVolumeID}}
	})
	volume := attachmentVolume()
	cli := testProvisionClient(t, server, testProvisionIdentity(), volume)
	reference := serverVolumeReference(t, cli, server)
	device := "/dev/vdb"

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(nil)
	provider.EXPECT().AttachVolume(gomock.Any(), gomock.Any(), server, gomock.Any()).DoAndReturn(
		func(_ any, _ *regionv1.Identity, _ *regionv1.Server, _ *regionv1.Volume) (*types.ServerVolumeAttachment, error) {
			stored := getAttachmentVolume(t, cli)
			require.Equal(t, &regionv1.VolumeClaimRef{Kind: regionv1.VolumeClaimKindServer, ID: server.Name}, stored.Spec.ClaimRef)
			require.True(t, controllerutil.ContainsFinalizer(stored, reference))

			return &types.ServerVolumeAttachment{Device: &device}, nil
		},
	)

	prov := attachmentProvisioner(t, server, provider)
	require.NoError(t, prov.Provision(coreclient.NewContext(t.Context(), cli)))

	require.Equal(t, []regionv1.ServerVolumeStatus{{
		ID:                 attachmentVolumeID,
		ProvisioningStatus: regionv1.AttachmentProvisioned,
		Device:             &device,
		Message:            "volume attached",
	}}, server.Status.Volumes)
}

func TestProvisionConvergesAlreadyClaimedVolume(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	server := testProvisionServer(func(server *regionv1.Server) {
		server.Spec.Volumes = []regionv1.ServerVolumeSpec{{ID: attachmentVolumeID}}
	})
	volume := attachmentVolume()
	cli := testProvisionClient(t, server, testProvisionIdentity(), volume)
	reference := serverVolumeReference(t, cli, server)
	claimVolumeForServer(volume, server, reference)
	cli = testProvisionClient(t, server, testProvisionIdentity(), volume)

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(nil)
	provider.EXPECT().AttachVolume(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(&types.ServerVolumeAttachment{}, nil)

	prov := attachmentProvisioner(t, server, provider)
	require.NoError(t, prov.Provision(coreclient.NewContext(t.Context(), cli)))
	require.Equal(t, regionv1.AttachmentProvisioned, server.Status.Volumes[0].ProvisioningStatus)
	require.Equal(t, server.Name, getAttachmentVolume(t, cli).Spec.ClaimRef.ID)
}

func TestProvisionDetachRetainsClaimUntilConverged(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	server := testProvisionServer()
	volume := attachmentVolume()
	cli := testProvisionClient(t, server, testProvisionIdentity(), volume)
	reference := serverVolumeReference(t, cli, server)
	claimVolumeForServer(volume, server, reference)
	cli = testProvisionClient(t, server, testProvisionIdentity(), volume)

	provider := mocktypes.NewMockProvider(ctrl)
	firstCreate := provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(nil)
	firstDetach := provider.EXPECT().DetachVolume(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(provisioners.ErrYield).After(firstCreate)
	secondCreate := provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(nil).After(firstDetach)
	provider.EXPECT().DetachVolume(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(nil).After(secondCreate)

	prov := attachmentProvisioner(t, server, provider)
	err := prov.Provision(coreclient.NewContext(t.Context(), cli))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Equal(t, regionv1.AttachmentDeprovisioning, server.Status.Volumes[0].ProvisioningStatus)
	require.NotNil(t, getAttachmentVolume(t, cli).Spec.ClaimRef)

	require.NoError(t, prov.Provision(coreclient.NewContext(t.Context(), cli)))
	stored := getAttachmentVolume(t, cli)
	require.Nil(t, stored.Spec.ClaimRef)
	require.False(t, controllerutil.ContainsFinalizer(stored, reference))
	require.Empty(t, server.Status.Volumes)
}

func TestProvisionRejectsClaimConflictBeforeAttach(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	server := testProvisionServer(func(server *regionv1.Server) {
		server.Spec.Volumes = []regionv1.ServerVolumeSpec{{ID: attachmentVolumeID}}
	})
	volume := attachmentVolume()
	volume.Status.Conditions = nil
	volume.Spec.ClaimRef = &regionv1.VolumeClaimRef{Kind: regionv1.VolumeClaimKindServer, ID: "another-server"}
	cli := testProvisionClient(t, server, testProvisionIdentity(), volume)

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(nil)

	prov := attachmentProvisioner(t, server, provider)
	err := prov.Provision(coreclient.NewContext(t.Context(), cli))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.ErrorIs(t, err, coreerrors.ErrConflict)
	require.Equal(t, regionv1.AttachmentProvisioning, server.Status.Volumes[0].ProvisioningStatus)
	require.Equal(t, "another-server", getAttachmentVolume(t, cli).Spec.ClaimRef.ID)
}

func TestProvisionDetachesRemovedVolumeBeforeWaitingForReplacement(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	server := testProvisionServer(func(server *regionv1.Server) {
		server.Spec.Volumes = []regionv1.ServerVolumeSpec{{ID: replacementVolumeID}}
	})
	removed := attachmentVolume()
	replacement := attachmentVolume()
	replacement.Name = replacementVolumeID
	replacement.Status.Conditions = nil
	cli := testProvisionClient(t, server, testProvisionIdentity(), removed, replacement)
	reference := serverVolumeReference(t, cli, server)
	claimVolumeForServer(removed, server, reference)
	cli = testProvisionClient(t, server, testProvisionIdentity(), removed, replacement)

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(nil)
	provider.EXPECT().DetachVolume(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(nil)

	prov := attachmentProvisioner(t, server, provider)
	err := prov.Provision(coreclient.NewContext(t.Context(), cli))
	require.ErrorIs(t, err, provisioners.ErrYield)

	stored := getAttachmentVolume(t, cli)
	require.Nil(t, stored.Spec.ClaimRef)
	require.False(t, controllerutil.ContainsFinalizer(stored, reference))
	require.Equal(t, []regionv1.ServerVolumeStatus{{
		ID:                 replacementVolumeID,
		ProvisioningStatus: regionv1.AttachmentProvisioning,
		Message:            "waiting for volume to be provisioned",
	}}, server.Status.Volumes)
}

func TestProvisionRetriesVolumeAttachmentIndependently(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	server := testProvisionServer(func(server *regionv1.Server) {
		server.Spec.Volumes = []regionv1.ServerVolumeSpec{{ID: attachmentVolumeID}}
	})
	volume := attachmentVolume()
	cli := testProvisionClient(t, server, testProvisionIdentity(), volume)
	reference := serverVolumeReference(t, cli, server)
	device := "/dev/vdb"

	provider := mocktypes.NewMockProvider(ctrl)
	firstCreate := provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(nil)
	firstAttach := provider.EXPECT().AttachVolume(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(nil, provisioners.ErrYield).After(firstCreate)
	secondCreate := provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(nil).After(firstAttach)
	provider.EXPECT().AttachVolume(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(&types.ServerVolumeAttachment{Device: &device}, nil).After(secondCreate)

	prov := attachmentProvisioner(t, server, provider)
	err := prov.Provision(coreclient.NewContext(t.Context(), cli))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Equal(t, regionv1.AttachmentProvisioning, server.Status.Volumes[0].ProvisioningStatus)
	require.NotNil(t, getAttachmentVolume(t, cli).Spec.ClaimRef)
	require.True(t, controllerutil.ContainsFinalizer(getAttachmentVolume(t, cli), reference))

	require.NoError(t, prov.Provision(coreclient.NewContext(t.Context(), cli)))
	require.Equal(t, regionv1.AttachmentProvisioned, server.Status.Volumes[0].ProvisioningStatus)
	require.Equal(t, &device, server.Status.Volumes[0].Device)
}

func TestDeprovisionDetachesAndReleasesVolumesBeforeServerDelete(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	server := testProvisionServer(func(server *regionv1.Server) {
		server.Spec.Volumes = []regionv1.ServerVolumeSpec{{ID: attachmentVolumeID}}
	})
	volume := attachmentVolume()
	cli := testProvisionClient(t, server, testProvisionIdentity(), volume)
	reference := serverVolumeReference(t, cli, server)
	claimVolumeForServer(volume, server, reference)
	cli = testProvisionClient(t, server, testProvisionIdentity(), volume)

	provider := mocktypes.NewMockProvider(ctrl)
	detach := provider.EXPECT().DetachVolume(gomock.Any(), gomock.Any(), server, gomock.Any()).DoAndReturn(
		func(_ any, _ *regionv1.Identity, _ *regionv1.Server, _ *regionv1.Volume) error {
			stored := getAttachmentVolume(t, cli)
			require.NotNil(t, stored.Spec.ClaimRef)
			require.True(t, controllerutil.ContainsFinalizer(stored, reference))

			return nil
		},
	)
	provider.EXPECT().DeleteServer(gomock.Any(), gomock.Any(), server).DoAndReturn(
		func(_ any, _ *regionv1.Identity, _ *regionv1.Server) error {
			stored := getAttachmentVolume(t, cli)
			require.Nil(t, stored.Spec.ClaimRef)
			require.False(t, controllerutil.ContainsFinalizer(stored, reference))

			return nil
		},
	).After(detach)

	prov := attachmentProvisioner(t, server, provider)
	require.NoError(t, prov.Deprovision(coreclient.NewContext(t.Context(), cli)))
}
