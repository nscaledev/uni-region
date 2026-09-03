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

package openstack_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/volumes"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/volumeattach"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack/mock"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	providerVolumeID = "provider-volume-id"
	otherServerID    = "other-server-id"
	volumeDevice     = "/dev/vdb"
)

var errVolumeAttachmentProvider = errors.New("nova unavailable")

func volumeAttachmentVolumeFixture() *regionv1.Volume {
	return &regionv1.Volume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "aaaaaaaa-0000-0000-0000-000000000001",
		},
	}
}

func cinderVolumeFixture(volume *regionv1.Volume) *volumes.Volume {
	return &volumes.Volume{
		ID:   providerVolumeID,
		Name: "volume-" + volume.Name,
	}
}

func cinderVolumeWithAttachment(volume *volumes.Volume, serverID string, multiattach bool) *volumes.Volume {
	result := *volume
	result.Multiattach = multiattach
	result.Attachments = []volumes.Attachment{
		{
			AttachmentID: "provider-attachment-id",
			Device:       volumeDevice,
			ID:           volume.ID,
			ServerID:     serverID,
			VolumeID:     volume.ID,
		},
	}

	return &result
}

func novaVolumeAttachmentFixture(server *servers.Server, volume *volumes.Volume) *volumeattach.VolumeAttachment {
	return &volumeattach.VolumeAttachment{
		Device:   volumeDevice,
		VolumeID: volume.ID,
		ServerID: server.ID,
	}
}

func requireVolumeAttachment(t *testing.T, attachmentDevice *string) {
	t.Helper()

	require.NotNil(t, attachmentDevice)
	require.Equal(t, volumeDevice, *attachmentDevice)
}

func TestAttachVolume(t *testing.T) {
	t.Parallel()

	server := serverFixture()
	volume := volumeAttachmentVolumeFixture()
	openstackServer := openstackServerFixture(server)
	cinderVolume := cinderVolumeFixture(volume)
	novaAttachment := novaVolumeAttachmentFixture(openstackServer, cinderVolume)
	notFound := gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusNotFound}

	t.Run("AttachesExistingVolume", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		compute := mock.NewMockComputeInterface(c)
		blockStorage := mock.NewMockVolumeInterface(c)

		compute.EXPECT().GetServer(t.Context(), server).Return(openstackServer, nil)
		blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(cinderVolume, nil)
		compute.EXPECT().CreateVolumeAttachment(t.Context(), openstackServer.ID, cinderVolume.ID).Return(novaAttachment, nil)

		attachment, err := openstack.AttachVolumeWithClients(t.Context(), compute, blockStorage, server, volume)
		require.NoError(t, err)
		require.NotNil(t, attachment)
		requireVolumeAttachment(t, attachment.Device)
	})

	t.Run("AlreadyAttachedIsIdempotent", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		compute := mock.NewMockComputeInterface(c)
		blockStorage := mock.NewMockVolumeInterface(c)
		attachedVolume := cinderVolumeWithAttachment(cinderVolume, openstackServer.ID, false)

		compute.EXPECT().GetServer(t.Context(), server).Return(openstackServer, nil)
		blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(attachedVolume, nil)

		attachment, err := openstack.AttachVolumeWithClients(t.Context(), compute, blockStorage, server, volume)
		require.NoError(t, err)
		require.NotNil(t, attachment)
		requireVolumeAttachment(t, attachment.Device)
	})

	t.Run("AttachedToDifferentServerReturnsConflictEvenWhenMultiattachCapable", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		compute := mock.NewMockComputeInterface(c)
		blockStorage := mock.NewMockVolumeInterface(c)
		attachedVolume := cinderVolumeWithAttachment(cinderVolume, otherServerID, true)

		compute.EXPECT().GetServer(t.Context(), server).Return(openstackServer, nil)
		blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(attachedVolume, nil)

		attachment, err := openstack.AttachVolumeWithClients(t.Context(), compute, blockStorage, server, volume)
		require.ErrorIs(t, err, coreerrors.ErrConflict)
		require.Nil(t, attachment)
	})

	t.Run("MissingServerReturnsNotFound", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		compute := mock.NewMockComputeInterface(c)
		blockStorage := mock.NewMockVolumeInterface(c)

		compute.EXPECT().GetServer(t.Context(), server).Return(nil, coreerrors.ErrResourceNotFound)

		attachment, err := openstack.AttachVolumeWithClients(t.Context(), compute, blockStorage, server, volume)
		require.ErrorIs(t, err, coreerrors.ErrResourceNotFound)
		require.Nil(t, attachment)
	})

	t.Run("MissingVolumeReturnsNotFound", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		compute := mock.NewMockComputeInterface(c)
		blockStorage := mock.NewMockVolumeInterface(c)

		compute.EXPECT().GetServer(t.Context(), server).Return(openstackServer, nil)
		blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(nil, coreerrors.ErrResourceNotFound)

		attachment, err := openstack.AttachVolumeWithClients(t.Context(), compute, blockStorage, server, volume)
		require.ErrorIs(t, err, coreerrors.ErrResourceNotFound)
		require.Nil(t, attachment)
	})

	t.Run("CreateNotFoundReturnsNotFound", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		compute := mock.NewMockComputeInterface(c)
		blockStorage := mock.NewMockVolumeInterface(c)

		compute.EXPECT().GetServer(t.Context(), server).Return(openstackServer, nil)
		blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(cinderVolume, nil)
		compute.EXPECT().CreateVolumeAttachment(t.Context(), openstackServer.ID, cinderVolume.ID).Return(nil, notFound)

		attachment, err := openstack.AttachVolumeWithClients(t.Context(), compute, blockStorage, server, volume)
		require.ErrorIs(t, err, coreerrors.ErrResourceNotFound)
		require.Nil(t, attachment)
	})

	t.Run("ConcurrentAttachConflictBecomesSuccess", func(t *testing.T) {
		t.Parallel()

		conflict := gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusConflict}
		c := gomock.NewController(t)
		compute := mock.NewMockComputeInterface(c)
		blockStorage := mock.NewMockVolumeInterface(c)

		compute.EXPECT().GetServer(t.Context(), server).Return(openstackServer, nil)
		blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(cinderVolume, nil)
		compute.EXPECT().CreateVolumeAttachment(t.Context(), openstackServer.ID, cinderVolume.ID).Return(nil, conflict)
		compute.EXPECT().GetVolumeAttachment(t.Context(), openstackServer.ID, cinderVolume.ID).Return(novaAttachment, nil)

		attachment, err := openstack.AttachVolumeWithClients(t.Context(), compute, blockStorage, server, volume)
		require.NoError(t, err)
		require.NotNil(t, attachment)
		requireVolumeAttachment(t, attachment.Device)
	})

	t.Run("UnresolvedConflictReturnsConflict", func(t *testing.T) {
		t.Parallel()

		conflict := gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusConflict}
		c := gomock.NewController(t)
		compute := mock.NewMockComputeInterface(c)
		blockStorage := mock.NewMockVolumeInterface(c)

		compute.EXPECT().GetServer(t.Context(), server).Return(openstackServer, nil)
		blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(cinderVolume, nil)
		compute.EXPECT().CreateVolumeAttachment(t.Context(), openstackServer.ID, cinderVolume.ID).Return(nil, conflict)
		compute.EXPECT().GetVolumeAttachment(t.Context(), openstackServer.ID, cinderVolume.ID).Return(nil, notFound)

		attachment, err := openstack.AttachVolumeWithClients(t.Context(), compute, blockStorage, server, volume)
		require.ErrorIs(t, err, coreerrors.ErrConflict)
		require.Nil(t, attachment)
	})

	t.Run("ProviderErrorIsPreserved", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		compute := mock.NewMockComputeInterface(c)
		blockStorage := mock.NewMockVolumeInterface(c)

		compute.EXPECT().GetServer(t.Context(), server).Return(openstackServer, nil)
		blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(cinderVolume, nil)
		compute.EXPECT().CreateVolumeAttachment(t.Context(), openstackServer.ID, cinderVolume.ID).Return(nil, errVolumeAttachmentProvider)

		attachment, err := openstack.AttachVolumeWithClients(t.Context(), compute, blockStorage, server, volume)
		require.ErrorIs(t, err, errVolumeAttachmentProvider)
		require.Nil(t, attachment)
	})
}

func TestDetachVolume(t *testing.T) {
	t.Parallel()

	server := serverFixture()
	volume := volumeAttachmentVolumeFixture()
	openstackServer := openstackServerFixture(server)
	cinderVolume := cinderVolumeFixture(volume)
	notFound := gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusNotFound}

	t.Run("DetachesExistingVolume", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		compute := mock.NewMockComputeInterface(c)
		blockStorage := mock.NewMockVolumeInterface(c)
		attachedVolume := cinderVolumeWithAttachment(cinderVolume, openstackServer.ID, false)
		attachedVolume.Attachments = append(attachedVolume.Attachments, volumes.Attachment{ServerID: otherServerID})

		gomock.InOrder(
			blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(attachedVolume, nil),
			compute.EXPECT().DeleteVolumeAttachment(t.Context(), openstackServer.ID, cinderVolume.ID).Return(nil),
			compute.EXPECT().DeleteVolumeAttachment(t.Context(), otherServerID, cinderVolume.ID).Return(nil),
			blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(cinderVolume, nil),
		)

		require.NoError(t, openstack.DetachVolumeWithClients(t.Context(), compute, blockStorage, server, volume))
	})

	t.Run("AcceptedDetachYieldsUntilAttachmentIsGone", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		compute := mock.NewMockComputeInterface(c)
		blockStorage := mock.NewMockVolumeInterface(c)
		attachedVolume := cinderVolumeWithAttachment(cinderVolume, openstackServer.ID, false)

		gomock.InOrder(
			blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(attachedVolume, nil),
			compute.EXPECT().DeleteVolumeAttachment(t.Context(), openstackServer.ID, cinderVolume.ID).Return(nil),
			blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(attachedVolume, nil),
		)

		err := openstack.DetachVolumeWithClients(t.Context(), compute, blockStorage, server, volume)
		require.ErrorIs(t, err, provisioners.ErrYield)
	})

	t.Run("AlreadyDetachedIsIdempotent", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		compute := mock.NewMockComputeInterface(c)
		blockStorage := mock.NewMockVolumeInterface(c)

		blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(cinderVolume, nil)

		require.NoError(t, openstack.DetachVolumeWithClients(t.Context(), compute, blockStorage, server, volume))
	})

	t.Run("DetachesAttachmentFromDifferentServer", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		compute := mock.NewMockComputeInterface(c)
		blockStorage := mock.NewMockVolumeInterface(c)
		attachedVolume := cinderVolumeWithAttachment(cinderVolume, otherServerID, true)

		gomock.InOrder(
			blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(attachedVolume, nil),
			compute.EXPECT().DeleteVolumeAttachment(t.Context(), otherServerID, cinderVolume.ID).Return(nil),
			blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(cinderVolume, nil),
		)

		require.NoError(t, openstack.DetachVolumeWithClients(t.Context(), compute, blockStorage, server, volume))
	})

	t.Run("MissingVolumeIsIdempotent", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		compute := mock.NewMockComputeInterface(c)
		blockStorage := mock.NewMockVolumeInterface(c)

		blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(nil, coreerrors.ErrResourceNotFound)

		require.NoError(t, openstack.DetachVolumeWithClients(t.Context(), compute, blockStorage, server, volume))
	})

	t.Run("DeleteNotFoundYieldsWhileCinderReportsAttachment", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		compute := mock.NewMockComputeInterface(c)
		blockStorage := mock.NewMockVolumeInterface(c)
		attachedVolume := cinderVolumeWithAttachment(cinderVolume, openstackServer.ID, false)

		gomock.InOrder(
			blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(attachedVolume, nil),
			compute.EXPECT().DeleteVolumeAttachment(t.Context(), openstackServer.ID, cinderVolume.ID).Return(notFound),
			blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(attachedVolume, nil),
		)

		err := openstack.DetachVolumeWithClients(t.Context(), compute, blockStorage, server, volume)
		require.ErrorIs(t, err, provisioners.ErrYield)
	})

	t.Run("ConflictReturnsConflict", func(t *testing.T) {
		t.Parallel()

		conflict := gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusConflict}
		c := gomock.NewController(t)
		compute := mock.NewMockComputeInterface(c)
		blockStorage := mock.NewMockVolumeInterface(c)
		attachedVolume := cinderVolumeWithAttachment(cinderVolume, openstackServer.ID, false)

		blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(attachedVolume, nil)
		compute.EXPECT().DeleteVolumeAttachment(t.Context(), openstackServer.ID, cinderVolume.ID).Return(conflict)

		err := openstack.DetachVolumeWithClients(t.Context(), compute, blockStorage, server, volume)
		require.ErrorIs(t, err, coreerrors.ErrConflict)
	})

	t.Run("ProviderErrorIsPreserved", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		compute := mock.NewMockComputeInterface(c)
		blockStorage := mock.NewMockVolumeInterface(c)
		attachedVolume := cinderVolumeWithAttachment(cinderVolume, openstackServer.ID, false)

		blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(attachedVolume, nil)
		compute.EXPECT().DeleteVolumeAttachment(t.Context(), openstackServer.ID, cinderVolume.ID).Return(errVolumeAttachmentProvider)

		err := openstack.DetachVolumeWithClients(t.Context(), compute, blockStorage, server, volume)
		require.ErrorIs(t, err, errVolumeAttachmentProvider)
	})
}

func TestDetachVolumeNoopsForUnrealizedIdentity(t *testing.T) {
	t.Parallel()

	identity := identityFixture()
	volume := volumeAttachmentVolumeFixture()

	t.Run("BackingIdentityAbsent", func(t *testing.T) {
		t.Parallel()

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())
		require.NoError(t, p.DetachVolume(t.Context(), identity, volume))
	})

	t.Run("ProjectNotAllocated", func(t *testing.T) {
		t.Parallel()

		objects := []client.Object{unrealizedOpenstackIdentityFixture(identity)}
		p := openstack.NewTestProvider(getClient(t, objects), regionFixture())

		require.NoError(t, p.DetachVolume(t.Context(), identity, volume))
	})
}
