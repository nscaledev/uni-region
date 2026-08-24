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

package openstack

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/volumes"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/volumeattach"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/types"
)

func providerResourceNotFound(err error) bool {
	return errors.Is(err, coreerrors.ErrResourceNotFound) ||
		gophercloud.ResponseCodeIs(err, http.StatusNotFound)
}

func serverVolumeAttachment(device string) *types.ServerVolumeAttachment {
	result := &types.ServerVolumeAttachment{}

	if device != "" {
		result.Device = &device
	}

	return result
}

func providerVolumeAttachment(attachment *volumeattach.VolumeAttachment) (*types.ServerVolumeAttachment, error) {
	if attachment == nil {
		return nil, fmt.Errorf("%w: provider returned an empty volume attachment", coreerrors.ErrConsistency)
	}

	return serverVolumeAttachment(attachment.Device), nil
}

func volumeAttachmentForServer(volume *volumes.Volume, serverID string) *volumes.Attachment {
	for i := range volume.Attachments {
		if volume.Attachments[i].ServerID == serverID {
			return &volume.Attachments[i]
		}
	}

	return nil
}

func volumeAttachmentForOtherServer(volume *volumes.Volume, serverID string) *volumes.Attachment {
	for i := range volume.Attachments {
		if volume.Attachments[i].ServerID != serverID {
			return &volume.Attachments[i]
		}
	}

	return nil
}

func volumeAttachmentResources(ctx context.Context, compute ServerInterface, blockStorage VolumeInterface, server *unikornv1.Server, volume *unikornv1.Volume) (*servers.Server, *volumes.Volume, error) {
	openstackServer, err := compute.GetServer(ctx, server)
	if err != nil {
		if providerResourceNotFound(err) {
			return nil, nil, fmt.Errorf("%w: no server found for Region server %s", coreerrors.ErrResourceNotFound, server.Name)
		}

		return nil, nil, err
	}

	cinderVolume, err := blockStorage.GetVolume(ctx, volume)
	if err != nil {
		if providerResourceNotFound(err) {
			return nil, nil, fmt.Errorf("%w: no volume found for Region volume %s", coreerrors.ErrResourceNotFound, volume.Name)
		}

		return nil, nil, err
	}

	return openstackServer, cinderVolume, nil
}

func confirmAttached(ctx context.Context, blockStorage VolumeInterface, serverID string, volume *unikornv1.Volume) (*types.ServerVolumeAttachment, error) {
	cinderVolume, err := blockStorage.GetVolume(ctx, volume)
	if err != nil {
		return nil, err
	}

	if attachment := volumeAttachmentForOtherServer(cinderVolume, serverID); attachment != nil {
		return nil, fmt.Errorf("%w: volume %s is attached to server %s", coreerrors.ErrConflict, cinderVolume.ID, attachment.ServerID)
	}
	if attachment := volumeAttachmentForServer(cinderVolume, serverID); attachment != nil {
		return serverVolumeAttachment(attachment.Device), nil
	}

	return nil, fmt.Errorf("%w: waiting for Cinder to confirm volume attachment", provisioners.ErrYield)
}

func confirmDetached(ctx context.Context, blockStorage VolumeInterface, serverID string, volume *unikornv1.Volume) error {
	cinderVolume, err := blockStorage.GetVolume(ctx, volume)
	if providerResourceNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}

	if volumeAttachmentForServer(cinderVolume, serverID) != nil {
		return fmt.Errorf("%w: waiting for Cinder to confirm volume detachment", provisioners.ErrYield)
	}

	return nil
}

func attachVolume(ctx context.Context, compute ComputeInterface, blockStorage VolumeInterface, server *unikornv1.Server, volume *unikornv1.Volume) (*types.ServerVolumeAttachment, error) {
	openstackServer, cinderVolume, err := volumeAttachmentResources(ctx, compute, blockStorage, server, volume)
	if err != nil {
		return nil, err
	}

	if attachment := volumeAttachmentForOtherServer(cinderVolume, openstackServer.ID); attachment != nil {
		return nil, fmt.Errorf(
			"%w: volume %s is already attached to server %s",
			coreerrors.ErrConflict,
			cinderVolume.ID,
			attachment.ServerID,
		)
	}

	if attachment := volumeAttachmentForServer(cinderVolume, openstackServer.ID); attachment != nil {
		return serverVolumeAttachment(attachment.Device), nil
	}

	attachment, err := compute.CreateVolumeAttachment(ctx, openstackServer.ID, cinderVolume.ID)
	if err == nil {
		if _, err := providerVolumeAttachment(attachment); err != nil {
			return nil, err
		}

		return confirmAttached(ctx, blockStorage, openstackServer.ID, volume)
	}

	if providerResourceNotFound(err) {
		return nil, fmt.Errorf(
			"%w: server %s or volume %s disappeared while creating the attachment",
			coreerrors.ErrResourceNotFound,
			openstackServer.ID,
			cinderVolume.ID,
		)
	}

	if !gophercloud.ResponseCodeIs(err, http.StatusConflict) {
		return nil, err
	}

	// A concurrent request may have created the same attachment between the
	// read and create. Confirm that desired state before surfacing the conflict.
	attachment, getErr := compute.GetVolumeAttachment(ctx, openstackServer.ID, cinderVolume.ID)
	if getErr == nil {
		return providerVolumeAttachment(attachment)
	}

	if !providerResourceNotFound(getErr) {
		return nil, getErr
	}

	return nil, fmt.Errorf(
		"%w: volume %s cannot be attached to server %s in its current state",
		coreerrors.ErrConflict,
		cinderVolume.ID,
		openstackServer.ID,
	)
}

func detachVolume(ctx context.Context, compute ComputeInterface, blockStorage VolumeInterface, server *unikornv1.Server, volume *unikornv1.Volume) error {
	openstackServer, cinderVolume, err := volumeAttachmentResources(ctx, compute, blockStorage, server, volume)
	if err != nil {
		if providerResourceNotFound(err) {
			return nil
		}

		return err
	}

	if volumeAttachmentForServer(cinderVolume, openstackServer.ID) == nil {
		return nil
	}

	if err := compute.DeleteVolumeAttachment(ctx, openstackServer.ID, cinderVolume.ID); err != nil {
		if providerResourceNotFound(err) {
			return nil
		}

		if gophercloud.ResponseCodeIs(err, http.StatusConflict) {
			return fmt.Errorf(
				"%w: volume %s cannot be detached from server %s in its current state",
				coreerrors.ErrConflict,
				cinderVolume.ID,
				openstackServer.ID,
			)
		}

		return err
	}

	return confirmDetached(ctx, blockStorage, openstackServer.ID, volume)
}

func (p *Provider) AttachVolume(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, volume *unikornv1.Volume) (*types.ServerVolumeAttachment, error) {
	compute, err := p.computeFromServicePrincipal(ctx, identity)
	if err != nil {
		return nil, err
	}

	blockStorage, err := p.blockStorageFromServicePrincipal(ctx, identity)
	if err != nil {
		return nil, err
	}

	return attachVolume(ctx, compute, blockStorage, server, volume)
}

func (p *Provider) DetachVolume(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, volume *unikornv1.Volume) error {
	provisioned, err := p.openstackIdentityProvisioned(ctx, identity)
	if err != nil {
		return err
	}

	if !provisioned {
		return nil
	}

	compute, err := p.computeFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	blockStorage, err := p.blockStorageFromServicePrincipal(ctx, identity)
	if err != nil {
		return err
	}

	return detachVolume(ctx, compute, blockStorage, server, volume)
}
