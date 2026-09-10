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
	"strings"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/volumes"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
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

func observedVolumeAttachment(cinderVolume *volumes.Volume, serverID string) (*types.ServerVolumeAttachment, bool, error) {
	if attachment := volumeAttachmentForOtherServer(cinderVolume, serverID); attachment != nil {
		return nil, false, fmt.Errorf(
			"%w: volume %s is already attached to server %s",
			coreerrors.ErrConflict,
			cinderVolume.ID,
			attachment.ServerID,
		)
	}

	if strings.HasPrefix(cinderVolume.Status, volumeStatusErrorPrefix) {
		return nil, false, provisioners.Terminal(unikornv1core.ConditionReasonErrored, "provider volume entered an error state")
	}

	attachment := volumeAttachmentForServer(cinderVolume, serverID)
	if attachment == nil {
		return nil, false, nil
	}

	if cinderVolume.Status != volumeStatusInUse {
		return nil, true, provisioners.ErrYield
	}

	return serverVolumeAttachment(attachment.Device), true, nil
}

func attachVolume(ctx context.Context, compute ComputeInterface, blockStorage VolumeInterface, server *unikornv1.Server, volume *unikornv1.Volume) (*types.ServerVolumeAttachment, error) {
	openstackServer, cinderVolume, err := volumeAttachmentResources(ctx, compute, blockStorage, server, volume)
	if err != nil {
		return nil, err
	}

	attachment, observed, err := observedVolumeAttachment(cinderVolume, openstackServer.ID)
	if observed || err != nil {
		return attachment, err
	}

	if cinderVolume.Status != volumeStatusAvailable {
		return nil, provisioners.ErrYield
	}

	_, err = compute.CreateVolumeAttachment(ctx, openstackServer.ID, cinderVolume.ID)
	if err == nil {
		return nil, provisioners.ErrYield
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
	_, getErr := compute.GetVolumeAttachment(ctx, openstackServer.ID, cinderVolume.ID)
	if getErr == nil {
		return nil, provisioners.ErrYield
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

func detachVolume(ctx context.Context, compute ComputeInterface, blockStorage VolumeInterface, server *unikornv1.Server, volume *unikornv1.Volume, serverDeleting bool) error {
	cinderVolume, err := blockStorage.GetVolume(ctx, volume)
	if err != nil {
		if providerResourceNotFound(err) {
			return nil
		}

		return err
	}

	if server != nil {
		detachRequested, err := requestServerVolumeDetach(ctx, compute, server, cinderVolume.ID, serverDeleting)
		if err != nil {
			return err
		}

		if detachRequested {
			// Nova detach is asynchronous. Verify Nova and Cinder again on the
			// next reconciliation before allowing the claim to be released.
			return provisioners.ErrYield
		}
	}

	// Region does not expose multiattach, so one Cinder attachment is the only
	// supported fallback when Nova could not confirm the claimed relationship.
	if len(cinderVolume.Attachments) != 0 {
		attachment := cinderVolume.Attachments[0]
		if err := deleteVolumeAttachment(ctx, compute, attachment.ServerID, cinderVolume.ID); err != nil {
			return err
		}

		return provisioners.ErrYield
	}

	// An empty Cinder attachment list is not enough: during the reproduced race,
	// Cinder returned [] while the Volume was still attaching or detaching.
	if cinderVolume.Status != volumeStatusAvailable {
		return provisioners.ErrYield
	}

	return nil
}

func requestServerVolumeDetach(ctx context.Context, compute ComputeInterface, server *unikornv1.Server, volumeID string, serverDeleting bool) (bool, error) {
	openstackServer, err := compute.GetServer(ctx, server)
	if err != nil {
		if providerResourceNotFound(err) {
			return false, nil
		}

		return false, err
	}

	if serverDeleting {
		return false, provisioners.ErrYield
	}

	// Cinder can report Attachments=[] while Nova still owns the attachment,
	// so always query Nova while the claimed Region Server is available.
	_, err = compute.GetVolumeAttachment(ctx, openstackServer.ID, volumeID)
	if err != nil {
		if providerResourceNotFound(err) {
			return false, nil
		}

		return false, err
	}

	if err := deleteVolumeAttachment(ctx, compute, openstackServer.ID, volumeID); err != nil {
		return false, err
	}

	return true, nil
}

func deleteVolumeAttachment(ctx context.Context, compute ComputeInterface, serverID, volumeID string) error {
	err := compute.DeleteVolumeAttachment(ctx, serverID, volumeID)
	if err == nil {
		return nil
	}

	if providerResourceNotFound(err) {
		return nil
	}

	if gophercloud.ResponseCodeIs(err, http.StatusBadRequest) {
		return provisioners.ErrYield
	}

	if gophercloud.ResponseCodeIs(err, http.StatusConflict) {
		return fmt.Errorf("%w: volume %s cannot be detached from server %s in its current state", coreerrors.ErrConflict, volumeID, serverID)
	}

	return err
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

func (p *Provider) DetachVolume(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, volume *unikornv1.Volume, serverDeleting bool) error {
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

	return detachVolume(ctx, compute, blockStorage, server, volume, serverDeleting)
}
