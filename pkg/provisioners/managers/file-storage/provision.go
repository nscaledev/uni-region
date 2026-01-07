/*
Copyright 2024-2025 the Unikorn Authors.
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

package filestorage

import (
	"context"
	"errors"
	"fmt"
	"slices"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/manager"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/file-storage/provisioners/types"

	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	ErrInvalidNetwork = errors.New("invalid network")
)

func (p *Provisioner) reconcileFileStorage(ctx context.Context, driver types.Driver) error {
	log := log.FromContext(ctx)

	// Fetch current file storage details
	fs, err := driver.GetDetails(ctx, p.fileStorage.Labels[coreconstants.ProjectLabel], p.fileStorage.Name)
	if ignoreNotFound(err) != nil {
		return err
	}

	desiredSize := p.fileStorage.Spec.Size.Value()
	desiredRootSquash := p.fileStorage.Spec.NFS.RootSquash

	// If the resource doesn't exist, create it
	if fs == nil {
		log.V(1).Info("creating file storage", "id", p.fileStorage.Name)

		created, err := driver.Create(ctx, p.fileStorage.Labels[coreconstants.ProjectLabel], p.fileStorage.Name, desiredSize, desiredRootSquash)
		if err != nil {
			return err
		}

		p.fileStorage.Status.MountPath = &created.Path

		return nil // Returns nil if created successfully
	}

	// ensure mountPath is set
	p.fileStorage.Status.MountPath = &fs.Path

	// If it exists but the size differs, resize it
	if fs.Size.Value() != desiredSize {
		log.V(1).Info("resizing file storage", "id", p.fileStorage.Name)
		return driver.Resize(ctx, p.fileStorage.Labels[coreconstants.ProjectLabel], p.fileStorage.Name, desiredSize)
	}

	// Already in desired state
	return nil
}

func (p *Provisioner) reconcileNetworkAttachments(ctx context.Context, cli client.Client, driver types.Driver, reference string) error {
	desiredSet, err := p.buildDesiredNetworkSet()
	if err != nil {
		return err
	}

	currentSet, err := p.buildCurrentNetworkSet(ctx, driver)
	if err != nil {
		return err
	}

	if err := p.attachMissingNetworks(ctx, cli, driver, desiredSet, currentSet, reference); err != nil {
		return err
	}

	if err := p.detachStaleNetworks(ctx, cli, driver, desiredSet, currentSet, reference); err != nil {
		return err
	}

	return nil
}

// buildDesiredNetworkSet constructs the desired VLAN -> networkInfo map
// from the FileStorage spec.
func (p *Provisioner) buildDesiredNetworkSet() (map[int]unikornv1.Attachment, error) {
	desiredSet := make(map[int]unikornv1.Attachment, len(p.fileStorage.Spec.Attachments))

	for _, a := range p.fileStorage.Spec.Attachments {
		if a.SegmentationID == nil {
			return nil, fmt.Errorf("%w: network %s has nil SegmentationID", ErrInvalidNetwork, a.NetworkID)
		}

		if a.IPRange == nil {
			return nil, fmt.Errorf("%w: network %s has nil IPRange", ErrInvalidNetwork, a.NetworkID)
		}

		desiredSet[*a.SegmentationID] = a
	}

	return desiredSet, nil
}

// buildCurrentNetworkSet returns a set of currently attached VLAN IDs.
func (p *Provisioner) buildCurrentNetworkSet(ctx context.Context, driver types.Driver) (map[int]struct{}, error) {
	attachments, err := driver.ListAttachments(ctx, p.fileStorage.Labels[coreconstants.ProjectLabel], p.fileStorage.Name)
	if err = ignoreNotFound(err); err != nil {
		return nil, err
	}

	currentSet := make(map[int]struct{}, len(attachments.Items))
	for _, a := range attachments.Items {
		currentSet[a.VlanID] = struct{}{}
	}

	return currentSet, nil
}

// attachMissingNetworks attaches networks that are desired but not yet attached.
func (p *Provisioner) attachMissingNetworks(ctx context.Context, cli client.Client, driver types.Driver, desiredSet map[int]unikornv1.Attachment, currentSet map[int]struct{}, reference string) error {
	log := log.FromContext(ctx)

	for vlan, attachment := range desiredSet {
		if _, exists := currentSet[vlan]; exists {
			setNetworkAttachmentStatus(p.fileStorage, attachment.NetworkID, attachment.SegmentationID, unikornv1.AttachmentProvisioned, "")

			continue
		}

		log.V(1).Info("attaching network", "vlan", vlan)

		// Add references to any resources we consume.
		if err := manager.AddResourceReference(ctx, cli, &unikornv1.Network{}, client.ObjectKey{Namespace: p.fileStorage.Namespace, Name: attachment.NetworkID}, reference); err != nil {
			setNetworkAttachmentStatus(p.fileStorage, attachment.NetworkID, attachment.SegmentationID, unikornv1.AttachmentErrored, err.Error())

			return fmt.Errorf("%w: failed to add network references", err)
		}

		if err := driver.AttachNetwork(ctx, p.fileStorage.Labels[coreconstants.ProjectLabel], p.fileStorage.Name, &attachment); err != nil {
			setNetworkAttachmentStatus(p.fileStorage, attachment.NetworkID, attachment.SegmentationID, unikornv1.AttachmentErrored, err.Error())

			return err
		}

		setNetworkAttachmentStatus(p.fileStorage, attachment.NetworkID, attachment.SegmentationID, unikornv1.AttachmentProvisioned, "")
	}

	return nil
}

// detachStaleNetworks detaches networks that are currently attached but no longer desired.
func (p *Provisioner) detachStaleNetworks(ctx context.Context, cli client.Client, driver types.Driver, desiredSet map[int]unikornv1.Attachment, currentSet map[int]struct{}, reference string) error {
	log := log.FromContext(ctx)

	for vlan := range currentSet {
		if _, desired := desiredSet[vlan]; desired {
			continue
		}

		log.V(1).Info("detaching network", "vlan", vlan)

		if err := driver.DetachNetwork(ctx, p.fileStorage.Labels[coreconstants.ProjectLabel], p.fileStorage.Name, vlan); err != nil {
			setVLanAttachmentStatus(p.fileStorage, vlan, unikornv1.AttachmentErrored, err.Error())

			return err
		}

		removeAttachmentStatus(p.fileStorage, vlan)
	}

	// Remove references to networks no longer attached. Since the driver (vast) is the source of truth for attachments but does not track network IDs,
	// we must list all candidate networks and check which are no longer referenced in fileStorage attachments.
	options := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{
			coreconstants.OrganizationLabel: p.fileStorage.Labels[coreconstants.OrganizationLabel],
			coreconstants.ProjectLabel:      p.fileStorage.Labels[coreconstants.ProjectLabel],
			constants.RegionLabel:           p.fileStorage.Labels[constants.RegionLabel],
		}),
	}

	networks := &unikornv1.NetworkList{}
	if err := cli.List(ctx, networks, options); err != nil {
		return err
	}

	for _, network := range networks.Items {
		// skip networks that don't have this reference.
		if !slices.Contains(network.Finalizers, reference) {
			continue
		}

		// if the fileStorage still has an attachment to this network, keep the reference.
		if p.isNetworkStillAttached(network.Name) {
			continue
		}

		if err := manager.RemoveResourceReference(ctx, cli, &unikornv1.Network{}, client.ObjectKeyFromObject(&network), reference); err != nil {
			return fmt.Errorf("%w: failed to remove network references", err)
		}
	}

	return nil
}

func (p *Provisioner) isNetworkStillAttached(networkName string) bool {
	for _, attachment := range p.fileStorage.Spec.Attachments {
		if attachment.NetworkID == networkName {
			return true
		}
	}

	return false
}
