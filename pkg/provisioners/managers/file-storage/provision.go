/*
Copyright 2024-2025 the Unikorn Authors.

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
	"math/big"
	"net"

	"github.com/unikorn-cloud/core/pkg/manager"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/file-storage/provisioners/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	ErrInvalidNetwork = errors.New("invalid network")
)

func (p *Provisioner) reconcileFileStorage(ctx context.Context, cli types.Client) error {
	log := log.FromContext(ctx)
	id := p.makeID()

	// Fetch current file storage details
	fs, err := cli.GetDetails(ctx, id)
	if ignoreNotFound(err) != nil {
		return err
	}

	desiredSize := p.fileStorage.Spec.Size.Value()
	desiredRootSquash := p.fileStorage.Spec.NFS.RootSquash

	// If the resource doesn't exist, create it
	if fs == nil {
		log.V(1).Info("creating file storage", "id", id)
		created, err := cli.Create(ctx, id, desiredSize, desiredRootSquash)

		p.fileStorage.Status.MountPath = &created.Path

		return err // Returns nil if created successfully
	}

	// ensure mountPath is set
	p.fileStorage.Status.MountPath = &fs.Path

	// If it exists but the size differs, resize it
	if fs.Size.Value() != desiredSize {
		log.V(1).Info("resizing file storage", "id", id)
		return cli.Resize(ctx, id, desiredSize)
	}

	// Already in desired state
	return nil
}

func (p *Provisioner) reconcileNetworkAttachments(ctx context.Context, cli client.Client, storageclient types.Client) error {
	id := p.makeID()

	desiredSet, err := p.buildDesiredNetworkSet(ctx, cli)
	if err != nil {
		return err
	}

	currentSet, err := p.buildCurrentNetworkSet(ctx, storageclient, id)
	if err != nil {
		return err
	}

	if err := p.attachMissingNetworks(ctx, storageclient, id, desiredSet, currentSet); err != nil {
		return err
	}

	if err := p.detachStaleNetworks(ctx, storageclient, id, desiredSet, currentSet); err != nil {
		return err
	}

	return nil
}

func (p *Provisioner) getNetwork(ctx context.Context, cli client.Client, networkID string) (*unikornv1.Network, *unikornv1.OpenstackNetwork, error) {
	network := &unikornv1.Network{}
	key := client.ObjectKey{
		Namespace: p.fileStorage.GetNamespace(),
		Name:      networkID,
	}

	if err := cli.Get(ctx, key, network); err != nil {
		return nil, nil, err
	}

	// Inhibit provisioning until the network is ready, as we may need the network information
	// to create attachments e.g. the vlanid in the case of OpenStack.
	if err := manager.ResourceReady(ctx, network); err != nil {
		return nil, nil, err
	}

	// don't
	openstacknetwork := &unikornv1.OpenstackNetwork{}
	if err := cli.Get(ctx, key, openstacknetwork); err != nil {
		return nil, nil, err
	}

	return network, openstacknetwork, nil
}

// buildDesiredNetworkSet constructs the desired VLAN -> networkInfo map
// from the FileStorage spec.
func (p *Provisioner) buildDesiredNetworkSet(ctx context.Context, cli client.Client) (map[int]networkInfo, error) {
	desiredSet := make(map[int]networkInfo, len(p.fileStorage.Spec.Attachments))

	for _, a := range p.fileStorage.Spec.Attachments {
		network, openstackNetwork, err := p.getNetwork(ctx, cli, a.NetworkID)
		if err != nil {
			return nil, err
		}

		if openstackNetwork.Spec.VlanID == nil {
			return nil, fmt.Errorf("%w: network %s has nil VlanID", ErrInvalidNetwork, a.NetworkID)
		}

		ipRange := storageRange(network.Spec.Prefix.IPNet)

		desiredSet[*openstackNetwork.Spec.VlanID] = networkInfo{
			VlanID:  *openstackNetwork.Spec.VlanID,
			IPRange: ipRange,
		}
	}

	return desiredSet, nil
}

// buildCurrentNetworkSet returns a set of currently attached VLAN IDs.
func (p *Provisioner) buildCurrentNetworkSet(ctx context.Context, cli types.Client, id *types.ID) (map[int]struct{}, error) {
	attachments, err := cli.ListAttachments(ctx, id)
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
func (p *Provisioner) attachMissingNetworks(ctx context.Context, cli types.Client, id *types.ID, desiredSet map[int]networkInfo, currentSet map[int]struct{}) error {
	log := log.FromContext(ctx)

	for vlan, d := range desiredSet {
		if _, exists := currentSet[vlan]; exists {
			continue
		}

		log.V(1).Info("attaching network", "vlan", vlan)

		if err := cli.AttachNetwork(ctx, id, d.VlanID, d.IPRange); err != nil {
			return err
		}
	}

	return nil
}

// detachStaleNetworks detaches networks that are currently attached but no longer desired.
func (p *Provisioner) detachStaleNetworks(ctx context.Context, cli types.Client, id *types.ID, desiredSet map[int]networkInfo, currentSet map[int]struct{}) error {
	log := log.FromContext(ctx)

	for vlan := range currentSet {
		if _, desired := desiredSet[vlan]; desired {
			continue
		}

		log.V(1).Info("detaching network", "vlan", vlan)

		if err := cli.DetachNetwork(ctx, id, vlan); err != nil {
			return err
		}
	}

	return nil
}

func storageRange(prefix net.IPNet) *types.IPRange {
	ba := big.NewInt(0).SetBytes(prefix.IP)

	// Start.
	bs := big.NewInt(0).Add(ba, big.NewInt(16))

	// End.
	be := big.NewInt(0).Add(ba, big.NewInt(19))

	return &types.IPRange{
		Start: net.IP(bs.Bytes()),
		End:   net.IP(be.Bytes()),
	}
}

type networkInfo struct {
	VlanID  int
	IPRange *types.IPRange
}
