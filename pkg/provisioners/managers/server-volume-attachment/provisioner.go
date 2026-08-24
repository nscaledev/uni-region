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

// Package servervolumeattachment reconciles one attachment as a UNI managed resource.
package servervolumeattachment

import (
	"context"
	"fmt"
	"slices"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coremanager "github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/provisioners/internal/base"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Provisioner struct {
	provisioners.Metadata

	attachment *unikornv1.ServerVolumeAttachment
	base.Base
}

func New(_ coremanager.ControllerOptions, providerSet providers.Providers) provisioners.ManagerProvisioner {
	return &Provisioner{
		Metadata:   provisioners.Metadata{Name: "server-volume-attachment"},
		attachment: &unikornv1.ServerVolumeAttachment{},
		Base:       base.Base{Providers: providerSet},
	}
}

var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.attachment
}

func (p *Provisioner) endpoints(ctx context.Context) (*unikornv1.Server, *unikornv1.Volume, error) {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return nil, nil, err
	}

	server := &unikornv1.Server{}
	if err := cli.Get(ctx, client.ObjectKey{Namespace: p.attachment.Namespace, Name: p.attachment.Spec.ServerID}, server); err != nil {
		return nil, nil, err
	}
	volume := &unikornv1.Volume{}
	if err := cli.Get(ctx, client.ObjectKey{Namespace: p.attachment.Namespace, Name: p.attachment.Spec.VolumeID}, volume); err != nil {
		return nil, nil, err
	}

	return server, volume, nil
}

func (p *Provisioner) addEndpointReferences(ctx context.Context, cli client.Client, server *unikornv1.Server, volume *unikornv1.Volume) (string, error) {
	reference, err := coremanager.GenerateResourceReference(cli, p.attachment)
	if err != nil {
		return "", err
	}

	if err := coremanager.AddResourceReference(ctx, cli, &unikornv1.Server{}, client.ObjectKeyFromObject(server), reference); err != nil {
		return "", err
	}

	if err := coremanager.AddResourceReference(ctx, cli, &unikornv1.Volume{}, client.ObjectKeyFromObject(volume), reference); err != nil {
		return "", err
	}

	return reference, nil
}

func safeguardsPersisted(attachment *unikornv1.ServerVolumeAttachment, server *unikornv1.Server, volume *unikornv1.Volume, reference string) bool {
	return slices.Contains(attachment.Finalizers, coreconstants.Finalizer) &&
		slices.Contains(server.Finalizers, reference) &&
		slices.Contains(volume.Finalizers, reference)
}

func (p *Provisioner) removeEndpointReferences(ctx context.Context, cli client.Client, server *unikornv1.Server, volume *unikornv1.Volume) error {
	reference, err := coremanager.GenerateResourceReference(cli, p.attachment)
	if err != nil {
		return err
	}

	if err := coremanager.RemoveResourceReference(ctx, cli, &unikornv1.Server{}, client.ObjectKeyFromObject(server), reference); err != nil {
		return err
	}

	return coremanager.RemoveResourceReference(ctx, cli, &unikornv1.Volume{}, client.ObjectKeyFromObject(volume), reference)
}

func (p *Provisioner) project(ctx context.Context, cli client.Client, status unikornv1.AttachmentProvisioningStatus, device *string, message string) error {
	server := &unikornv1.Server{}
	if err := cli.Get(ctx, client.ObjectKey{Namespace: p.attachment.Namespace, Name: p.attachment.Spec.ServerID}, server); err != nil {
		return err
	}

	index := slices.IndexFunc(server.Status.Volumes, func(volume unikornv1.ServerVolumeStatus) bool {
		return volume.ID == p.attachment.Spec.VolumeID
	})
	row := unikornv1.ServerVolumeStatus{ID: p.attachment.Spec.VolumeID, ProvisioningStatus: status, Device: device, Message: message}
	if index < 0 {
		server.Status.Volumes = append(server.Status.Volumes, row)
	} else {
		server.Status.Volumes[index] = row
	}

	if err := cli.Status().Update(ctx, server); err != nil {
		if apierrors.IsConflict(err) {
			return provisioners.ErrYield
		}

		return err
	}

	return nil
}

func (p *Provisioner) removeProjection(ctx context.Context, cli client.Client) error {
	server := &unikornv1.Server{}
	if err := cli.Get(ctx, client.ObjectKey{Namespace: p.attachment.Namespace, Name: p.attachment.Spec.ServerID}, server); err != nil {
		return client.IgnoreNotFound(err)
	}

	server.Status.Volumes = slices.DeleteFunc(server.Status.Volumes, func(volume unikornv1.ServerVolumeStatus) bool {
		return volume.ID == p.attachment.Spec.VolumeID
	})

	if err := cli.Status().Update(ctx, server); err != nil {
		if apierrors.IsConflict(err) {
			return provisioners.ErrYield
		}

		return err
	}

	return nil
}

// Provision gates provider work on the durable coordinator claim. Provider work
// is added only after endpoint references and deletion finalization are present.
func (p *Provisioner) Provision(ctx context.Context) error {
	server, volume, err := p.endpoints(ctx)
	if err != nil {
		return err
	}

	if volume.Spec.ClaimRef == nil || volume.Spec.ClaimRef.Kind != unikornv1.VolumeClaimKindServer || volume.Spec.ClaimRef.ID != p.attachment.Spec.ServerID {
		return fmt.Errorf("%w: waiting for the selected volume claim", provisioners.ErrYield)
	}

	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	reference, err := p.addEndpointReferences(ctx, cli, server, volume)
	if err != nil {
		return err
	}

	server, volume, err = p.endpoints(ctx)
	if err != nil {
		return err
	}
	if !safeguardsPersisted(p.attachment, server, volume, reference) {
		return fmt.Errorf("%w: waiting for attachment safeguards", provisioners.ErrYield)
	}

	p.attachment.Status.ObservedGeneration = ptr.To(p.attachment.Generation)

	provider, identity, err := p.ProviderAndIdentity(ctx, server)
	if err != nil {
		return err
	}
	if err := coremanager.ResourceReady(ctx, identity); err != nil {
		return err
	}

	providerAttachment, err := provider.AttachVolume(ctx, identity, server, volume)
	if err != nil {
		return err
	}

	p.attachment.Status.Device = providerAttachment.Device

	return p.project(ctx, cli, unikornv1.AttachmentProvisioned, providerAttachment.Device, "attached")
}

func (p *Provisioner) Deprovision(ctx context.Context) error {
	server, volume, err := p.endpoints(ctx)
	if err != nil {
		return err
	}
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}
	if err := p.project(ctx, cli, unikornv1.AttachmentDeprovisioning, nil, "detaching"); err != nil {
		return err
	}

	provider, identity, err := p.ProviderAndIdentity(ctx, server)
	if err != nil {
		return err
	}
	if err := provider.DetachVolume(ctx, identity, server, volume); err != nil {
		return err
	}

	if err := p.removeEndpointReferences(ctx, cli, server, volume); err != nil {
		return err
	}

	return p.removeProjection(ctx, cli)
}
