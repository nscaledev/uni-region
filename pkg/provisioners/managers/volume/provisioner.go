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

package volume

import (
	"context"
	"errors"

	"github.com/spf13/pflag"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	"github.com/unikorn-cloud/region/pkg/provisioners/internal/base"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Options allows access to CLI options in the provisioner.
type Options struct {
	// identityOptions allow the identity host and CA to be set.
	identityOptions *identityclient.Options
	// clientOptions give access to client certificate information for controller-to-API calls.
	clientOptions coreclient.HTTPClientOptions
}

// AddFlags registers the Volume controller's downstream client options.
func (o *Options) AddFlags(f *pflag.FlagSet) {
	if o.identityOptions == nil {
		o.identityOptions = identityclient.NewOptions()
	}

	o.identityOptions.AddFlags(f)
	o.clientOptions.AddFlags(f)
}

// Provisioner reconciles provider-backed Volume lifecycle.
type Provisioner struct {
	provisioners.Metadata

	volume  *unikornv1.Volume
	options *Options

	base.WithIdentity
}

// New returns a new initialized Volume provisioner.
func New(options manager.ControllerOptions, providerSet providers.Providers) provisioners.ManagerProvisioner {
	o, _ := options.(*Options)

	return &Provisioner{
		volume:  &unikornv1.Volume{},
		options: o,
		WithIdentity: base.WithIdentity{
			Base: base.Base{
				Providers: providerSet,
			},
			IdentityClients: base.NewIdentityClientFactory(o.identityOptions, &o.clientOptions),
		},
	}
}

var _ provisioners.ManagerProvisioner = &Provisioner{}

// Object returns the Volume reconciled by this provisioner.
func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.volume
}

// Provision reconciles the desired provider Volume.
func (p *Provisioner) Provision(ctx context.Context) error {
	provider, identity, err := p.ProviderAndIdentity(ctx, p.volume)
	if err != nil {
		return err
	}

	if err := manager.ResourceReady(ctx, identity); err != nil {
		return err
	}

	if err := provider.CreateVolume(ctx, identity, p.volume); err != nil {
		return err
	}

	if err := p.reconcileAttachment(ctx, provider, identity); err != nil {
		return err
	}

	p.volume.Status.ObservedGeneration = &p.volume.Generation

	return nil
}

func (p *Provisioner) reconcileAttachment(ctx context.Context, provider types.Provider, identity *unikornv1.Identity) error {
	if p.volume.Spec.ClaimRef == nil {
		return p.detachAttachment(ctx, provider, identity, p.attachmentForDetach())
	}

	server, exists, err := p.claimedServer(ctx)
	if err != nil {
		return err
	}

	if !exists {
		if err := p.detachAttachment(ctx, provider, identity, p.attachmentForDetach()); err != nil {
			return err
		}

		return provisioners.ErrYield
	}

	if p.volume.Status.Attachment != nil && p.volume.Status.Attachment.ServerID != server.Name {
		return p.replaceAttachment(ctx, provider, identity)
	}

	if server.GetDeletionTimestamp() != nil || !serverRequestsVolume(server, p.volume.Name) {
		return p.detachAttachment(ctx, provider, identity, p.attachmentForDetach())
	}

	return p.reconcileServerAttachment(ctx, provider, identity, server)
}

func (p *Provisioner) claimedServer(ctx context.Context) (*unikornv1.Server, bool, error) {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return nil, false, err
	}

	server := &unikornv1.Server{}

	if err := cli.Get(ctx, client.ObjectKey{Namespace: p.volume.Namespace, Name: p.volume.Spec.ClaimRef.ID}, server); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return nil, false, err
		}

		server.Name = p.volume.Spec.ClaimRef.ID

		return server, false, nil
	}

	return server, true, nil
}

func (p *Provisioner) replaceAttachment(ctx context.Context, provider types.Provider, identity *unikornv1.Identity) error {
	if err := p.detachAttachment(ctx, provider, identity, p.volume.Status.Attachment); err != nil {
		return err
	}

	return provisioners.ErrYield
}

func (p *Provisioner) reconcileServerAttachment(ctx context.Context, provider types.Provider, identity *unikornv1.Identity, server *unikornv1.Server) error {
	condition, err := unikornv1core.GetAvailableCondition(server)
	if err != nil || condition.Reason != unikornv1core.ConditionReasonProvisioned {
		return p.waitForServerAttachment(ctx, server, condition, err)
	}

	attachment, err := provider.AttachVolume(ctx, identity, server, p.volume)
	if err != nil {
		status := unikornv1.AttachmentProvisioning

		if !errors.Is(err, provisioners.ErrYield) {
			status = unikornv1.AttachmentErrored
		}

		if statusErr := p.setAttachmentStatus(ctx, server, status, nil, attachmentMessage(err)); statusErr != nil {
			return statusErr
		}

		return err
	}

	return p.setAttachmentStatus(ctx, server, unikornv1.AttachmentProvisioned, attachment.Device, "")
}

func (p *Provisioner) waitForServerAttachment(ctx context.Context, server *unikornv1.Server, condition *unikornv1core.TypedCondition[unikornv1core.ProvisioningConditionReason], conditionErr error) error {
	if conditionErr == nil && condition.Reason == unikornv1core.ConditionReasonErrored {
		message := "server provisioning failed"

		if err := p.setAttachmentStatus(ctx, server, unikornv1.AttachmentErrored, nil, message); err != nil {
			return err
		}

		return provisioners.ErrYield
	}

	if err := p.setAttachmentStatus(ctx, server, unikornv1.AttachmentProvisioning, nil, "waiting for server provisioning"); err != nil {
		return err
	}

	return provisioners.ErrYield
}

func serverRequestsVolume(server *unikornv1.Server, volumeID string) bool {
	for _, volume := range server.Spec.Volumes {
		if volume.ID == volumeID {
			return true
		}
	}

	return false
}

func attachmentMessage(err error) string {
	var provisioningError *provisioners.Error
	if errors.As(err, &provisioningError) {
		return provisioningError.Message()
	}

	return "an unexpected error occurred"
}

func (p *Provisioner) detachAttachment(ctx context.Context, provider types.Provider, identity *unikornv1.Identity, attachment *unikornv1.VolumeAttachmentStatus) error {
	if attachment == nil {
		return nil
	}

	server := &unikornv1.Server{}
	cli, err := coreclient.FromContext(ctx)

	if err != nil {
		return err
	}

	serverExists := true

	if err := cli.Get(ctx, client.ObjectKey{Namespace: p.volume.Namespace, Name: attachment.ServerID}, server); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return err
		}

		server.Name = attachment.ServerID
		serverExists = false
	}

	if err := provider.DetachVolume(ctx, identity, server, p.volume); err != nil {
		if statusErr := p.setAttachmentStatus(ctx, server, unikornv1.AttachmentDeprovisioning, attachment.Device, attachmentMessage(err)); statusErr != nil {
			return statusErr
		}

		return err
	}

	if !serverExists {
		p.volume.Status.Attachment = nil

		return nil
	}

	server.Status.Volumes = removeServerVolumeStatus(server.Status.Volumes, p.volume.Name)

	if err := cli.Status().Update(ctx, server); err != nil {
		return err
	}

	p.volume.Status.Attachment = nil

	return nil
}

func (p *Provisioner) attachmentForDetach() *unikornv1.VolumeAttachmentStatus {
	if p.volume.Status.Attachment != nil {
		return p.volume.Status.Attachment
	}

	if p.volume.Spec.ClaimRef == nil {
		return nil
	}

	return &unikornv1.VolumeAttachmentStatus{ServerID: p.volume.Spec.ClaimRef.ID}
}

func (p *Provisioner) attachmentDetachTargets() []*unikornv1.VolumeAttachmentStatus {
	targets := []*unikornv1.VolumeAttachmentStatus{}
	if p.volume.Status.Attachment != nil {
		targets = append(targets, p.volume.Status.Attachment)
	}

	if p.volume.Spec.ClaimRef != nil && (p.volume.Status.Attachment == nil || p.volume.Status.Attachment.ServerID != p.volume.Spec.ClaimRef.ID) {
		targets = append(targets, &unikornv1.VolumeAttachmentStatus{ServerID: p.volume.Spec.ClaimRef.ID})
	}

	return targets
}

func (p *Provisioner) setAttachmentStatus(ctx context.Context, server *unikornv1.Server, status unikornv1.AttachmentProvisioningStatus, device *string, message string) error {
	p.volume.Status.Attachment = &unikornv1.VolumeAttachmentStatus{
		ServerID:           server.Name,
		ProvisioningStatus: status,
		Device:             device,
		Message:            message,
	}

	server.Status.Volumes = append(removeServerVolumeStatus(server.Status.Volumes, p.volume.Name), unikornv1.ServerVolumeStatus{
		ID:                 p.volume.Name,
		ProvisioningStatus: status,
		Device:             device,
		Message:            message,
	})

	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	return cli.Status().Update(ctx, server)
}

func removeServerVolumeStatus(volumes []unikornv1.ServerVolumeStatus, volumeID string) []unikornv1.ServerVolumeStatus {
	result := volumes[:0]

	for _, volume := range volumes {
		if volume.ID != volumeID {
			result = append(result, volume)
		}
	}

	return result
}

// Deprovision removes provider state before releasing any Identity allocation.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	provider, identity, err := p.ProviderAndIdentity(ctx, p.volume)
	if err != nil {
		return err
	}

	// Provider cleanup is unconditional and idempotent. The provider owns
	// authoritative rediscovery and already-absent handling, so readiness and
	// best-effort status must never gate this call.
	for _, attachment := range p.attachmentDetachTargets() {
		if err := p.detachAttachment(ctx, provider, identity, attachment); err != nil {
			return err
		}
	}

	if err := provider.DeleteVolume(ctx, identity, p.volume); err != nil {
		return err
	}

	if p.volume.Annotations[coreconstants.AllocationAnnotation] == "" {
		return nil
	}

	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	api, err := p.IdentityClient(ctx, p.volume)
	if err != nil {
		return err
	}

	return identityclient.NewAllocations(cli, api).Delete(ctx, p.volume)
}
