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
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	"github.com/unikorn-cloud/region/pkg/provisioners/internal/base"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
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

	if err := p.reconcileVolume(ctx, provider, identity); err != nil {
		return err
	}

	p.volume.Status.ObservedGeneration = &p.volume.Generation

	return nil
}

func (p *Provisioner) reconcileVolume(ctx context.Context, provider types.Provider, identity *unikornv1.Identity) error {
	if p.volume.Spec.ClaimRef == nil {
		p.volume.Status.AttachedAt = nil

		if err := manager.ResourceReady(ctx, identity); err != nil {
			return err
		}

		return provider.CreateVolume(ctx, identity, p.volume)
	}

	server, exists, err := p.claimedServer(ctx)
	if err != nil {
		return err
	}

	if exists {
		return p.reconcileServerClaim(ctx, provider, identity, server)
	}

	// The create saga claims before writing the Server. Without a confirmed
	// attachment, wait for that write or its compensation to become visible.
	if p.volume.Status.AttachedAt == nil {
		return provisioners.ErrYield
	}

	return p.teardownClaim(ctx, provider, identity, nil, "")
}

func (p *Provisioner) reconcileServerClaim(ctx context.Context, provider types.Provider, identity *unikornv1.Identity, server *unikornv1.Server) error {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	reference, err := manager.GenerateResourceReference(cli, p.volume)
	if err != nil {
		return err
	}

	// Keep the claim available to the provider until it confirms teardown, then
	// release it because the Server is going away or no longer wants the Volume.
	if server.GetDeletionTimestamp() != nil {
		return p.teardownClaim(ctx, provider, identity, server, reference)
	}

	if !serverRequestsVolume(server, p.volume.Name) {
		// The update saga claims before writing Server intent. Without a confirmed
		// attachment or controller reference, wait for that write or its compensation.
		if p.volume.Status.AttachedAt == nil && !controllerutil.ContainsFinalizer(server, reference) {
			return provisioners.ErrYield
		}

		return p.teardownClaim(ctx, provider, identity, server, reference)
	}

	if err := manager.AddResourceReference(ctx, cli, &unikornv1.Server{}, client.ObjectKeyFromObject(server), reference); err != nil {
		return err
	}

	return p.reconcileReferencedVolume(ctx, provider, identity, reference)
}

func (p *Provisioner) reconcileReferencedVolume(ctx context.Context, provider types.Provider, identity *unikornv1.Identity, reference string) error {
	// Re-read after placing the reference so a concurrent update cannot attach a
	// Volume that the Server no longer requests.
	server, exists, err := p.claimedServer(ctx)
	if err != nil {
		return err
	}

	if !exists {
		return provisioners.ErrYield
	}

	if server.GetDeletionTimestamp() != nil || !serverRequestsVolume(server, p.volume.Name) {
		return p.teardownClaim(ctx, provider, identity, server, reference)
	}

	if err := manager.ResourceReady(ctx, identity); err != nil {
		return err
	}

	return p.reconcileClaimedVolume(ctx, provider, identity, server)
}

func (p *Provisioner) teardownClaim(ctx context.Context, provider types.Provider, identity *unikornv1.Identity, server *unikornv1.Server, reference string) error {
	// Preserve the Server until the provider has confirmed Nova and Cinder agree
	// that the attachment is gone. Releasing the claim earlier loses that context.
	if err := p.detachAttachments(ctx, provider, identity, server); err != nil {
		return err
	}

	if server != nil {
		cli, err := coreclient.FromContext(ctx)
		if err != nil {
			return err
		}

		if err := manager.RemoveResourceReference(ctx, cli, &unikornv1.Server{}, client.ObjectKeyFromObject(server), reference); err != nil {
			return err
		}
	}

	if err := p.releaseClaim(ctx); err != nil {
		return err
	}

	p.volume.Status.AttachedAt = nil

	// Reconcile the Volume from scratch before observing its generation.
	return provisioners.ErrYield
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

		return nil, false, nil
	}

	return server, true, nil
}

func (p *Provisioner) reconcileClaimedVolume(ctx context.Context, provider types.Provider, identity *unikornv1.Identity, server *unikornv1.Server) error {
	if err := provider.CreateVolume(ctx, identity, p.volume); err != nil {
		return err
	}

	condition, err := unikornv1core.GetAvailableCondition(server)
	if err != nil || condition.Reason != unikornv1core.ConditionReasonProvisioned {
		return p.waitForServerProvisioning(ctx, server, condition, err)
	}

	attachment, err := provider.AttachVolume(ctx, identity, server, p.volume)
	if err != nil {
		return p.handleAttachmentError(ctx, server, err)
	}

	if err := p.setAttachmentStatus(ctx, server, unikornv1.AttachmentProvisioned, attachment.Device, ""); err != nil {
		return err
	}

	if p.volume.Status.AttachedAt == nil {
		attachedAt := metav1.Now()
		p.volume.Status.AttachedAt = &attachedAt
	}

	return nil
}

func (p *Provisioner) handleAttachmentError(ctx context.Context, server *unikornv1.Server, err error) error {
	status := unikornv1.AttachmentProvisioning
	if !errors.Is(err, provisioners.ErrYield) {
		status = unikornv1.AttachmentErrored
	}

	if statusErr := p.setAttachmentStatus(ctx, server, status, nil, attachmentMessage(err)); statusErr != nil {
		return statusErr
	}

	return err
}

// waitForServerProvisioning records why attachment is blocked and yields until
// the claimed Server is ready for the provider attachment call.
func (p *Provisioner) waitForServerProvisioning(ctx context.Context, server *unikornv1.Server, condition *unikornv1core.TypedCondition[unikornv1core.ProvisioningConditionReason], conditionErr error) error {
	// A Server provisioning error blocks attachment, but remains retryable because
	// the Server condition can recover without a Volume generation change.
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
	if errors.Is(err, provisioners.ErrYield) {
		return "waiting for volume attachment to converge"
	}

	if errors.Is(err, coreerrors.ErrConflict) {
		return "volume attachment conflicts with provider state"
	}

	var provisioningError *provisioners.Error
	if errors.As(err, &provisioningError) {
		return provisioningError.Message()
	}

	return "an unexpected error occurred"
}

func (p *Provisioner) detachAttachments(ctx context.Context, provider types.Provider, identity *unikornv1.Identity, server *unikornv1.Server) error {
	if server != nil {
		status := &unikornv1.ServerVolumeStatus{
			ID:                 p.volume.Name,
			ProvisioningStatus: unikornv1.AttachmentDeprovisioning,
			Message:            "detaching volume attachment",
		}

		if err := p.updateAttachmentStatus(ctx, server, status, false); err != nil && !kerrors.IsNotFound(err) {
			return err
		}
	}

	if err := provider.DetachVolume(ctx, identity, server, p.volume); err != nil {
		return err
	}

	if server != nil {
		if err := p.updateAttachmentStatus(ctx, server, nil, false); err != nil && !kerrors.IsNotFound(err) {
			return err
		}
	}

	return nil
}

func (p *Provisioner) releaseClaim(ctx context.Context) error {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	p.volume.Spec.ClaimRef = nil

	if err := cli.Update(ctx, p.volume); err != nil {
		if kerrors.IsConflict(err) {
			return provisioners.ErrYield
		}

		return err
	}

	return nil
}

func (p *Provisioner) setAttachmentStatus(ctx context.Context, server *unikornv1.Server, status unikornv1.AttachmentProvisioningStatus, device *string, message string) error {
	return p.updateAttachmentStatus(ctx, server, &unikornv1.ServerVolumeStatus{
		ID:                 p.volume.Name,
		ProvisioningStatus: status,
		Device:             device,
		Message:            message,
	}, true)
}

func (p *Provisioner) updateAttachmentStatus(ctx context.Context, server *unikornv1.Server, status *unikornv1.ServerVolumeStatus, create bool) error {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	key := client.ObjectKeyFromObject(server)

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &unikornv1.Server{}
		if err := cli.Get(ctx, key, latest); err != nil {
			return err
		}

		updated := removeServerVolumeStatus(latest.Status.Volumes, p.volume.Name)
		if status != nil {
			if !create && len(updated) == len(latest.Status.Volumes) {
				return nil
			}

			updated = append(updated, *status)
		} else if len(updated) == len(latest.Status.Volumes) {
			return nil
		}

		latest.Status.Volumes = updated

		return cli.Status().Update(ctx, latest)
	})
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
	// derived status must never gate this call.
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
