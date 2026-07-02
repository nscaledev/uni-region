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

package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/pflag"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	"github.com/unikorn-cloud/region/pkg/provisioners/internal/base"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/record"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	defaultProviderCreateMaxAttempts = 3

	eventReasonProviderCreateRetrying   = "ProviderCreateRetrying"
	eventReasonProviderCreateRetryReady = "ProviderCreateRetryReady"
	eventReasonProviderCreateFailed     = "ProviderCreateFailed"
)

// Options allows access to CLI options in the provisioner.
type Options struct {
	// ProviderCreateMaxAttempts bounds provider server create attempts before
	// surfacing an error on the Server.
	ProviderCreateMaxAttempts int32
}

// NewOptions returns server controller options with production defaults.
func NewOptions() *Options {
	return &Options{
		ProviderCreateMaxAttempts: defaultProviderCreateMaxAttempts,
	}
}

func (o *Options) AddFlags(f *pflag.FlagSet) {
	if o.ProviderCreateMaxAttempts == 0 {
		o.ProviderCreateMaxAttempts = defaultProviderCreateMaxAttempts
	}

	f.Int32Var(&o.ProviderCreateMaxAttempts, "provider-create-max-attempts", o.ProviderCreateMaxAttempts, "Maximum provider server create attempts before surfacing an error")
}

// Provisioner encapsulates control plane provisioning.
type Provisioner struct {
	provisioners.Metadata
	// server is the server we're provisioning.
	server *unikornv1.Server
	// options are documented for the type.
	options *Options
	// recorder is used to emit provider create retry events.
	recorder record.EventRecorder

	// Base gives this methods for getting identities and providers.
	base.Base
}

// New returns a new initialized provisioner object.
func New(options manager.ControllerOptions, providers providers.Providers) provisioners.ManagerProvisioner {
	o, _ := options.(*Options)
	if o == nil {
		o = NewOptions()
	}

	return &Provisioner{
		server:  &unikornv1.Server{},
		options: o,
		Base: base.Base{
			Providers: providers,
		},
	}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.server
}

func (p *Provisioner) networkIDs() []string {
	ids := make([]string, len(p.server.Spec.Networks))

	// TODO: ensure the API rejects repeats.
	for i := range p.server.Spec.Networks {
		ids[i] = p.server.Spec.Networks[i].ID.String()
	}

	return ids
}

func (p *Provisioner) securityGroupIDs() []string {
	ids := make([]string, len(p.server.Spec.SecurityGroups))

	// TODO: ensure the API rejects repeats.
	for i := range p.server.Spec.SecurityGroups {
		ids[i] = p.server.Spec.SecurityGroups[i].ID.String()
	}

	return ids
}

func (p *Provisioner) sshCertificateAuthorityKey() *client.ObjectKey {
	if p.server.Spec.SSHCertificateAuthorityID == nil {
		return nil
	}

	return &client.ObjectKey{
		Namespace: p.server.Namespace,
		Name:      *p.server.Spec.SSHCertificateAuthorityID,
	}
}

func (p *Provisioner) addSSHCertificateAuthorityReference(ctx context.Context, cli client.Client, reference string) error {
	key := p.sshCertificateAuthorityKey()
	if key == nil {
		return nil
	}

	return manager.AddResourceReference(ctx, cli, &unikornv1.SSHCertificateAuthority{}, *key, reference)
}

func (p *Provisioner) removeSSHCertificateAuthorityReference(ctx context.Context, cli client.Client, reference string) error {
	key := p.sshCertificateAuthorityKey()
	if key == nil {
		return nil
	}

	return manager.RemoveResourceReference(ctx, cli, &unikornv1.SSHCertificateAuthority{}, *key, reference)
}

func (p *Provisioner) addConsumedResourceReferences(ctx context.Context, cli client.Client, reference string) error {
	if err := manager.AddResourceReferences(ctx, cli, &unikornv1.NetworkList{}, p.identityListOptions(), reference, p.networkIDs()); err != nil {
		return fmt.Errorf("%w: failed to add network references", err)
	}

	if err := manager.AddResourceReferences(ctx, cli, &unikornv1.SecurityGroupList{}, p.identityListOptions(), reference, p.securityGroupIDs()); err != nil {
		return fmt.Errorf("%w: failed to add security group references", err)
	}

	if err := p.addSSHCertificateAuthorityReference(ctx, cli, reference); err != nil {
		return fmt.Errorf("%w: failed to add SSH certificate authority reference", err)
	}

	return nil
}

func (p *Provisioner) removeConsumedResourceReferences(ctx context.Context, cli client.Client, reference string) error {
	if err := manager.RemoveResourceReferences(ctx, cli, &unikornv1.NetworkList{}, p.identityListOptions(), reference, p.networkIDs()); err != nil {
		return fmt.Errorf("%w: failed to remove network references", err)
	}

	if err := manager.RemoveResourceReferences(ctx, cli, &unikornv1.SecurityGroupList{}, p.identityListOptions(), reference, p.securityGroupIDs()); err != nil {
		return fmt.Errorf("%w: failed to remove security group references", err)
	}

	if err := p.removeSSHCertificateAuthorityReference(ctx, cli, reference); err != nil {
		return fmt.Errorf("%w: failed to remove SSH certificate authority reference", err)
	}

	return nil
}

func (p *Provisioner) clearConsumedResourceReferences(ctx context.Context, cli client.Client, reference string) error {
	if err := manager.ClearResourceReferences(ctx, cli, &unikornv1.NetworkList{}, p.identityListOptions(), reference); err != nil {
		return fmt.Errorf("%w: failed to clear network references", err)
	}

	if err := manager.ClearResourceReferences(ctx, cli, &unikornv1.SecurityGroupList{}, p.identityListOptions(), reference); err != nil {
		return fmt.Errorf("%w: failed to clear security group references", err)
	}

	if err := p.removeSSHCertificateAuthorityReference(ctx, cli, reference); err != nil {
		return fmt.Errorf("%w: failed to clear SSH certificate authority reference", err)
	}

	return nil
}

// identityListOptions lists all resources associated with an identity.
func (p *Provisioner) identityListOptions() *client.ListOptions {
	selector := map[string]string{
		constants.IdentityLabel: p.server.Labels[constants.IdentityLabel],
	}

	return &client.ListOptions{
		Namespace:     p.server.Namespace,
		LabelSelector: labels.SelectorFromSet(selector),
	}
}

func (p *Provisioner) providerCreateMaxAttempts() int32 {
	if p.options == nil {
		return defaultProviderCreateMaxAttempts
	}

	if p.options.ProviderCreateMaxAttempts < 1 {
		return 1
	}

	return p.options.ProviderCreateMaxAttempts
}

func (p *Provisioner) eventRecorder(ctx context.Context) record.EventRecorder {
	if p.recorder != nil {
		return p.recorder
	}

	return manager.FromContext(ctx).GetEventRecorderFor("server-controller")
}

func (p *Provisioner) recordProviderCreateRetryEvent(ctx context.Context, eventType, reason, logMessage, eventMessage string, attempt, maxAttempts int32) {
	log.FromContext(ctx).Info(logMessage, "eventType", eventType, "reason", reason, "attempt", attempt, "maxAttempts", maxAttempts)
	p.eventRecorder(ctx).Event(p.server, eventType, reason, eventMessage)
}

// ProviderCreateFailure reports whether a server is a pre-launch provider create
// failure that is eligible for bounded delete-and-retry (rebuild). It is the
// single source of truth for that decision, shared by the provisioner and the
// controller's watch predicate so the two can never drift.
//
// It deliberately fails closed: any signal that the server has ever booted blocks
// a rebuild, because a rebuild after first boot destroys data and forecloses
// debugging or recovery.
//
//   - LaunchedAt is the steady-state guard: it mirrors Nova launched_at, which is
//     set at first boot and never cleared by Nova, so LaunchedAt != nil means the
//     server has booted.
//   - ProvisionedAt is a durable, write-once copy of that same launched_at signal
//     that nothing in this package ever clears. It exists because LaunchedAt is
//     cleared by resetProviderCreateRuntimeStatus during an in-flight retry: the
//     latch closes that window (and any future loss of LaunchedAt) so a server
//     that has booted cannot be re-armed for rebuild. A reconciler-owned Available
//     condition cannot serve this role — it is re-derived every reconcile and
//     flips to a non-provisioned value when a reconcile re-runs against a flaky
//     provider (for example on a controller restart).
//   - The post-launch Phases are retained as further defence in depth.
func ProviderCreateFailure(server *unikornv1.Server) bool {
	if server.Status.ProvisionedAt != nil {
		return false
	}

	if server.Status.LaunchedAt != nil {
		return false
	}

	switch server.Status.Phase {
	case unikornv1.InstanceLifecyclePhaseRunning,
		unikornv1.InstanceLifecyclePhaseStopping,
		unikornv1.InstanceLifecyclePhaseStopped:
		return false
	case unikornv1.InstanceLifecyclePhasePending,
		unikornv1.InstanceLifecyclePhaseQueued,
		unikornv1.InstanceLifecyclePhaseBuilding,
		"":
	}

	condition, err := server.StatusConditionRead(unikornv1core.ConditionHealthy)
	if err != nil {
		return false
	}

	return condition.Status == corev1.ConditionFalse &&
		condition.Reason == unikornv1core.ConditionReasonErrored
}

func (p *Provisioner) providerCreateFailure() bool {
	return ProviderCreateFailure(p.server)
}

func (p *Provisioner) resetProviderCreateRuntimeStatus(message string) {
	p.server.Status.Phase = unikornv1.InstanceLifecyclePhasePending
	p.server.Status.PrivateIP = nil
	p.server.Status.PublicIP = nil
	p.server.Status.MACAddress = nil
	p.server.Status.LaunchedAt = nil
	p.server.Status.ScheduledAt = nil
	p.server.StatusConditionWrite(unikornv1core.ConditionHealthy, corev1.ConditionUnknown, unikornv1core.ConditionReasonProvisioning, message)
}

func (p *Provisioner) deleteFailedProviderServer(ctx context.Context, provider types.Provider, identity *unikornv1.Identity, attempt, maxAttempts int32) error {
	if err := provider.DeleteServer(ctx, identity, p.server); err != nil {
		return err
	}

	if err := provider.UpdateServerState(ctx, identity, p.server); err != nil {
		if !errors.Is(err, coreerrors.ErrResourceNotFound) {
			return err
		}

		p.server.Status.ProviderCreateRetrying = false
		p.resetProviderCreateRuntimeStatus("Retrying provider server create")
		p.recordProviderCreateRetryEvent(
			ctx,
			corev1.EventTypeNormal,
			eventReasonProviderCreateRetryReady,
			"retrying provider server create",
			fmt.Sprintf("Failed provider server deleted; retrying provider server create (attempt %d/%d)", attempt, maxAttempts),
			attempt,
			maxAttempts,
		)

		return provisioners.ErrYield
	}

	p.server.Status.ProviderCreateRetrying = true
	p.resetProviderCreateRuntimeStatus("Deleting failed provider server before retrying create")

	return provisioners.ErrYield
}

func (p *Provisioner) handleProviderCreateRetry(ctx context.Context, provider types.Provider, identity *unikornv1.Identity) (bool, error) {
	maxAttempts := p.providerCreateMaxAttempts()

	if p.server.Status.ProviderCreateRetrying {
		return true, p.deleteFailedProviderServer(ctx, provider, identity, p.server.Status.ProviderCreateFailures, maxAttempts)
	}

	if !p.providerCreateFailure() {
		return false, nil
	}

	attempt := p.server.Status.ProviderCreateFailures + 1

	if attempt >= maxAttempts {
		// We have reached the attempt cap. Clamp the counter to the cap before
		// returning so a re-reconcile (for example after a controller restart,
		// where the failure predicate still holds) cannot advance it any further,
		// then abort terminally instead of retrying. Recovery is out of band:
		// once the underlying fault is fixed an operator resets
		// ProviderCreateFailures to re-arm the retry process.
		p.server.Status.ProviderCreateFailures = maxAttempts
		p.server.Status.ProviderCreateRetrying = false
		p.recordProviderCreateRetryEvent(
			ctx,
			corev1.EventTypeWarning,
			eventReasonProviderCreateFailed,
			"provider server create failed after all retry attempts",
			fmt.Sprintf("Provider server create failed after %d attempts", maxAttempts),
			maxAttempts,
			maxAttempts,
		)

		return true, provisioners.Terminal("provider_create_failed", fmt.Sprintf("provider server create failed after %d attempts", maxAttempts))
	}

	p.server.Status.ProviderCreateFailures = attempt
	p.server.Status.ProviderCreateRetrying = true
	p.recordProviderCreateRetryEvent(
		ctx,
		corev1.EventTypeNormal,
		eventReasonProviderCreateRetrying,
		"deleting failed provider server before retrying create",
		fmt.Sprintf("Deleting failed provider server before retrying create (attempt %d/%d)", attempt, maxAttempts),
		attempt,
		maxAttempts,
	)

	return true, p.deleteFailedProviderServer(ctx, provider, identity, attempt, maxAttempts)
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	// Add references to any resources we consume.
	reference, err := manager.GenerateResourceReference(cli, p.server)
	if err != nil {
		return err
	}

	if err := p.addConsumedResourceReferences(ctx, cli, reference); err != nil {
		return err
	}

	provider, identity, err := p.ProviderAndIdentity(ctx, p.server)
	if err != nil {
		return err
	}

	if err := manager.ResourceReady(ctx, identity); err != nil {
		return err
	}

	if handled, err := p.handleProviderCreateRetry(ctx, provider, identity); handled {
		return err
	}

	options, err := p.serverCreateOptions(ctx, cli)
	if err != nil {
		return err
	}

	// Do the provisioning.
	if err := provider.CreateServer(ctx, identity, p.server, options); err != nil {
		return err
	}

	// Release any references to any resources we no longer consume.
	if err := p.removeConsumedResourceReferences(ctx, cli, reference); err != nil {
		return err
	}

	return nil
}

// Deprovision implements the Provision interface.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	provider, identity, err := p.ProviderAndIdentity(ctx, p.server)
	if err != nil {
		return err
	}

	if err := provider.DeleteServer(ctx, identity, p.server); err != nil {
		return err
	}

	// Once we know the server is gone, allow deletion of the security group.
	reference, err := manager.GenerateResourceReference(cli, p.server)
	if err != nil {
		return err
	}

	if err := p.clearConsumedResourceReferences(ctx, cli, reference); err != nil {
		return err
	}

	return nil
}
