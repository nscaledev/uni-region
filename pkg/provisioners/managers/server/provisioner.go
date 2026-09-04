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
	kerrors "k8s.io/apimachinery/pkg/api/errors"
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

	// metrics are attached by the controller factory once the meter exists.
	// Nil until then, and nil in tests.
	metrics *Metrics
}

// SetMetrics attaches the lifecycle instruments.  Called by the controller
// factory after OpenTelemetry setup, which is why this is not a flag.
func (o *Options) SetMetrics(metrics *Metrics) {
	o.metrics = metrics
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

	// controller-runtime's replacement, GetEventRecorder, writes to events.k8s.io/v1
	// instead of core/v1.  That needs new RBAC on every controller that emits events,
	// and an action string on every call site, so it is a deployment change rather
	// than a library bump.  Deprecated is not removed; controller-runtime suppresses
	// the same warning internally.
	return manager.FromContext(ctx).GetEventRecorderFor("server-controller") //nolint:staticcheck,nolintlint // legacy core/v1 event API.
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
//   - The failure signal itself is the Active condition, set to
//     ActiveConditionReasonError by whichever observer sees the server in a
//     terminal error state (e.g. Nova ERROR). Active is the pertinent lifecycle axis for a single
//     server's state; the Healthy condition is a legacy cluster-aggregate concept
//     and nothing here depends on it.
func ProviderCreateFailure(server *unikornv1.Server) bool {
	if server.Status.ProvisionedAt != nil {
		return false
	}

	if server.Status.LaunchedAt != nil {
		return false
	}

	// A missing Active condition (server never observed) is not a failure.
	active, err := unikornv1.GetActiveCondition(server)
	if err != nil {
		return false
	}

	return active.Reason == unikornv1.ActiveConditionReasonError
}

func (p *Provisioner) providerCreateFailure() bool {
	return ProviderCreateFailure(p.server)
}

// resetProviderCreateRuntimeStatus clears the runtime status left by a failed
// create attempt so the next attempt starts clean. Resetting the Active condition
// to Pending clears the terminal Error state, so ProviderCreateFailure no longer
// fires while the retry is in flight. The Healthy condition is left alone: nothing
// gates on it and the next pass re-derives it.
func (p *Provisioner) resetProviderCreateRuntimeStatus() {
	p.server.SetActiveCondition(unikornv1.ActiveConditionReasonPending)
	p.server.Status.PrivateIP = nil
	p.server.Status.PublicIP = nil
	// MACAddress is deliberately not reset: a stale value self-heals on the next
	// observation rather than flickering to unset.
	p.server.Status.LaunchedAt = nil
	p.server.Status.ScheduledAt = nil
}

func (p *Provisioner) deleteFailedProviderServer(ctx context.Context, provider types.Provider, identity *unikornv1.Identity, attempt, maxAttempts int32) error {
	if err := provider.DeleteServer(ctx, identity, p.server); err != nil {
		return err
	}

	// Provider contract: UpdateServerState must surface ErrResourceNotFound for
	// an absent provider server — it is the "confirmed gone" signal this gate
	// depends on. The OpenStack implementation records the absent observation
	// first and then returns the error (see updateServerStateWithClients).
	if err := provider.UpdateServerState(ctx, identity, p.server); err != nil {
		if !errors.Is(err, coreerrors.ErrResourceNotFound) {
			return err
		}

		p.server.Status.ProviderCreateRetrying = false
		p.resetProviderCreateRuntimeStatus()
		// Reset the provider-create gates only once the failed server is confirmed
		// gone. While ProviderCreateRetrying is true the reconcile short-circuits
		// into the delete above and never reaches CreateServer, so the mop-up is
		// safe on the stale True gates; resetting here gives external services a
		// single re-satisfy against a cleaned-up server rather than one burned
		// against the still-dying server.
		p.server.ProviderCreateGatesReset("region", "ProviderCreateRetry", "provider create will retry")
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
	p.resetProviderCreateRuntimeStatus()

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

		// The provisioning reason is the generic Errored (provisioning state is a
		// closed, generic vocabulary); the provider-create-failure specificity rides
		// the Active condition (ActiveConditionReasonError) and this message.
		return true, provisioners.Terminal(unikornv1core.ConditionReasonErrored, fmt.Sprintf("provider server create failed after %d attempts", maxAttempts))
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

// blockUntilDependenciesReady gates provider create on the readiness of the
// server's separately-provisioned platform dependencies: its identity, networks
// and security groups. Attempting a create before these are provisioned yields a
// doomed provider call that the retry machinery then has to mop up; gating here
// turns that into an explicit, self-explanatory wait.
//
// Only these are gated. The SSH certificate authority is synchronous spec data
// with no readiness to wait on, and public IP capacity is not knowable ahead of
// allocation. The identity is already fetched, so it is classified directly;
// networks and security groups are fetched by id.
func (p *Provisioner) blockUntilDependenciesReady(ctx context.Context, cli client.Client, identity *unikornv1.Identity) error {
	if err := p.classifyDependency(cli, identity); err != nil {
		return err
	}

	for _, id := range p.networkIDs() {
		if err := p.blockUntilResourceReady(ctx, cli, id, &unikornv1.Network{}); err != nil {
			return err
		}
	}

	for _, id := range p.securityGroupIDs() {
		if err := p.blockUntilResourceReady(ctx, cli, id, &unikornv1.SecurityGroup{}); err != nil {
			return err
		}
	}

	if !p.server.ProviderCreateGatesReady() {
		return fmt.Errorf("%w: provider create gates remaining %v", provisioners.ErrYield, p.server.RemainingProviderCreateGates())
	}

	return nil
}

// blockUntilResourceReady fetches a dependency by id and classifies it.
//
// A NotFound is terminal, not transient: addConsumedResourceReferences runs
// first, rejecting unknown IDs with ErrConsistency and finalizing each
// dependency, so a network being deleted lingers (with a deletion timestamp)
// rather than disappearing. A referenced, finalized dependency that is
// nonetheless gone is a consistency violation no amount of requeuing will fix —
// parking it is correct.
func (p *Provisioner) blockUntilResourceReady(ctx context.Context, cli client.Client, id string, resource unikornv1core.ManagableResourceInterface) error {
	if err := cli.Get(ctx, client.ObjectKey{Namespace: p.server.Namespace, Name: id}, resource); err != nil {
		if kerrors.IsNotFound(err) {
			resource.SetName(id)

			return provisioners.DependencyNotFound(cli.Scheme(), resource)
		}

		return err
	}

	return p.classifyDependency(cli, resource)
}

// classifyDependency maps a fetched dependency's Available condition onto a
// disposition:
//
//   - Provisioned   -> nil, proceed
//   - Errored       -> DependencyFailed: still yields (it may recover), but names
//     the failure so the wait is not mistaken for progress
//   - anything else -> DependencyNotReady: still coming up
func (p *Provisioner) classifyDependency(cli client.Client, resource unikornv1core.ManagableResourceInterface) error {
	condition, err := unikornv1core.GetAvailableCondition(resource)

	switch {
	case err == nil && condition.Reason == unikornv1core.ConditionReasonProvisioned:
		return nil
	case err == nil && condition.Reason == unikornv1core.ConditionReasonErrored:
		return provisioners.DependencyFailed(cli.Scheme(), resource)
	default:
		return provisioners.DependencyNotReady(cli.Scheme(), resource)
	}
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	// The status as read, to diff what this pass observed changing against.
	// Taken before anything can write to it.
	before := p.server.DeepCopy()

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

	defer p.emitTransitions(ctx, cli.Scheme(), before, provider)

	if err := p.blockUntilDependenciesReady(ctx, cli, identity); err != nil {
		return err
	}

	if handled, err := p.handleProviderCreateRetry(ctx, provider, identity); handled {
		return err
	}

	return p.createServerAndReleaseReferences(ctx, cli, provider, identity, reference)
}

// createServerAndReleaseReferences reconciles the provider server and then
// releases references to resources the spec no longer consumes. The release
// must happen on three dispositions: a successful pass (provisionErr is nil),
// a yielding pass (ErrYield), and a parked pass (an error satisfying
// provisioners.IsTerminal, i.e. ErrTerminal or ErrUserActionRequired). A park
// persists until a spec edit — longer-lived than any yield — so a security
// group dropped from the spec in the same update whose rebuild then parks must
// not keep this server's finalizer and block the group's deletion indefinitely.
// The provider detaches dropped groups from the Neutron port before the image
// row runs, so releasing on a park is safe. Genuine unclassified errors return
// early: the provider state is unknown and reference release is not safe.
func (p *Provisioner) createServerAndReleaseReferences(ctx context.Context, cli client.Client, provider types.Provider, identity *unikornv1.Identity, reference string) error {
	options, err := p.serverCreateOptions(ctx, cli)
	if err != nil {
		return err
	}

	provisionErr := provider.CreateServer(ctx, identity, p.server, options)
	if provisionErr != nil && !errors.Is(provisionErr, provisioners.ErrYield) && !provisioners.IsTerminal(provisionErr) {
		return provisionErr
	}

	if err := p.removeConsumedResourceReferences(ctx, cli, reference); err != nil {
		return err
	}

	return provisionErr
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
