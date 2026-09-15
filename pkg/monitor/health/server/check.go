/*
Copyright 2025 the Unikorn Authors.
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
	goerrors "errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/provisioninglog"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers"
	providertypes "github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// checkConcurrency is how many identities are observed at once.
//
// Each concurrent observation decodes and retains one identity's whole project,
// so this bounds peak memory and must move with the monitor's memory limit and
// GOMEMLIMIT (charts/region/values.yaml). It also bounds how much of the estate
// one degraded cell can hold up, since a bucket has no deadline of its own. See
// the README's cycle section for the sizing and the trade-off.
const checkConcurrency = 4

// Checker for server health.
type Checker struct {
	// client is a Kubernetes client.
	client client.Client
	// namespace is where we are running.
	namespace string
	// providers is the shared provider cache for monitor checks.
	providers providers.Providers
	// metrics holds the OTel instruments. May be nil if no meter was provided.
	metrics *Metrics
}

// New creates a new health checker.
func New(client client.Client, namespace string, providers providers.Providers, metrics *Metrics) *Checker {
	return &Checker{
		client:    client,
		namespace: namespace,
		providers: providers,
		metrics:   metrics,
	}
}

// serverLogger returns a logger pre-populated with the standard server identity fields.
// Precondition: region and identity labels validated by groupServers.
func serverLogger(ctx context.Context, s *unikornv1.Server) logr.Logger {
	return log.FromContext(ctx).WithValues(
		"instance_id", s.Name,
		"org_id", s.Labels[coreconstants.OrganizationLabel],
		"region_id", s.Labels[constants.RegionLabel],
	)
}

// recordDurationIfFirstObservation records a histogram observation for a duration
// measured from creationTime to timestamp. It only fires when the timestamp is
// newly populated (was nil before, non-nil now), ensuring each server produces at
// most one observation across stop/restart cycles.
func (c *Checker) recordDurationIfFirstObservation(ctx context.Context, server *unikornv1.Server, logKey string, previous, current *metav1.Time, record func(time.Duration)) {
	if previous != nil || current == nil {
		return
	}

	duration := current.Sub(server.CreationTimestamp.Time)
	if duration < 0 {
		serverLogger(ctx, server).Info("skipping duration metric: negative duration (clock skew?)",
			logKey, current.Time,
			"created_at", server.CreationTimestamp.Time,
		)

		return
	}

	record(duration)
}

// onPhaseTransition logs the lifecycle change and records provisioning histogram
// observations on the first transition into Running from any earlier state. The
// lifecycle path is now Pending → Building → Running for VMs and
// Pending → Queued → Building → Running for baremetal, so a strict
// "Pending → Running" predicate would silently miss every observation. The
// per-server one-shot guarantee is preserved by recordDurationIfFirstObservation,
// which fires only when the relevant timestamp transitions from nil to non-nil.
// Precondition: region and identity labels validated by groupServers.
func (c *Checker) onPhaseTransition(ctx context.Context, server, updated *unikornv1.Server, regionID, regionName, flavorID, flavorName string) {
	newActive, err := unikornv1.GetActiveCondition(updated)
	if err != nil {
		return
	}

	// The prior reason is empty when the server had no Active condition yet (its
	// first observation), which still counts as a transition into the new state.
	var oldReason unikornv1.ActiveConditionReason
	if oldActive, oldErr := unikornv1.GetActiveCondition(server); oldErr == nil {
		oldReason = oldActive.Reason
	}

	if oldReason == newActive.Reason {
		return
	}

	// Emit the lifecycle transition to the structured stream (msg == "lifecycle"),
	// at parity with the provisioning stream. Reaching here means the Active reason
	// actually changed, which is the edge the stream requires.
	provisioninglog.Emit(ctx, c.client.Scheme(), server, provisioninglog.StreamLifecycle,
		string(newActive.Status), string(newActive.Reason), newActive.Message)

	becameRunning := oldReason != unikornv1.ActiveConditionReasonRunning &&
		newActive.Reason == unikornv1.ActiveConditionReasonRunning

	if !becameRunning || c.metrics == nil {
		return
	}

	c.recordDurationIfFirstObservation(ctx, server, "launched_at", server.Status.LaunchedAt, updated.Status.LaunchedAt,
		func(d time.Duration) { c.metrics.RecordProvision(ctx, d, regionID, regionName, flavorID, flavorName) })

	c.recordDurationIfFirstObservation(ctx, server, "scheduled_at", server.Status.ScheduledAt, updated.Status.ScheduledAt,
		func(d time.Duration) { c.metrics.RecordScheduling(ctx, d, regionID, regionName, flavorID, flavorName) })
}

// logStateTransition emits a structured log entry when the server's ConditionHealthy
// status changes.
// Precondition: region and identity labels validated by groupServers.
func (c *Checker) logStateTransition(ctx context.Context, server, updated *unikornv1.Server) {
	// StatusConditionRead only errors when the condition is absent (ErrStatusConditionLookup).
	oldCondition, oldErr := server.StatusConditionRead(unikornv1core.ConditionHealthy)
	newCondition, newErr := updated.StatusConditionRead(unikornv1core.ConditionHealthy)

	if newErr != nil {
		return
	}

	if oldErr == nil && oldCondition.Status == newCondition.Status {
		return
	}

	// Condition appeared for the first time, or its status changed.
	durationSource := server.CreationTimestamp.Time

	var fromHealth string

	if oldErr == nil {
		durationSource = oldCondition.LastTransitionTime.Time
		fromHealth = oldCondition.Reason
	}

	serverLogger(ctx, server).Info("instance health transition",
		"from_health", fromHealth,
		"to_health", newCondition.Reason,
		"duration_ms", newCondition.LastTransitionTime.Sub(durationSource).Milliseconds(),
	)
}

// resolveRegionName returns the display name for a region from the provider,
// returning an empty string if the lookup fails or the name label is absent.
func resolveRegionName(ctx context.Context, provider providertypes.Provider, regionID string) string {
	region, err := provider.Region(ctx)
	if err != nil {
		logFailure(ctx, log.FromContext(ctx).WithValues("region", regionID), err, "failed to get region name")
		return ""
	}

	return region.Labels[coreconstants.NameLabel]
}

// lookupFlavorName returns the display name for flavorID from a pre-fetched list,
// returning an empty string if not found.
func lookupFlavorName(flavors providertypes.FlavorList, flavorID string) string {
	for _, f := range flavors {
		if f.ID == flavorID {
			return f.Name
		}
	}

	return ""
}

// checkedServer holds the post-check server state and the resolved metric label
// values for that server.
type checkedServer struct {
	server     *unikornv1.Server
	regionID   string
	regionName string
	flavorID   string
	flavorName string
}

// checkServer projects the group's provider read onto one server and persists it.
// Best effort: a failure logs and drops this server, leaving the rest of the group
// alone. Returns nil when the server contributes nothing to the state gauge.
func (c *Checker) checkServer(ctx context.Context, server *unikornv1.Server, observer providertypes.ServerObserver, group *serverGroup) *checkedServer {
	updated := server.DeepCopy()

	// A not-found does not abort the check: the observer records the absent
	// observation (errored cleared, generation stamped, image sticky) before
	// surfacing the error, and that observation must still be persisted so the
	// observed wake fires and the reconciler recreates the server.
	stateErr := observer.Observe(ctx, updated)
	if stateErr != nil && !goerrors.Is(stateErr, errors.ErrResourceNotFound) {
		logFailure(ctx, serverLogger(ctx, server), stateErr, "failed to observe server, skipping")

		return nil
	}

	patched, err := c.patchServer(ctx, server, updated)
	if err != nil {
		// Including a conflict: the reconciler won the race, and re-deriving on
		// the next poll is the right answer, not retrying on a stale base.
		logFailure(ctx, serverLogger(ctx, server), err, "failed to patch server status, skipping")

		return nil
	}

	if stateErr != nil {
		// The absent server contributes nothing to the state gauge for this
		// cycle: there is no provider state to count, and phase/health
		// transitions cannot have moved on a read of nothing. Only say the
		// observation was persisted if it actually was — a server already
		// recorded as absent projects identically and is skipped.
		if patched {
			serverLogger(ctx, server).Info("server not found in provider, absent observation persisted")
		}

		return nil
	}

	flavorID := server.Spec.FlavorID.String()
	flavorName := lookupFlavorName(group.region.flavors, flavorID)

	c.onPhaseTransition(ctx, server, updated, group.regionID, group.region.regionName, flavorID, flavorName)
	c.logStateTransition(ctx, server, updated)

	return &checkedServer{
		server:     updated,
		regionID:   group.regionID,
		regionName: group.region.regionName,
		flavorID:   flavorID,
		flavorName: flavorName,
	}
}

// patchServer writes the projection, and only when it changed. Over a steady
// estate every server would otherwise have its status rewritten every poll.
// Reports whether it wrote, so a caller does not claim to have persisted
// something it skipped.
func (c *Checker) patchServer(ctx context.Context, server, updated *unikornv1.Server) (bool, error) {
	if equality.Semantic.DeepEqual(server.Status, updated.Status) {
		return false, nil
	}

	// One patch for health, phase, MAC and the observed region together, under an
	// optimistic lock: a poll that races the reconciler must lose and re-read rather
	// than write a projection built from a stale base.
	if err := c.client.Status().Patch(ctx, updated, client.MergeFromWithOptions(server, &client.MergeFromWithOptimisticLock{})); err != nil {
		return false, err
	}

	return true, nil
}

// regionInfo holds the resolved provider and label values for a region.
type regionInfo struct {
	provider   providertypes.Provider
	regionName string
	flavors    providertypes.FlavorList
}

// regionEntry is a cache slot for resolveRegion. err is non-nil if the region could
// not be resolved, in which case info is nil. Failures are cached so the provider is
// not retried for every server in the same region within a single poll cycle.
type regionEntry struct {
	info *regionInfo
	err  error
}

// resolveRegion returns the cached regionInfo for regionID, populating the cache on
// first access by calling LookupCloud, Region, and Flavors on the provider.
func (c *Checker) resolveRegion(ctx context.Context, cache map[string]regionEntry, regionID string) (*regionInfo, error) {
	if entry, ok := cache[regionID]; ok {
		return entry.info, entry.err
	}

	provider, err := c.providers.LookupCloud(regionID)
	if err != nil {
		logFailure(ctx, log.FromContext(ctx).WithValues("region", regionID), err, "failed to resolve region, skipping")

		cache[regionID] = regionEntry{err: err}

		return nil, err
	}

	flavors, err := provider.Flavors(ctx)
	if err != nil {
		// Flavor lookup failure is non-fatal: regionInfo is still cached so subsequent
		// servers in this region don't re-attempt. Affected servers fall back to raw flavor ID.
		logFailure(ctx, log.FromContext(ctx).WithValues("region", regionID), err, "failed to list flavors")
	}

	ri := &regionInfo{
		provider:   provider,
		regionName: resolveRegionName(ctx, provider, regionID),
		flavors:    flavors,
	}

	cache[regionID] = regionEntry{info: ri}

	return ri, nil
}

// logFailure records a best-effort failure, staying quiet only when the cycle's
// own context is done.
//
// The test is the context and NEVER the error: the shared provider client bounds
// each request with an http.Client timeout whose expiry also satisfies
// errors.Is(err, context.DeadlineExceeded), so keying off the error would hide a
// wedged provider. See the README's best-effort section.
func logFailure(ctx context.Context, logger logr.Logger, err error, msg string) {
	if ctx.Err() != nil {
		return
	}

	logger.Error(err, msg)
}

// serverGroup is the servers sharing one identity, and so one Keystone project
// and one provider read.
type serverGroup struct {
	region     *regionInfo
	regionID   string
	identityID string
	servers    []*unikornv1.Server
}

// groupServers buckets servers by identity, resolving each region as it goes.
// Region resolution happens here rather than inside the fan-out because
// resolveRegion writes an unguarded map, and there are only ever a handful of
// regions to resolve.
func (c *Checker) groupServers(ctx context.Context, items []unikornv1.Server) []serverGroup {
	regions := map[string]regionEntry{}
	index := map[string]int{}

	groups := make([]serverGroup, 0, len(items))

	for i := range items {
		server := &items[i]

		if server.DeletionTimestamp != nil {
			continue
		}

		regionID, ok := server.Labels[constants.RegionLabel]
		if !ok {
			log.FromContext(ctx).Info("server missing region label, skipping", "server", server.Name)

			continue
		}

		identityID, ok := server.Labels[constants.IdentityLabel]
		if !ok {
			// A broken invariant rather than routine news, so it stays on the
			// error axis where it can be alerted on.
			err := fmt.Errorf("%w: server %s missing identity label", errors.ErrConsistency, server.Name)
			logFailure(ctx, log.FromContext(ctx), err, "server missing identity label, skipping")

			continue
		}

		region, err := c.resolveRegion(ctx, regions, regionID)
		if err != nil {
			continue
		}

		key := regionID + "/" + identityID

		at, ok := index[key]
		if !ok {
			at = len(groups)
			index[key] = at

			group := serverGroup{region: region, regionID: regionID, identityID: identityID}
			groups = append(groups, group)
		}

		groups[at].servers = append(groups[at].servers, server)
	}

	return groups
}

// checkGroup observes one identity's project in a single provider read and
// projects it onto every server in the group. Best effort: a failure logs and
// skips this identity for this cycle, leaving every other identity alone.
//
// The batch is read once and projected serially, so it ages as the group is
// walked, and the per-server fault and Ironic reads remain inside that loop —
// which delays everything behind them in the same identity, VMs included. See
// the README's cycle section.
func (c *Checker) checkGroup(ctx context.Context, group *serverGroup) []checkedServer {
	logger := log.FromContext(ctx).WithValues(
		"region_id", group.regionID,
		"identity_id", group.identityID,
		"servers", len(group.servers),
	)

	identity := &unikornv1.Identity{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: group.identityID}, identity); err != nil {
		logFailure(ctx, logger, err, "failed to get identity, skipping servers")

		return nil
	}

	observer, err := group.region.provider.ObserveServers(ctx, identity)
	if err != nil {
		logFailure(ctx, logger, err, "failed to observe identity servers, skipping")

		return nil
	}

	checked := make([]checkedServer, 0, len(group.servers))

	for _, server := range group.servers {
		if result := c.checkServer(ctx, server, observer, group); result != nil {
			checked = append(checked, *result)
		}
	}

	return checked
}

// Check does a full health check against all servers on the platform: one
// provider read per identity, a bounded number of identities at a time.
func (c *Checker) Check(ctx context.Context) error {
	servers := &unikornv1.ServerList{}

	if err := c.client.List(ctx, servers, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return err
	}

	groups := c.groupServers(ctx, servers.Items)

	results := make([][]checkedServer, len(groups))

	// What makes this best effort is checkGroup absorbing its own failures, not
	// the choice of Group: nothing here hands the errgroup a failure to react to.
	// A plain Group rather than WithContext so that stays true if it ever does.
	group := &errgroup.Group{}
	group.SetLimit(checkConcurrency)

	for i := range groups {
		// Checked before dispatching as well as inside: on shutdown the group
		// would otherwise be fed every remaining bucket just to watch each one
		// fail against a dead context.
		if ctx.Err() != nil {
			break
		}

		group.Go(func() error {
			results[i] = c.checkGroup(ctx, &groups[i])

			return ctx.Err()
		})
	}

	if err := group.Wait(); err != nil {
		return err
	}

	// Also checked here, because a cycle cancelled before its first bucket was
	// dispatched has nothing to report the cancellation through.
	if err := ctx.Err(); err != nil {
		return err
	}

	effective := make([]checkedServer, 0, len(servers.Items))
	for _, result := range results {
		effective = append(effective, result...)
	}

	c.updateStateCounts(effective)

	return nil
}

// updateStateCounts rebuilds unikorn_region_server_state from the effective server list.
// Servers skipped due to region resolution or provider errors are absent from the gauge for
// that cycle; a provider outage affecting a whole region will drop those servers entirely
// rather than showing them as unknown. A server whose provider instance is gone
// (not-found) is likewise excluded even though its absent observation is patched —
// there is no provider state to count.
func (c *Checker) updateStateCounts(servers []checkedServer) {
	if c.metrics == nil {
		return
	}

	counts := make(map[StateMetricsKey]int64)

	for _, s := range servers {
		// An unobserved server (no Active condition) contributes an empty state,
		// matching the prior behaviour of an unset lifecycle phase.
		var state unikornv1.ActiveConditionReason
		if active, err := unikornv1.GetActiveCondition(s.server); err == nil {
			state = active.Reason
		}

		key := StateMetricsKey{
			State:      strings.ToLower(string(state)),
			RegionID:   s.regionID,
			RegionName: s.regionName,
			FlavorID:   s.flavorID,
			FlavorName: s.flavorName,
		}
		counts[key]++
	}

	c.metrics.SetStateCounts(counts)
}
