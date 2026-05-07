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

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers"
	providertypes "github.com/unikorn-cloud/region/pkg/providers/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

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
// Precondition: region label validated by Check; identity label validated by checkServer.
func serverLogger(ctx context.Context, s *unikornv1.Server) logr.Logger {
	return log.FromContext(ctx).WithValues(
		"instance_id", s.Name,
		"org_id", s.Labels[coreconstants.OrganizationLabel],
		"region_id", s.Labels[constants.RegionLabel],
	)
}

// onPhaseTransition logs the phase change and records a provisioning histogram
// observation on Pending → Running.
// Precondition: region label validated by Check; identity label validated by checkServer.
func (c *Checker) onPhaseTransition(ctx context.Context, server, updated *unikornv1.Server, regionID, regionName, flavorID, flavorName string) {
	if server.Status.Phase == updated.Status.Phase {
		return
	}

	serverLogger(ctx, server).Info("instance phase transition",
		"from_phase", string(server.Status.Phase),
		"to_phase", string(updated.Status.Phase),
		"time_since_creation_ms", time.Since(server.CreationTimestamp.Time).Milliseconds(),
	)

	pendingToRunning := server.Status.Phase == unikornv1.InstanceLifecyclePhasePending &&
		updated.Status.Phase == unikornv1.InstanceLifecyclePhaseRunning

	if !pendingToRunning || c.metrics == nil {
		return
	}

	// Read from server (pre-patch state): the annotation was stamped in a prior poll cycle.
	entryTimeStr, ok := server.GetAnnotations()[constants.ServerPendingEntryTimeAnnotation]
	if !ok {
		return
	}

	t, err := time.Parse(time.RFC3339, entryTimeStr)
	if err != nil {
		log.FromContext(ctx).Error(err, "skipping provision duration: invalid pending-entry-time annotation")
		return
	}

	c.metrics.RecordProvision(ctx, time.Since(t), regionID, regionName, flavorID, flavorName)
}

// logStateTransition emits a structured log entry when the server's ConditionHealthy
// status changes.
// Precondition: region label validated by Check; identity label validated by checkServer.
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

	var fromState string

	if oldErr == nil {
		durationSource = oldCondition.LastTransitionTime.Time
		fromState = string(oldCondition.Reason)
	}

	serverLogger(ctx, server).Info("instance state transition",
		"from_state", fromState,
		"to_state", string(newCondition.Reason),
		"duration_ms", newCondition.LastTransitionTime.Sub(durationSource).Milliseconds(),
	)
}

// managePendingAnnotation stamps the phase-entry time annotation when a server enters
// the Pending phase, and removes it when the server leaves Pending. Removing on exit
// bounds measurement error to at most one poll period across stop/start cycles and
// partial patch failures.
//
// Note: a stop/start cycle that completes entirely between two polls is not detected —
// the stale timestamp persists until Running is observed. Acceptable given histogram
// granularity.
func (c *Checker) managePendingAnnotation(ctx context.Context, updated *unikornv1.Server) error {
	_, hasAnnot := updated.GetAnnotations()[constants.ServerPendingEntryTimeAnnotation]

	if updated.Status.Phase != unikornv1.InstanceLifecyclePhasePending {
		if !hasAnnot {
			return nil
		}

		patch := updated.DeepCopy()
		delete(patch.Annotations, constants.ServerPendingEntryTimeAnnotation)

		return c.client.Patch(ctx, patch, client.MergeFromWithOptions(updated, &client.MergeFromWithOptimisticLock{}))
	}

	if hasAnnot {
		return nil
	}

	// Server just entered Pending: stamp the current time.
	patch := updated.DeepCopy()
	metav1.SetMetaDataAnnotation(&patch.ObjectMeta, constants.ServerPendingEntryTimeAnnotation, time.Now().UTC().Format(time.RFC3339))

	return c.client.Patch(ctx, patch, client.MergeFromWithOptions(updated, &client.MergeFromWithOptimisticLock{}))
}

// resolveRegionName returns the display name for a region from the provider,
// returning an empty string if the lookup fails or the name label is absent.
func resolveRegionName(ctx context.Context, provider providertypes.Provider, regionID string) string {
	region, err := provider.Region(ctx)
	if err != nil {
		log.FromContext(ctx).Error(err, "failed to get region name", "region", regionID)
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

// checkServer consults the provider for the server health status. Returns the
// effective server state and resolved metric label values.
func (c *Checker) checkServer(ctx context.Context, server *unikornv1.Server, provider providertypes.Provider, regionID, regionName, flavorID, flavorName string) (*checkedServer, error) {
	identityID, ok := server.Labels[constants.IdentityLabel]
	if !ok {
		return nil, fmt.Errorf("%w: server %s missing identity label", errors.ErrConsistency, server.Name)
	}

	identity := &unikornv1.Identity{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: identityID}, identity); err != nil {
		return nil, err
	}

	updated := server.DeepCopy()

	if err := provider.UpdateServerState(ctx, identity, updated); err != nil {
		return nil, err
	}

	if err := c.client.Status().Patch(ctx, updated, client.MergeFromWithOptions(server, &client.MergeFromWithOptimisticLock{})); err != nil {
		return nil, err
	}

	c.onPhaseTransition(ctx, server, updated, regionID, regionName, flavorID, flavorName)
	c.logStateTransition(ctx, server, updated)

	// managePendingAnnotation must run after Status().Patch: controller-runtime rewrites
	// updated (including ResourceVersion) from the server response, so the optimistic-lock
	// base for the annotation patch is always fresh. Reordering this call is a bug.
	if err := c.managePendingAnnotation(ctx, updated); err != nil {
		// Annotation patch failures are non-fatal: the next poll will re-attempt.
		// Aborting the loop here would block all subsequent servers for a transient error.
		serverLogger(ctx, server).Error(err, "failed to patch pending-entry annotation")
	}

	return &checkedServer{server: updated, regionID: regionID, regionName: regionName, flavorID: flavorID, flavorName: flavorName}, nil
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
		if !goerrors.Is(err, context.Canceled) && !goerrors.Is(err, context.DeadlineExceeded) {
			log.FromContext(ctx).Error(err, "failed to resolve region, skipping", "region", regionID)
			cache[regionID] = regionEntry{err: err}
		}

		return nil, err
	}

	flavors, err := provider.Flavors(ctx)
	if err != nil {
		// Flavor lookup failure is non-fatal: regionInfo is still cached so subsequent
		// servers in this region don't re-attempt. Affected servers fall back to raw flavor ID.
		log.FromContext(ctx).Error(err, "failed to list flavors", "region", regionID)
	}

	ri := &regionInfo{
		provider:   provider,
		regionName: resolveRegionName(ctx, provider, regionID),
		flavors:    flavors,
	}

	cache[regionID] = regionEntry{info: ri}

	return ri, nil
}

// isFatal reports whether err should abort the poll cycle.
func isFatal(err error) bool {
	return goerrors.Is(err, context.Canceled) || goerrors.Is(err, context.DeadlineExceeded)
}

// processServer resolves the region, checks one server, and appends the result to effective.
// Returns a non-nil error only for fatal errors that should abort the poll cycle.
func (c *Checker) processServer(ctx context.Context, srv *unikornv1.Server, regions map[string]regionEntry, effective *[]checkedServer) error {
	if srv.DeletionTimestamp != nil {
		return nil
	}

	regionID, ok := srv.Labels[constants.RegionLabel]
	if !ok {
		log.FromContext(ctx).Info("server missing region label, skipping", "server", srv.Name)

		return nil
	}

	ri, err := c.resolveRegion(ctx, regions, regionID)
	if err != nil {
		if isFatal(err) {
			return err
		}

		return nil
	}

	result, err := c.checkServer(ctx, srv, ri.provider, regionID, ri.regionName, srv.Spec.FlavorID, lookupFlavorName(ri.flavors, srv.Spec.FlavorID))
	if err != nil {
		if isFatal(err) {
			return err
		}

		if goerrors.Is(err, errors.ErrResourceNotFound) {
			log.FromContext(ctx).Info("server not found in provider, skipping", "server", srv.Name)
		} else {
			log.FromContext(ctx).Error(err, "failed to check server, skipping", "server", srv.Name)
		}

		return nil
	}

	*effective = append(*effective, *result)

	return nil
}

// Check does a full health check against all servers on the platform.
// NOTE: this is going to be very heavy weight!
func (c *Checker) Check(ctx context.Context) error {
	servers := &unikornv1.ServerList{}

	if err := c.client.List(ctx, servers, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return err
	}

	regions := make(map[string]regionEntry)
	effective := make([]checkedServer, 0, len(servers.Items))

	for i := range servers.Items {
		if err := c.processServer(ctx, &servers.Items[i], regions, &effective); err != nil {
			return err
		}
	}

	c.updateStateCounts(effective)

	return nil
}

// updateStateCounts rebuilds unikorn_region_server_state from the effective server list.
// Servers skipped due to region resolution or provider errors are absent from the gauge for
// that cycle; a provider outage affecting a whole region will drop those servers entirely
// rather than showing them as unknown.
func (c *Checker) updateStateCounts(servers []checkedServer) {
	if c.metrics == nil {
		return
	}

	counts := make(map[StateMetricsKey]int64)

	for _, s := range servers {
		key := StateMetricsKey{
			State:      strings.ToLower(string(s.server.Status.Phase)),
			RegionID:   s.regionID,
			RegionName: s.regionName,
			FlavorID:   s.flavorID,
			FlavorName: s.flavorName,
		}
		counts[key]++
	}

	c.metrics.SetStateCounts(counts)
}
