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
	"time"

	"github.com/go-logr/logr"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/provisioninglog"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

func serverLogger(ctx context.Context, s *unikornv1.Server) logr.Logger {
	return log.FromContext(ctx).WithValues(
		"instance_id", s.Name,
		"org_id", s.Labels[coreconstants.OrganizationLabel],
		"region_id", s.Labels[constants.RegionLabel],
	)
}

// emitTransitions reports what this pass observed changing, by diffing the
// status it read against the status it wrote.  See the README's Transition
// Emission section.
func (p *Provisioner) emitTransitions(ctx context.Context, scheme *runtime.Scheme, before *unikornv1.Server, provider types.Provider) {
	p.emitLifecycleTransition(ctx, scheme, before, provider)
}

// emitLifecycleTransition emits an Active-condition change to the lifecycle
// stream, and records the duration histograms on the first arrival at Running.
func (p *Provisioner) emitLifecycleTransition(ctx context.Context, scheme *runtime.Scheme, before *unikornv1.Server, provider types.Provider) {
	after, err := unikornv1.GetActiveCondition(p.server)
	if err != nil {
		return
	}

	// An absent prior condition is the server's first observation, which still
	// counts as a transition into the new state.
	var previous unikornv1.ActiveConditionReason
	if old, oldErr := unikornv1.GetActiveCondition(before); oldErr == nil {
		previous = old.Reason
	}

	if previous == after.Reason {
		return
	}

	provisioninglog.Emit(ctx, scheme, p.server, provisioninglog.StreamLifecycle,
		string(after.Status), string(after.Reason), after.Message)

	if after.Reason != unikornv1.ActiveConditionReasonRunning {
		return
	}

	p.recordArrivalDurations(ctx, before, provider)
}

// recordArrivalDurations records both duration histograms if this pass is the
// one that first populated the timestamp each measures.
func (p *Provisioner) recordArrivalDurations(ctx context.Context, before *unikornv1.Server, provider types.Provider) {
	if p.options == nil || p.options.metrics == nil {
		return
	}

	provisionDuration, provisionOK := p.firstObservation(ctx, "launched_at", before.Status.LaunchedAt, p.server.Status.LaunchedAt)
	schedulingDuration, schedulingOK := p.firstObservation(ctx, "scheduled_at", before.Status.ScheduledAt, p.server.Status.ScheduledAt)

	if !provisionOK && !schedulingOK {
		return
	}

	// Resolved here rather than per pass: this runs once in a server's life, so
	// the two provider reads it costs are not on any hot path.
	labels := p.serverLabels(ctx, provider)

	if provisionOK {
		p.options.metrics.RecordProvision(ctx, provisionDuration, labels)
	}

	if schedulingOK {
		p.options.metrics.RecordScheduling(ctx, schedulingDuration, labels)
	}
}

// firstObservation returns the duration from creation to current, and whether
// this pass is the one that populated it.  Each server therefore contributes at
// most one observation, across stop/restart cycles included.
func (p *Provisioner) firstObservation(ctx context.Context, logKey string, previous, current *metav1.Time) (time.Duration, bool) {
	if previous != nil || current == nil {
		return 0, false
	}

	duration := current.Sub(p.server.CreationTimestamp.Time)
	if duration < 0 {
		serverLogger(ctx, p.server).Info("skipping duration metric: negative duration (clock skew?)",
			logKey, current.Time,
			"created_at", p.server.CreationTimestamp.Time,
		)

		return 0, false
	}

	return duration, true
}

// serverLabels resolves the metric label values, falling back to the raw IDs
// when the display names cannot be read.
func (p *Provisioner) serverLabels(ctx context.Context, provider types.Provider) serverLabels {
	labels := serverLabels{
		regionID: p.server.Labels[constants.RegionLabel],
		flavorID: p.server.Spec.FlavorID.String(),
	}

	if provider == nil {
		return labels
	}

	if region, err := provider.Region(ctx); err != nil {
		serverLogger(ctx, p.server).Error(err, "failed to resolve region name for metrics")
	} else {
		labels.regionName = region.Labels[coreconstants.NameLabel]
	}

	flavors, err := provider.Flavors(ctx)
	if err != nil {
		serverLogger(ctx, p.server).Error(err, "failed to list flavors for metrics")

		return labels
	}

	for _, flavor := range flavors {
		if flavor.ID == labels.flavorID {
			labels.flavorName = flavor.Name

			break
		}
	}

	return labels
}
