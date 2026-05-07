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

package server

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	attrState      = "state"
	attrRegionID   = "region_id"
	attrRegionName = "region_name"
	attrFlavorID   = "flavor_id"
	attrFlavorName = "flavor_name"
)

// StateMetricsKey is the composite key for grouping server counts.
type StateMetricsKey struct {
	State      string
	RegionID   string
	RegionName string
	FlavorID   string
	FlavorName string
}

// Metrics holds the OTel instruments for the server health monitor.
type Metrics struct {
	mu          sync.RWMutex
	stateCounts map[StateMetricsKey]int64

	stateGauge    metric.Int64ObservableGauge
	provisionHist metric.Float64Histogram
}

// NewMetrics creates and registers OTel instruments on the given meter.
func NewMetrics(meter metric.Meter) (*Metrics, error) {
	stateGauge, err := meter.Int64ObservableGauge(
		"unikorn_region_server_state",
		metric.WithDescription("Number of servers currently in each lifecycle state, per region and flavor."),
	)
	if err != nil {
		return nil, err
	}

	provisionHist, err := meter.Float64Histogram(
		"unikorn_region_server_provision_duration_seconds",
		metric.WithDescription("Duration of the Pending phase, observed on Pending to Running transition."),
		metric.WithExplicitBucketBoundaries(5, 15, 30, 60, 120, 300, 600, 900, 1800, 3600),
	)
	if err != nil {
		return nil, err
	}

	m := &Metrics{
		stateCounts:   make(map[StateMetricsKey]int64),
		stateGauge:    stateGauge,
		provisionHist: provisionHist,
	}

	if _, err := meter.RegisterCallback(m.collectStateCounts, m.stateGauge); err != nil {
		return nil, err
	}

	return m, nil
}

// collectStateCounts is the OTel observable callback for unikorn_region_server_state.
// It is called by the SDK on each metric collection cycle.
func (m *Metrics) collectStateCounts(_ context.Context, o metric.Observer) error {
	// Safe because SetStateCounts always replaces the map reference; it never mutates in place.
	m.mu.RLock()
	snapshot := m.stateCounts
	m.mu.RUnlock()

	for k, count := range snapshot {
		o.ObserveInt64(m.stateGauge, count,
			metric.WithAttributes(
				attribute.String(attrState, k.State),
				attribute.String(attrRegionID, k.RegionID),
				attribute.String(attrRegionName, k.RegionName),
				attribute.String(attrFlavorID, k.FlavorID),
				attribute.String(attrFlavorName, k.FlavorName),
			),
		)
	}

	return nil
}

// SetStateCounts replaces the cached state counts. Called after each full poll cycle.
// Caller must not retain or mutate the passed map after this call.
func (m *Metrics) SetStateCounts(counts map[StateMetricsKey]int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.stateCounts = counts
}

// RecordProvision observes a Pending → Running provisioning duration.
func (m *Metrics) RecordProvision(ctx context.Context, d time.Duration, regionID, regionName, flavorID, flavorName string) {
	m.provisionHist.Record(ctx, d.Seconds(),
		metric.WithAttributes(
			attribute.String(attrRegionID, regionID),
			attribute.String(attrRegionName, regionName),
			attribute.String(attrFlavorID, flavorID),
			attribute.String(attrFlavorName, flavorName),
		),
	)
}
