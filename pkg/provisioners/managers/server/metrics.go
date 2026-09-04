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
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	attrRegionID   = "region_id"
	attrRegionName = "region_name"
	attrFlavorID   = "flavor_id"
	attrFlavorName = "flavor_name"
)

// Metrics holds the server lifecycle instruments.  Both are recorded once per
// server, on its first observed transition into Running.
type Metrics struct {
	provisionHist  metric.Float64Histogram
	schedulingHist metric.Float64Histogram
}

// NewMetrics creates and registers the instruments on the given meter.
func NewMetrics(meter metric.Meter) (*Metrics, error) {
	provisionHist, err := meter.Float64Histogram(
		"unikorn_region_server_provision_duration_seconds",
		metric.WithDescription("Duration from Uni Server CR creation to Nova booting the VM (OS-SRV-USG:launched_at), observed on first Pending to Running transition. For VMs this is close to guest-ready time (<1 min gap); for baremetal the guest OS may need ~15 more minutes to boot."),
		metric.WithExplicitBucketBoundaries(5, 15, 30, 60, 120, 300, 600, 900, 1800, 3600),
	)
	if err != nil {
		return nil, err
	}

	schedulingHist, err := meter.Float64Histogram(
		"unikorn_region_server_scheduling_duration_seconds",
		metric.WithDescription("Duration from Uni Server CR creation to Nova creating the server (created timestamp), observed on first Pending to Running transition."),
		metric.WithExplicitBucketBoundaries(1, 5, 10, 30, 60, 120, 300),
	)
	if err != nil {
		return nil, err
	}

	return &Metrics{
		provisionHist:  provisionHist,
		schedulingHist: schedulingHist,
	}, nil
}

// serverLabels identifies the server a duration is recorded for.
type serverLabels struct {
	regionID   string
	regionName string
	flavorID   string
	flavorName string
}

func (l serverLabels) attributes() metric.MeasurementOption {
	return metric.WithAttributes(
		attribute.String(attrRegionID, l.regionID),
		attribute.String(attrRegionName, l.regionName),
		attribute.String(attrFlavorID, l.flavorID),
		attribute.String(attrFlavorName, l.flavorName),
	)
}

// RecordProvision observes a creation-to-boot duration.
func (m *Metrics) RecordProvision(ctx context.Context, d time.Duration, labels serverLabels) {
	m.provisionHist.Record(ctx, d.Seconds(), labels.attributes())
}

// RecordScheduling observes a creation-to-Nova-accept duration.
func (m *Metrics) RecordScheduling(ctx context.Context, d time.Duration, labels serverLabels) {
	m.schedulingHist.Record(ctx, d.Seconds(), labels.attributes())
}
