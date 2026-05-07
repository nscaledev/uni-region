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

package server_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	healthserver "github.com/unikorn-cloud/region/pkg/monitor/health/server"
)

// newTestMeter returns a Meter backed by a ManualReader so tests can collect
// metric data on demand without starting a periodic export loop.
func newTestMeter(t *testing.T) (metric.Meter, *sdkmetric.ManualReader) {
	t.Helper()

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	t.Cleanup(func() {
		_ = provider.Shutdown(t.Context())
	})

	return provider.Meter("test"), reader
}

// attrValue returns the string value of a named attribute from an attribute set.
func attrValue(attrs attribute.Set, key string) string {
	v, _ := attrs.Value(attribute.Key(key))

	return v.AsString()
}

// collectGauge returns all data points for unikorn_region_server_state.
func collectGauge(t *testing.T, reader *sdkmetric.ManualReader) []metricdata.DataPoint[int64] {
	t.Helper()

	const name = "unikorn_region_server_state"

	var rm metricdata.ResourceMetrics

	require.NoError(t, reader.Collect(t.Context(), &rm))

	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				gauge, ok := m.Data.(metricdata.Gauge[int64])
				require.True(t, ok, "metric %q is not an Int64 gauge", name)

				return gauge.DataPoints
			}
		}
	}

	return nil
}

// collectHistogram returns all data points for unikorn_region_server_provision_duration_seconds.
func collectHistogram(t *testing.T, reader *sdkmetric.ManualReader) []metricdata.HistogramDataPoint[float64] {
	t.Helper()

	const name = "unikorn_region_server_provision_duration_seconds"

	var rm metricdata.ResourceMetrics

	require.NoError(t, reader.Collect(t.Context(), &rm))

	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				hist, ok := m.Data.(metricdata.Histogram[float64])
				require.True(t, ok, "metric %q is not a Float64 histogram", name)

				return hist.DataPoints
			}
		}
	}

	return nil
}

func TestSetStateCountsReplacesMap(t *testing.T) {
	t.Parallel()

	meter, reader := newTestMeter(t)

	m, err := healthserver.NewMetrics(meter)
	require.NoError(t, err)

	m.SetStateCounts(map[healthserver.StateMetricsKey]int64{
		{State: "pending", RegionID: "region-a", RegionName: "Region A", FlavorID: "flavor-small", FlavorName: "m1.small"}: 3,
		{State: "running", RegionID: "region-a", RegionName: "Region A", FlavorID: "flavor-small", FlavorName: "m1.small"}: 7,
	})

	points := collectGauge(t, reader)
	require.Len(t, points, 2)

	// Replace with a single entry — previous entries must not persist.
	m.SetStateCounts(map[healthserver.StateMetricsKey]int64{
		{State: "running", RegionID: "region-b", RegionName: "Region B", FlavorID: "flavor-large", FlavorName: "m1.large"}: 1,
	})

	points = collectGauge(t, reader)
	require.Len(t, points, 1)
	assert.Equal(t, int64(1), points[0].Value)
	assert.Equal(t, "running", attrValue(points[0].Attributes, "state"))
	assert.Equal(t, "region-b", attrValue(points[0].Attributes, "region_id"))
	assert.Equal(t, "Region B", attrValue(points[0].Attributes, "region_name"))
}

func TestCollectStateCountsEmitsCorrectObservations(t *testing.T) {
	t.Parallel()

	meter, reader := newTestMeter(t)

	m, err := healthserver.NewMetrics(meter)
	require.NoError(t, err)

	m.SetStateCounts(map[healthserver.StateMetricsKey]int64{
		{State: "pending", RegionID: "region-1", RegionName: "Test Region", FlavorID: "flavor-1", FlavorName: "m1.small"}: 5,
		{State: "stopped", RegionID: "region-1", RegionName: "Test Region", FlavorID: "flavor-1", FlavorName: "m1.small"}: 2,
	})

	points := collectGauge(t, reader)
	require.Len(t, points, 2)

	counts := map[string]int64{}
	for _, p := range points {
		counts[attrValue(p.Attributes, "state")] = p.Value
	}

	assert.Equal(t, int64(5), counts["pending"])
	assert.Equal(t, int64(2), counts["stopped"])
}

func TestRecordProvisionRecordsWithCorrectAttributes(t *testing.T) {
	t.Parallel()

	meter, reader := newTestMeter(t)

	m, err := healthserver.NewMetrics(meter)
	require.NoError(t, err)

	m.RecordProvision(t.Context(), 90*time.Second, "region-1", "Test Region", "flavor-1", "m1.small")

	points := collectHistogram(t, reader)
	require.Len(t, points, 1)

	assert.Equal(t, uint64(1), points[0].Count)
	assert.InDelta(t, 90.0, points[0].Sum, 0.001)
	assert.Equal(t, "region-1", attrValue(points[0].Attributes, "region_id"))
	assert.Equal(t, "Test Region", attrValue(points[0].Attributes, "region_name"))
	assert.Equal(t, "flavor-1", attrValue(points[0].Attributes, "flavor_id"))
	assert.Equal(t, "m1.small", attrValue(points[0].Attributes, "flavor_name"))
}
