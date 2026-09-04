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
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"
	serverprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/server"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

const testMetricFlavorID = "7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d"

var errUnavailable = errors.New("provider unavailable")

// newTestMeter returns a meter plus the reader its instruments record into.
func newTestMeter(t *testing.T) (*sdkmetric.MeterProvider, *sdkmetric.ManualReader) {
	t.Helper()

	reader := sdkmetric.NewManualReader()

	return sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)), reader
}

// histogramCount returns the total number of observations recorded against the
// named histogram.
func histogramCount(t *testing.T, reader *sdkmetric.ManualReader, name string) uint64 {
	t.Helper()

	var data metricdata.ResourceMetrics

	require.NoError(t, reader.Collect(t.Context(), &data))

	var total uint64

	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != name {
				continue
			}

			histogram, ok := m.Data.(metricdata.Histogram[float64])
			require.True(t, ok, "%s is not a float histogram", name)

			for _, point := range histogram.DataPoints {
				total += point.Count
			}
		}
	}

	return total
}

// captureSink is a logr.LogSink that records Info calls so tests can assert on them.
// entries is a shared pointer so that copies produced by WithValues all write to the
// same slice (logr calls WithValues even with an empty key list).
type captureSink struct {
	entries   *[]map[string]any
	presetKVs []any
}

func newCaptureSink() *captureSink {
	entries := make([]map[string]any, 0)

	return &captureSink{entries: &entries}
}

var _ logr.LogSink = (*captureSink)(nil)

func (s *captureSink) Init(logr.RuntimeInfo)        {}
func (s *captureSink) Enabled(int) bool             { return true }
func (s *captureSink) Error(error, string, ...any)  {}
func (s *captureSink) WithName(string) logr.LogSink { return s }

func (s *captureSink) WithValues(kvs ...any) logr.LogSink {
	c := *s // shares the entries pointer; each copy gets its own presetKVs
	c.presetKVs = append(append([]any{}, s.presetKVs...), kvs...)

	return &c
}

func (s *captureSink) Info(_ int, msg string, keysAndValues ...any) {
	entry := map[string]any{"_msg": msg}

	for i := 0; i+1 < len(s.presetKVs); i += 2 {
		entry[fmt.Sprint(s.presetKVs[i])] = s.presetKVs[i+1]
	}

	for i := 0; i+1 < len(keysAndValues); i += 2 {
		entry[fmt.Sprint(keysAndValues[i])] = keysAndValues[i+1]
	}

	*s.entries = append(*s.entries, entry)
}

func (s *captureSink) entriesWithMsg(msg string) []map[string]any {
	var out []map[string]any

	for _, e := range *s.entries {
		if e["_msg"] == msg {
			out = append(out, e)
		}
	}

	return out
}

// transitionFixture returns a server created an hour ago with no status.
func transitionFixture() *unikornv1.Server {
	return &unikornv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "server-1",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
		},
	}
}

// arrive moves a server to Running with both Nova timestamps populated, which
// is the edge both histograms measure.
func arrive(server *unikornv1.Server, offset time.Duration) {
	server.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)

	at := metav1.NewTime(server.CreationTimestamp.Add(offset))
	server.Status.LaunchedAt = &at
	server.Status.ScheduledAt = &at
}

func emit(t *testing.T, before, after *unikornv1.Server, metrics *serverprovisioner.Metrics) *captureSink {
	t.Helper()

	return emitWithProvider(t, before, after, metrics, nil)
}

func emitWithProvider(t *testing.T, before, after *unikornv1.Server, metrics *serverprovisioner.Metrics, provider types.Provider) *captureSink {
	t.Helper()

	options := serverprovisioner.NewOptions()
	options.SetMetrics(metrics)

	p := serverprovisioner.NewForTest(after, nil, options)

	sink := newCaptureSink()
	ctx := log.IntoContext(t.Context(), logr.New(sink))

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	serverprovisioner.EmitTransitions(ctx, p, scheme, before, provider)

	return sink
}

// histogramAttributes returns the attribute set of the single data point
// recorded against the named histogram.
func histogramAttributes(t *testing.T, reader *sdkmetric.ManualReader, name string) map[string]string {
	t.Helper()

	var data metricdata.ResourceMetrics

	require.NoError(t, reader.Collect(t.Context(), &data))

	out := map[string]string{}

	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != name {
				continue
			}

			histogram, ok := m.Data.(metricdata.Histogram[float64])
			require.True(t, ok)
			require.Len(t, histogram.DataPoints, 1)

			for _, attr := range histogram.DataPoints[0].Attributes.ToSlice() {
				out[string(attr.Key)] = attr.Value.AsString()
			}
		}
	}

	return out
}

// TestRecordsDurationsOnArrival pins that a pass observing the first arrival at
// Running records both histograms.
func TestRecordsDurationsOnArrival(t *testing.T) {
	t.Parallel()

	provider, reader := newTestMeter(t)

	metrics, err := serverprovisioner.NewMetrics(provider.Meter("test"))
	require.NoError(t, err)

	before := transitionFixture()
	before.SetActiveCondition(unikornv1.ActiveConditionReasonBuilding)

	after := before.DeepCopy()
	arrive(after, time.Minute)

	_ = emit(t, before, after, metrics)

	require.Equal(t, uint64(1), histogramCount(t, reader, "unikorn_region_server_provision_duration_seconds"))
	require.Equal(t, uint64(1), histogramCount(t, reader, "unikorn_region_server_scheduling_duration_seconds"))
}

// TestRecordsDurationsFromAnyEarlierState pins that the histograms key off the
// arrival at Running, not off a particular predecessor. The lifecycle path is
// Pending → Building → Running for VMs and Pending → Queued → Building →
// Running for baremetal, so a strict Pending → Running predicate would miss
// every observation.
func TestRecordsDurationsFromAnyEarlierState(t *testing.T) {
	t.Parallel()

	for _, previous := range []unikornv1.ActiveConditionReason{
		unikornv1.ActiveConditionReasonPending,
		unikornv1.ActiveConditionReasonQueued,
		unikornv1.ActiveConditionReasonBuilding,
	} {
		t.Run(string(previous), func(t *testing.T) {
			t.Parallel()

			provider, reader := newTestMeter(t)

			metrics, err := serverprovisioner.NewMetrics(provider.Meter("test"))
			require.NoError(t, err)

			before := transitionFixture()
			before.SetActiveCondition(previous)

			after := before.DeepCopy()
			arrive(after, time.Minute)

			_ = emit(t, before, after, metrics)

			require.Equal(t, uint64(1), histogramCount(t, reader, "unikorn_region_server_provision_duration_seconds"))
		})
	}
}

// TestNoDurationsWithoutAnArrival pins that an intermediate transition records
// nothing.
func TestNoDurationsWithoutAnArrival(t *testing.T) {
	t.Parallel()

	provider, reader := newTestMeter(t)

	metrics, err := serverprovisioner.NewMetrics(provider.Meter("test"))
	require.NoError(t, err)

	before := transitionFixture()
	before.SetActiveCondition(unikornv1.ActiveConditionReasonPending)

	after := before.DeepCopy()
	after.SetActiveCondition(unikornv1.ActiveConditionReasonBuilding)

	_ = emit(t, before, after, metrics)

	require.Zero(t, histogramCount(t, reader, "unikorn_region_server_provision_duration_seconds"))
	require.Zero(t, histogramCount(t, reader, "unikorn_region_server_scheduling_duration_seconds"))
}

// TestNoDurationsOnSecondArrival is the one-shot guarantee: a server that has
// already booted and comes back to Running -- a stop/start cycle, or a
// controller restart -- must not observe again.
func TestNoDurationsOnSecondArrival(t *testing.T) {
	t.Parallel()

	provider, reader := newTestMeter(t)

	metrics, err := serverprovisioner.NewMetrics(provider.Meter("test"))
	require.NoError(t, err)

	before := transitionFixture()
	before.SetActiveCondition(unikornv1.ActiveConditionReasonStopped)
	arrive(before, time.Minute)
	before.SetActiveCondition(unikornv1.ActiveConditionReasonStopped)

	after := before.DeepCopy()
	after.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)

	_ = emit(t, before, after, metrics)

	require.Zero(t, histogramCount(t, reader, "unikorn_region_server_provision_duration_seconds"))
	require.Zero(t, histogramCount(t, reader, "unikorn_region_server_scheduling_duration_seconds"))
}

// TestNoDurationsOnClockSkew pins that a timestamp predating the resource is
// dropped rather than recorded as a negative duration.
func TestNoDurationsOnClockSkew(t *testing.T) {
	t.Parallel()

	provider, reader := newTestMeter(t)

	metrics, err := serverprovisioner.NewMetrics(provider.Meter("test"))
	require.NoError(t, err)

	before := transitionFixture()
	before.SetActiveCondition(unikornv1.ActiveConditionReasonBuilding)

	after := before.DeepCopy()
	arrive(after, -time.Minute)

	_ = emit(t, before, after, metrics)

	require.Zero(t, histogramCount(t, reader, "unikorn_region_server_provision_duration_seconds"))
	require.Zero(t, histogramCount(t, reader, "unikorn_region_server_scheduling_duration_seconds"))
}

// TestNoDurationsWithoutMetrics pins that an unconfigured meter is survivable,
// since NewForTest and the unit tests run without one.
func TestNoDurationsWithoutMetrics(t *testing.T) {
	t.Parallel()

	before := transitionFixture()
	before.SetActiveCondition(unikornv1.ActiveConditionReasonBuilding)

	after := before.DeepCopy()
	arrive(after, time.Minute)

	require.NotPanics(t, func() { _ = emit(t, before, after, nil) })
}

// TestEmitsLifecycleTransitionOnChange pins that an Active change reaches the
// lifecycle stream.
func TestEmitsLifecycleTransitionOnChange(t *testing.T) {
	t.Parallel()

	before := transitionFixture()
	before.SetActiveCondition(unikornv1.ActiveConditionReasonBuilding)

	after := before.DeepCopy()
	after.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)

	sink := emit(t, before, after, nil)

	require.Len(t, sink.entriesWithMsg("lifecycle"), 1)
}

// TestNoLifecycleTransitionWhenUnchanged pins the dedupe. Without it every pass
// re-emits the state it already reported, which for a polling controller is one
// spurious record per server per period.
func TestNoLifecycleTransitionWhenUnchanged(t *testing.T) {
	t.Parallel()

	before := transitionFixture()
	before.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)

	after := before.DeepCopy()
	after.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)

	sink := emit(t, before, after, nil)

	require.Empty(t, sink.entriesWithMsg("lifecycle"))
}

// TestNoDurationsOnNonArrivalWithFreshTimestamps pins that the histograms key
// off arriving at Running, not merely off a timestamp appearing. A server whose
// first observation is Stopped has booted, but it never arrived.
func TestNoDurationsOnNonArrivalWithFreshTimestamps(t *testing.T) {
	t.Parallel()

	provider, reader := newTestMeter(t)

	metrics, err := serverprovisioner.NewMetrics(provider.Meter("test"))
	require.NoError(t, err)

	before := transitionFixture()
	before.SetActiveCondition(unikornv1.ActiveConditionReasonPending)

	after := before.DeepCopy()
	arrive(after, time.Minute)
	// Booted, but settled somewhere other than Running.
	after.SetActiveCondition(unikornv1.ActiveConditionReasonStopped)

	_ = emit(t, before, after, metrics)

	require.Zero(t, histogramCount(t, reader, "unikorn_region_server_provision_duration_seconds"))
	require.Zero(t, histogramCount(t, reader, "unikorn_region_server_scheduling_duration_seconds"))
}

// TestRecordsResolvedLabels pins the metric attribution: which display name
// lands on which attribute, and that the IDs come from the label and the spec
// rather than being swapped.
func TestRecordsResolvedLabels(t *testing.T) {
	t.Parallel()

	meterProvider, reader := newTestMeter(t)

	metrics, err := serverprovisioner.NewMetrics(meterProvider.Meter("test"))
	require.NoError(t, err)

	before := transitionFixture()
	before.Labels = map[string]string{constants.RegionLabel: testRegionID}
	before.Spec.FlavorID = idstest.MustParseFlavorID(testMetricFlavorID)
	before.SetActiveCondition(unikornv1.ActiveConditionReasonBuilding)

	after := before.DeepCopy()
	arrive(after, time.Minute)

	ctrl := gomock.NewController(t)

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().Region(gomock.Any()).Return(&unikornv1.Region{
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{coreconstants.NameLabel: "region-one"}},
	}, nil)
	provider.EXPECT().Flavors(gomock.Any()).Return(types.FlavorList{
		{ID: "other", Name: "wrong"},
		{ID: testMetricFlavorID, Name: "gpu-8x"},
	}, nil)

	_ = emitWithProvider(t, before, after, metrics, provider)

	attributes := histogramAttributes(t, reader, "unikorn_region_server_provision_duration_seconds")
	require.Equal(t, testRegionID, attributes["region_id"])
	require.Equal(t, "region-one", attributes["region_name"])
	require.Equal(t, testMetricFlavorID, attributes["flavor_id"])
	require.Equal(t, "gpu-8x", attributes["flavor_name"])
}

// TestRecordsBareIDsWhenNamesUnresolvable pins the fallback: a provider that
// cannot answer must not lose the observation, only its display names.
func TestRecordsBareIDsWhenNamesUnresolvable(t *testing.T) {
	t.Parallel()

	meterProvider, reader := newTestMeter(t)

	metrics, err := serverprovisioner.NewMetrics(meterProvider.Meter("test"))
	require.NoError(t, err)

	before := transitionFixture()
	before.Labels = map[string]string{constants.RegionLabel: testRegionID}
	before.Spec.FlavorID = idstest.MustParseFlavorID(testMetricFlavorID)
	before.SetActiveCondition(unikornv1.ActiveConditionReasonBuilding)

	after := before.DeepCopy()
	arrive(after, time.Minute)

	ctrl := gomock.NewController(t)

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().Region(gomock.Any()).Return(nil, errUnavailable)
	provider.EXPECT().Flavors(gomock.Any()).Return(nil, errUnavailable)

	_ = emitWithProvider(t, before, after, metrics, provider)

	attributes := histogramAttributes(t, reader, "unikorn_region_server_provision_duration_seconds")
	require.Equal(t, testRegionID, attributes["region_id"])
	require.Empty(t, attributes["region_name"])
	require.Equal(t, testMetricFlavorID, attributes["flavor_id"])
	require.Empty(t, attributes["flavor_name"])
}

// TestRecordsEmptyFlavorNameWhenNotListed pins the flavor match: a flavor the
// provider does not list keeps its ID and loses only the name.
func TestRecordsEmptyFlavorNameWhenNotListed(t *testing.T) {
	t.Parallel()

	meterProvider, reader := newTestMeter(t)

	metrics, err := serverprovisioner.NewMetrics(meterProvider.Meter("test"))
	require.NoError(t, err)

	before := transitionFixture()
	before.Labels = map[string]string{constants.RegionLabel: testRegionID}
	before.Spec.FlavorID = idstest.MustParseFlavorID(testMetricFlavorID)
	before.SetActiveCondition(unikornv1.ActiveConditionReasonBuilding)

	after := before.DeepCopy()
	arrive(after, time.Minute)

	ctrl := gomock.NewController(t)

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().Region(gomock.Any()).Return(&unikornv1.Region{}, nil)
	provider.EXPECT().Flavors(gomock.Any()).Return(types.FlavorList{{ID: "other", Name: "wrong"}}, nil)

	_ = emitWithProvider(t, before, after, metrics, provider)

	attributes := histogramAttributes(t, reader, "unikorn_region_server_provision_duration_seconds")
	require.Equal(t, testMetricFlavorID, attributes["flavor_id"])
	require.Empty(t, attributes["flavor_name"])
}

// TestHealthOnlyChangeEmitsNothing pins that health is not its own record. Both
// conditions derive from the same provider read in the same pass, so a health
// line alongside the lifecycle one reported the same event twice; the lifecycle
// record is the only record.
func TestHealthOnlyChangeEmitsNothing(t *testing.T) {
	t.Parallel()

	before := transitionFixture()
	before.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)
	before.SetHealthCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "healthy")

	after := before.DeepCopy()
	after.SetHealthCondition(corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "degraded")

	sink := emit(t, before, after, nil)

	require.Empty(t, sink.entriesWithMsg("instance health transition"), "health is not a record of its own")
	require.Empty(t, sink.entriesWithMsg("lifecycle"), "the lifecycle state did not move")
}
