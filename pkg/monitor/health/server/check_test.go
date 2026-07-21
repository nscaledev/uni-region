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
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/provisioninglog"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	idstest "github.com/unikorn-cloud/region/pkg/ids/idstest"
	healthserver "github.com/unikorn-cloud/region/pkg/monitor/health/server"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	providerTypes "github.com/unikorn-cloud/region/pkg/providers/types"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	namespace  = "test-ns"
	regionID   = "region-1"
	regionName = "Test Region"
	identityID = "identity-1"
	serverID   = "server-1"
	orgID      = "org-1"
	flavorID   = "eeeeeeee-0000-0000-0000-000000000001"
	flavorName = "m1.small"
)

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

func newFakeClient(t *testing.T, objects ...runtime.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&unikornv1.Server{})

	for _, o := range objects {
		builder = builder.WithRuntimeObjects(o)
	}

	return builder.Build()
}

func serverFixture(phase unikornv1.ActiveConditionReason, conditions ...metav1.Condition) *unikornv1.Server {
	server := &unikornv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serverID,
			Namespace: namespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel: orgID,
				constants.RegionLabel:           regionID,
				constants.IdentityLabel:         identityID,
			},
		},
		Spec: unikornv1.ServerSpec{
			FlavorID: idstest.MustParseFlavorID(flavorID),
		},
		Status: unikornv1.ServerStatus{
			Conditions: conditions,
		},
	}

	server.SetActiveCondition(phase)

	return server
}

func regionFixture() *unikornv1.Region {
	return &unikornv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      regionID,
			Namespace: namespace,
			Labels: map[string]string{
				coreconstants.NameLabel: regionName,
			},
		},
	}
}

func identityFixture() *unikornv1.Identity {
	return &unikornv1.Identity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      identityID,
			Namespace: namespace,
		},
	}
}

func healthCondition() metav1.Condition {
	return metav1.Condition{
		Type:               string(unikornv1core.ConditionHealthy),
		Status:             metav1.ConditionTrue,
		Reason:             string(unikornv1core.ConditionReasonHealthy),
		LastTransitionTime: metav1.NewTime(time.Now().Add(-time.Minute)),
	}
}

// runCheckFull builds a Checker, injects a capturing logger, and runs Check.
// It returns the fake Kubernetes client (for inspecting object state), the
// log sink (for asserting on emitted entries), and any error from Check.
func runCheckFull(t *testing.T, srv *unikornv1.Server, updateFn func(*unikornv1.Server)) (client.Client, *captureSink, error) {
	t.Helper()

	ctrl := gomock.NewController(t)

	mockProvider := mocktypes.NewMockProvider(ctrl)
	mockProvider.EXPECT().
		UpdateServerState(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ *unikornv1.Identity, s *unikornv1.Server) error {
			updateFn(s)
			return nil
		})
	mockProvider.EXPECT().
		Region(gomock.Any()).
		Return(regionFixture(), nil).
		AnyTimes()
	mockProvider.EXPECT().
		Flavors(gomock.Any()).
		Return(providerTypes.FlavorList{{ID: flavorID, Name: flavorName}}, nil).
		AnyTimes()

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(regionID).Return(mockProvider, nil).AnyTimes()

	sink := newCaptureSink()
	ctx := logr.NewContext(t.Context(), logr.New(sink))
	k8sClient := newFakeClient(t, identityFixture(), srv)

	checker := healthserver.New(k8sClient, namespace, providers, nil)

	return k8sClient, sink, checker.Check(ctx)
}

func runCheck(t *testing.T, srv *unikornv1.Server, updateFn func(*unikornv1.Server)) (*captureSink, error) {
	t.Helper()

	_, sink, err := runCheckFull(t, srv, updateFn)

	return sink, err
}

// TestCheckServerLogsOnPhaseChange verifies that a phase transition log is emitted when
// the server's lifecycle phase changes, and that it contains the required fields.
func TestCheckServerLogsOnPhaseChange(t *testing.T) {
	t.Parallel()

	srv := serverFixture(unikornv1.ActiveConditionReasonPending)

	sink, err := runCheck(t, srv, func(s *unikornv1.Server) {
		s.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)
	})

	require.NoError(t, err)

	entries := sink.entriesWithMsg("lifecycle")
	require.Len(t, entries, 1)

	resource, ok := entries[0]["resource"].(*provisioninglog.Resource)
	require.True(t, ok)
	require.Equal(t, serverID, resource.ID)

	scope, ok := entries[0]["scope"].(map[string]string)
	require.True(t, ok)
	require.Equal(t, orgID, scope["organization"])

	transition, ok := entries[0]["lifecycle"].(*provisioninglog.Transition)
	require.True(t, ok)
	require.Equal(t, string(unikornv1.ActiveConditionReasonRunning), transition.Reason)
}

// TestCheckServerNoLogWhenPhaseUnchanged verifies that no phase transition log is emitted
// when the provider reports the same phase.
func TestCheckServerNoLogWhenPhaseUnchanged(t *testing.T) {
	t.Parallel()

	srv := serverFixture(unikornv1.ActiveConditionReasonRunning)

	sink, err := runCheck(t, srv, func(s *unikornv1.Server) {
		s.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)
	})

	require.NoError(t, err)
	require.Empty(t, sink.entriesWithMsg("lifecycle"))
}

// TestCheckServerLogsOnStateChange verifies that a state transition log is emitted when
// the server's health condition changes, and that it contains the required fields.
func TestCheckServerLogsOnStateChange(t *testing.T) {
	t.Parallel()

	srv := serverFixture(unikornv1.ActiveConditionReasonRunning,
		healthCondition(),
	)

	sink, err := runCheck(t, srv, func(s *unikornv1.Server) {
		s.SetHealthCondition(corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "")
	})

	require.NoError(t, err)

	entries := sink.entriesWithMsg("instance health transition")
	require.Len(t, entries, 1)
	require.Equal(t, serverID, entries[0]["instance_id"])
	require.Equal(t, orgID, entries[0]["org_id"])
	require.Equal(t, regionID, entries[0]["region_id"])
	require.Equal(t, string(unikornv1core.ConditionReasonHealthy), entries[0]["from_health"])
	require.Equal(t, string(unikornv1core.ConditionReasonDegraded), entries[0]["to_health"])
	require.NotZero(t, entries[0]["duration_ms"])
}

// TestCheckServerNoLogWhenStateUnchanged verifies that no state transition log is emitted
// when the provider reports the same health condition.
func TestCheckServerNoLogWhenStateUnchanged(t *testing.T) {
	t.Parallel()

	srv := serverFixture(unikornv1.ActiveConditionReasonRunning,
		healthCondition(),
	)

	sink, err := runCheck(t, srv, func(s *unikornv1.Server) {
		s.SetHealthCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "")
	})

	require.NoError(t, err)
	require.Empty(t, sink.entriesWithMsg("instance health transition"))
}

// TestCheckServerNoLogWhenStatusUnchangedReasonDiffers documents that logStateTransition
// compares ConditionHealthy.Status, not Reason. If Status stays True while Reason changes
// (e.g. Healthy → Unknown, both True), no log is emitted. This is intentional: Reason
// changes within the same Status are not considered state transitions.
func TestCheckServerNoLogWhenStatusUnchangedReasonDiffers(t *testing.T) {
	t.Parallel()

	srv := serverFixture(unikornv1.ActiveConditionReasonRunning,
		healthCondition(),
	)

	sink, err := runCheck(t, srv, func(s *unikornv1.Server) {
		// Status stays True; only Reason changes.
		s.SetHealthCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonUnknown, "")
	})

	require.NoError(t, err)
	require.Empty(t, sink.entriesWithMsg("instance health transition"))
}

// TestCheckServerLogsWhenConditionAppearsForFirstTime verifies that a state transition log
// is emitted when there was no prior ConditionHealthy and the provider sets one, and that
// from_health is empty since there was no previous condition.
func TestCheckServerLogsWhenConditionAppearsForFirstTime(t *testing.T) {
	t.Parallel()

	srv := serverFixture(unikornv1.ActiveConditionReasonRunning) // no prior condition
	srv.CreationTimestamp = metav1.NewTime(time.Now().Add(-5 * time.Minute))

	sink, err := runCheck(t, srv, func(s *unikornv1.Server) {
		s.SetHealthCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "")
	})

	require.NoError(t, err)

	entries := sink.entriesWithMsg("instance health transition")
	require.Len(t, entries, 1)
	require.Empty(t, entries[0]["from_health"])
	require.Equal(t, string(unikornv1core.ConditionReasonHealthy), entries[0]["to_health"])
	require.NotZero(t, entries[0]["duration_ms"])
}

// TestCheckServerLogsBothOnCombinedChange verifies that both log entries are emitted when
// phase and health condition change simultaneously.
func TestCheckServerLogsBothOnCombinedChange(t *testing.T) {
	t.Parallel()

	srv := serverFixture(unikornv1.ActiveConditionReasonPending,
		healthCondition(),
	)

	sink, err := runCheck(t, srv, func(s *unikornv1.Server) {
		s.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)
		s.SetHealthCondition(corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "")
	})

	require.NoError(t, err)
	require.Len(t, sink.entriesWithMsg("lifecycle"), 1)
	require.Len(t, sink.entriesWithMsg("instance health transition"), 1)
}

// TestCheckServerNoHistogramOnClockSkew verifies that no histogram observation is recorded
// when a timestamp precedes CreationTimestamp (clock skew between Uni and Nova).
func TestCheckServerNoHistogramOnClockSkew(t *testing.T) {
	t.Parallel()

	meter, reader := newTestMeter(t)

	m, err := healthserver.NewMetrics(meter)
	require.NoError(t, err)

	createdAt := time.Now().Truncate(time.Second)
	// launchedAt is before createdAt — simulates clock skew.
	launchedAt := metav1.NewTime(createdAt.Add(-30 * time.Second))

	srv := serverFixture(unikornv1.ActiveConditionReasonPending)
	srv.CreationTimestamp = metav1.NewTime(createdAt)

	ctrl := gomock.NewController(t)

	mockProvider := mocktypes.NewMockProvider(ctrl)
	mockProvider.EXPECT().
		UpdateServerState(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ *unikornv1.Identity, s *unikornv1.Server) error {
			s.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)
			s.Status.LaunchedAt = &launchedAt

			return nil
		})
	mockProvider.EXPECT().
		Region(gomock.Any()).
		Return(regionFixture(), nil).
		AnyTimes()
	mockProvider.EXPECT().
		Flavors(gomock.Any()).
		Return(providerTypes.FlavorList{{ID: flavorID, Name: flavorName}}, nil).
		AnyTimes()

	mockProviders := mockproviders.NewMockProviders(ctrl)
	mockProviders.EXPECT().LookupCloud(regionID).Return(mockProvider, nil).AnyTimes()

	sink := newCaptureSink()
	ctx := logr.NewContext(t.Context(), logr.New(sink))
	checker := healthserver.New(newFakeClient(t, identityFixture(), srv), namespace, mockProviders, m)
	require.NoError(t, checker.Check(ctx))

	require.Empty(t, collectHistogram(t, reader))
	require.NotEmpty(t, sink.entriesWithMsg("skipping duration metric: negative duration (clock skew?)"))
}

// TestCheckServerNoHistogramWhenTimestampsNil verifies that no histogram observations are
// recorded when a server transitions Pending → Running but neither LaunchedAt nor
// ScheduledAt is set. This can happen for servers that booted before these fields were
// introduced, or on providers that do not populate the relevant Nova fields.
func TestCheckServerNoHistogramWhenTimestampsNil(t *testing.T) {
	t.Parallel()

	meter, reader := newTestMeter(t)

	m, err := healthserver.NewMetrics(meter)
	require.NoError(t, err)

	srv := serverFixture(unikornv1.ActiveConditionReasonPending)

	ctrl := gomock.NewController(t)

	mockProvider := mocktypes.NewMockProvider(ctrl)
	mockProvider.EXPECT().
		UpdateServerState(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ *unikornv1.Identity, s *unikornv1.Server) error {
			s.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)
			// LaunchedAt and ScheduledAt intentionally not set
			return nil
		})
	mockProvider.EXPECT().
		Region(gomock.Any()).
		Return(regionFixture(), nil).
		AnyTimes()
	mockProvider.EXPECT().
		Flavors(gomock.Any()).
		Return(providerTypes.FlavorList{{ID: flavorID, Name: flavorName}}, nil).
		AnyTimes()

	mockProviders := mockproviders.NewMockProviders(ctrl)
	mockProviders.EXPECT().LookupCloud(regionID).Return(mockProvider, nil).AnyTimes()

	ctx := logr.NewContext(t.Context(), logr.Discard())
	checker := healthserver.New(newFakeClient(t, identityFixture(), srv), namespace, mockProviders, m)
	require.NoError(t, checker.Check(ctx))

	require.Empty(t, collectHistogram(t, reader))
	require.Empty(t, collectSchedulingHistogram(t, reader))
}

// TestCheckServerRecordsProvisionDurationOnPendingToRunning verifies that a Pending →
// Running transition with LaunchedAt set produces a histogram observation whose duration
// equals LaunchedAt − CreationTimestamp.
func TestCheckServerRecordsProvisionDurationOnPendingToRunning(t *testing.T) {
	t.Parallel()

	meter, reader := newTestMeter(t)

	m, err := healthserver.NewMetrics(meter)
	require.NoError(t, err)

	createdAt := time.Now().Add(-2 * time.Minute).Truncate(time.Second)
	launchedAt := createdAt.Add(2 * time.Minute)

	srv := serverFixture(unikornv1.ActiveConditionReasonPending)
	srv.CreationTimestamp = metav1.NewTime(createdAt)

	ctrl := gomock.NewController(t)

	mockProvider := mocktypes.NewMockProvider(ctrl)
	mockProvider.EXPECT().
		UpdateServerState(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ *unikornv1.Identity, s *unikornv1.Server) error {
			s.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)

			t := metav1.NewTime(launchedAt)
			s.Status.LaunchedAt = &t

			return nil
		})
	mockProvider.EXPECT().
		Region(gomock.Any()).
		Return(regionFixture(), nil).
		AnyTimes()
	mockProvider.EXPECT().
		Flavors(gomock.Any()).
		Return(providerTypes.FlavorList{{ID: flavorID, Name: flavorName}}, nil).
		AnyTimes()

	mockProviders := mockproviders.NewMockProviders(ctrl)
	mockProviders.EXPECT().LookupCloud(regionID).Return(mockProvider, nil).AnyTimes()

	ctx := logr.NewContext(t.Context(), logr.Discard())
	checker := healthserver.New(newFakeClient(t, identityFixture(), srv), namespace, mockProviders, m)
	require.NoError(t, checker.Check(ctx))

	points := collectHistogram(t, reader)
	require.Len(t, points, 1)
	assert.Equal(t, uint64(1), points[0].Count)
	assert.InDelta(t, (2 * time.Minute).Seconds(), points[0].Sum, 0.001)
	assert.Equal(t, regionID, attrValue(points[0].Attributes, "region_id"))
	assert.Equal(t, regionName, attrValue(points[0].Attributes, "region_name"))
	assert.Equal(t, flavorID, attrValue(points[0].Attributes, "flavor_id"))
	assert.Equal(t, flavorName, attrValue(points[0].Attributes, "flavor_name"))
}

// TestCheckServerRecordsSchedulingDurationOnPendingToRunning verifies that a Pending →
// Running transition with ScheduledAt set produces a scheduling histogram observation
// whose duration equals ScheduledAt − CreationTimestamp.
func TestCheckServerRecordsSchedulingDurationOnPendingToRunning(t *testing.T) {
	t.Parallel()

	meter, reader := newTestMeter(t)

	m, err := healthserver.NewMetrics(meter)
	require.NoError(t, err)

	createdAt := time.Now().Add(-2 * time.Minute).Truncate(time.Second)
	scheduledAt := createdAt.Add(10 * time.Second)

	srv := serverFixture(unikornv1.ActiveConditionReasonPending)
	srv.CreationTimestamp = metav1.NewTime(createdAt)

	ctrl := gomock.NewController(t)

	mockProvider := mocktypes.NewMockProvider(ctrl)
	mockProvider.EXPECT().
		UpdateServerState(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ *unikornv1.Identity, s *unikornv1.Server) error {
			s.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)

			t := metav1.NewTime(scheduledAt)
			s.Status.ScheduledAt = &t

			return nil
		})
	mockProvider.EXPECT().
		Region(gomock.Any()).
		Return(regionFixture(), nil).
		AnyTimes()
	mockProvider.EXPECT().
		Flavors(gomock.Any()).
		Return(providerTypes.FlavorList{{ID: flavorID, Name: flavorName}}, nil).
		AnyTimes()

	mockProviders := mockproviders.NewMockProviders(ctrl)
	mockProviders.EXPECT().LookupCloud(regionID).Return(mockProvider, nil).AnyTimes()

	ctx := logr.NewContext(t.Context(), logr.Discard())
	checker := healthserver.New(newFakeClient(t, identityFixture(), srv), namespace, mockProviders, m)
	require.NoError(t, checker.Check(ctx))

	points := collectSchedulingHistogram(t, reader)
	require.Len(t, points, 1)
	assert.Equal(t, uint64(1), points[0].Count)
	assert.InDelta(t, (10 * time.Second).Seconds(), points[0].Sum, 0.001)
	assert.Equal(t, regionID, attrValue(points[0].Attributes, "region_id"))
	assert.Equal(t, regionName, attrValue(points[0].Attributes, "region_name"))
	assert.Equal(t, flavorID, attrValue(points[0].Attributes, "flavor_id"))
	assert.Equal(t, flavorName, attrValue(points[0].Attributes, "flavor_name"))

	// Provision histogram must be empty: LaunchedAt was not set.
	require.Empty(t, collectHistogram(t, reader))
}

// TestCheckServerNoHistogramOnRestartAfterFirstBoot verifies that neither histogram
// fires on a second Pending → Running transition when LaunchedAt and ScheduledAt are
// already set from the first boot.
func TestCheckServerNoHistogramOnRestartAfterFirstBoot(t *testing.T) {
	t.Parallel()

	meter, reader := newTestMeter(t)

	m, err := healthserver.NewMetrics(meter)
	require.NoError(t, err)

	launchedAt := metav1.NewTime(time.Now().Add(-time.Minute))
	scheduledAt := metav1.NewTime(time.Now().Add(-2 * time.Minute))

	// Server already has both timestamps from its first boot.
	srv := serverFixture(unikornv1.ActiveConditionReasonPending)
	srv.Status.LaunchedAt = &launchedAt
	srv.Status.ScheduledAt = &scheduledAt

	ctrl := gomock.NewController(t)

	mockProvider := mocktypes.NewMockProvider(ctrl)
	mockProvider.EXPECT().
		UpdateServerState(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ *unikornv1.Identity, s *unikornv1.Server) error {
			s.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)
			s.Status.LaunchedAt = &launchedAt
			s.Status.ScheduledAt = &scheduledAt

			return nil
		})
	mockProvider.EXPECT().
		Region(gomock.Any()).
		Return(regionFixture(), nil).
		AnyTimes()
	mockProvider.EXPECT().
		Flavors(gomock.Any()).
		Return(providerTypes.FlavorList{{ID: flavorID, Name: flavorName}}, nil).
		AnyTimes()

	mockProviders := mockproviders.NewMockProviders(ctrl)
	mockProviders.EXPECT().LookupCloud(regionID).Return(mockProvider, nil).AnyTimes()

	ctx := logr.NewContext(t.Context(), logr.Discard())
	checker := healthserver.New(newFakeClient(t, identityFixture(), srv), namespace, mockProviders, m)
	require.NoError(t, checker.Check(ctx))

	require.Empty(t, collectHistogram(t, reader))
	require.Empty(t, collectSchedulingHistogram(t, reader))
}

// runFallbackCheck builds a Checker with the given provider mocks and runs Check
// against a Pending server that transitions to Running with LaunchedAt set.
// Asserts the histogram recorded exactly one point and returns its
// region_id, region_name, flavor_id, flavor_name attribute values.
func runFallbackCheck(t *testing.T, setupRegion, setupFlavor func(*mocktypes.MockProvider)) (string, string, string, string) {
	t.Helper()

	meter, reader := newTestMeter(t)

	m, err := healthserver.NewMetrics(meter)
	require.NoError(t, err)

	createdAt := time.Now().Add(-time.Minute).Truncate(time.Second)
	launchedAt := createdAt.Add(time.Minute)

	srv := serverFixture(unikornv1.ActiveConditionReasonPending)
	srv.CreationTimestamp = metav1.NewTime(createdAt)

	ctrl := gomock.NewController(t)

	mockProvider := mocktypes.NewMockProvider(ctrl)
	mockProvider.EXPECT().
		UpdateServerState(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ *unikornv1.Identity, s *unikornv1.Server) error {
			s.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)

			t := metav1.NewTime(launchedAt)
			s.Status.LaunchedAt = &t

			return nil
		})
	setupRegion(mockProvider)
	setupFlavor(mockProvider)

	mockProviders := mockproviders.NewMockProviders(ctrl)
	mockProviders.EXPECT().LookupCloud(regionID).Return(mockProvider, nil).AnyTimes()

	ctx := logr.NewContext(t.Context(), logr.Discard())
	checker := healthserver.New(newFakeClient(t, identityFixture(), srv), namespace, mockProviders, m)
	require.NoError(t, checker.Check(ctx))

	points := collectHistogram(t, reader)
	require.Len(t, points, 1)

	return attrValue(points[0].Attributes, "region_id"),
		attrValue(points[0].Attributes, "region_name"),
		attrValue(points[0].Attributes, "flavor_id"),
		attrValue(points[0].Attributes, "flavor_name")
}

func TestResolveRegionNameEmptyOnLookupError(t *testing.T) {
	t.Parallel()

	rID, rName, fID, fName := runFallbackCheck(t,
		func(p *mocktypes.MockProvider) {
			p.EXPECT().Region(gomock.Any()).Return(nil, fmt.Errorf("unavailable")).AnyTimes() //nolint:err113
		},
		func(p *mocktypes.MockProvider) {
			p.EXPECT().Flavors(gomock.Any()).Return(providerTypes.FlavorList{{ID: flavorID, Name: flavorName}}, nil).AnyTimes()
		},
	)

	assert.Equal(t, regionID, rID)
	assert.Empty(t, rName)
	assert.Equal(t, flavorID, fID)
	assert.Equal(t, flavorName, fName)
}

func TestResolveRegionNameEmptyWhenLabelAbsent(t *testing.T) {
	t.Parallel()

	rID, rName, fID, fName := runFallbackCheck(t,
		func(p *mocktypes.MockProvider) {
			p.EXPECT().Region(gomock.Any()).Return(&unikornv1.Region{
				ObjectMeta: metav1.ObjectMeta{Name: regionID},
			}, nil).AnyTimes()
		},
		func(p *mocktypes.MockProvider) {
			p.EXPECT().Flavors(gomock.Any()).Return(providerTypes.FlavorList{{ID: flavorID, Name: flavorName}}, nil).AnyTimes()
		},
	)

	assert.Equal(t, regionID, rID)
	assert.Empty(t, rName)
	assert.Equal(t, flavorID, fID)
	assert.Equal(t, flavorName, fName)
}

func TestResolveFlavorNameEmptyOnLookupError(t *testing.T) {
	t.Parallel()

	rID, rName, fID, fName := runFallbackCheck(t,
		func(p *mocktypes.MockProvider) {
			p.EXPECT().Region(gomock.Any()).Return(regionFixture(), nil).AnyTimes()
		},
		func(p *mocktypes.MockProvider) {
			p.EXPECT().Flavors(gomock.Any()).Return(nil, fmt.Errorf("unavailable")).AnyTimes() //nolint:err113
		},
	)

	assert.Equal(t, regionID, rID)
	assert.Equal(t, regionName, rName)
	assert.Equal(t, flavorID, fID)
	assert.Empty(t, fName)
}

func TestResolveFlavorNameEmptyWhenNotInList(t *testing.T) {
	t.Parallel()

	rID, rName, fID, fName := runFallbackCheck(t,
		func(p *mocktypes.MockProvider) {
			p.EXPECT().Region(gomock.Any()).Return(regionFixture(), nil).AnyTimes()
		},
		func(p *mocktypes.MockProvider) {
			p.EXPECT().Flavors(gomock.Any()).Return(providerTypes.FlavorList{{ID: "other", Name: "other"}}, nil).AnyTimes()
		},
	)

	assert.Equal(t, regionID, rID)
	assert.Equal(t, regionName, rName)
	assert.Equal(t, flavorID, fID)
	assert.Empty(t, fName)
}

// TestCheckGaugeEmitsLowercaseStateLabels wires Check → updateStateCounts → gauge end-to-end.
// It asserts that state labels are lowercased and that counts aggregate correctly.
func TestCheckGaugeEmitsLowercaseStateLabels(t *testing.T) {
	t.Parallel()

	meter, reader := newTestMeter(t)

	m, err := healthserver.NewMetrics(meter)
	require.NoError(t, err)

	makeSrv := func(name string, phase unikornv1.ActiveConditionReason) *unikornv1.Server {
		srv := serverFixture(phase)
		srv.Name = name

		return srv
	}

	ctrl := gomock.NewController(t)

	mockProvider := mocktypes.NewMockProvider(ctrl)
	mockProvider.EXPECT().
		UpdateServerState(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil).
		AnyTimes()
	mockProvider.EXPECT().
		Region(gomock.Any()).
		Return(regionFixture(), nil).
		AnyTimes()
	mockProvider.EXPECT().
		Flavors(gomock.Any()).
		Return(providerTypes.FlavorList{{ID: flavorID, Name: flavorName}}, nil).
		AnyTimes()

	mockProviders := mockproviders.NewMockProviders(ctrl)
	mockProviders.EXPECT().LookupCloud(regionID).Return(mockProvider, nil).AnyTimes()

	srv1 := makeSrv("server-1", unikornv1.ActiveConditionReasonPending)
	srv2 := makeSrv("server-2", unikornv1.ActiveConditionReasonPending)
	srv3 := makeSrv("server-3", unikornv1.ActiveConditionReasonRunning)

	ctx := logr.NewContext(t.Context(), logr.Discard())
	checker := healthserver.New(newFakeClient(t, identityFixture(), srv1, srv2, srv3), namespace, mockProviders, m)
	require.NoError(t, checker.Check(ctx))

	points := collectGauge(t, reader)
	require.Len(t, points, 2)

	counts := map[string]int64{}
	for _, p := range points {
		counts[attrValue(p.Attributes, "state")] = p.Value
	}

	assert.Equal(t, int64(2), counts["pending"])
	assert.Equal(t, int64(1), counts["running"])
}

// assertProvisionDurationRecorded runs Check on a server transitioning from
// startPhase to Running with LaunchedAt set and asserts the provision histogram
// recorded exactly one observation with the expected duration. The Phase path
// is now Pending → Building → Running for VMs and Pending → Queued →
// Building → Running for baremetal, so the histogram has to fire from any
// pre-Running phase, not just Pending.
func assertProvisionDurationRecorded(t *testing.T, startPhase unikornv1.ActiveConditionReason) {
	t.Helper()

	meter, reader := newTestMeter(t)

	m, err := healthserver.NewMetrics(meter)
	require.NoError(t, err)

	createdAt := time.Now().Add(-2 * time.Minute).Truncate(time.Second)
	launchedAt := createdAt.Add(2 * time.Minute)

	srv := serverFixture(startPhase)
	srv.CreationTimestamp = metav1.NewTime(createdAt)

	ctrl := gomock.NewController(t)

	mockProvider := mocktypes.NewMockProvider(ctrl)
	mockProvider.EXPECT().
		UpdateServerState(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ *unikornv1.Identity, s *unikornv1.Server) error {
			s.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)

			t := metav1.NewTime(launchedAt)
			s.Status.LaunchedAt = &t

			return nil
		})
	mockProvider.EXPECT().
		Region(gomock.Any()).
		Return(regionFixture(), nil).
		AnyTimes()
	mockProvider.EXPECT().
		Flavors(gomock.Any()).
		Return(providerTypes.FlavorList{{ID: flavorID, Name: flavorName}}, nil).
		AnyTimes()

	mockProviders := mockproviders.NewMockProviders(ctrl)
	mockProviders.EXPECT().LookupCloud(regionID).Return(mockProvider, nil).AnyTimes()

	ctx := logr.NewContext(t.Context(), logr.Discard())
	checker := healthserver.New(newFakeClient(t, identityFixture(), srv), namespace, mockProviders, m)
	require.NoError(t, checker.Check(ctx))

	points := collectHistogram(t, reader)
	require.Len(t, points, 1)
	assert.Equal(t, uint64(1), points[0].Count)
	assert.InDelta(t, (2 * time.Minute).Seconds(), points[0].Sum, 0.001)
}

// TestCheckServerRecordsProvisionDurationOnBuildingToRunning verifies that a
// Building → Running transition still records the provision histogram. The Phase
// path now goes Pending → Building → Running for VMs, so without this the
// histogram would silently stop firing.
func TestCheckServerRecordsProvisionDurationOnBuildingToRunning(t *testing.T) {
	t.Parallel()

	assertProvisionDurationRecorded(t, unikornv1.ActiveConditionReasonBuilding)
}

// TestCheckServerRecordsProvisionDurationOnQueuedToRunning covers the baremetal
// path where the server's last observed Phase before Running may be Queued (for
// example, if Building was skipped between poll cycles).
func TestCheckServerRecordsProvisionDurationOnQueuedToRunning(t *testing.T) {
	t.Parallel()

	assertProvisionDurationRecorded(t, unikornv1.ActiveConditionReasonQueued)
}

// TestCheckServerNoHistogramOnIntermediatePhaseTransition verifies that
// transitions that are not into Running (e.g. Pending → Building) do not
// produce a histogram observation; the histograms must only fire on the
// first reach of Running.
func TestCheckServerNoHistogramOnIntermediatePhaseTransition(t *testing.T) {
	t.Parallel()

	meter, reader := newTestMeter(t)

	m, err := healthserver.NewMetrics(meter)
	require.NoError(t, err)

	createdAt := time.Now().Add(-time.Minute).Truncate(time.Second)
	launchedAt := metav1.NewTime(createdAt.Add(30 * time.Second))

	srv := serverFixture(unikornv1.ActiveConditionReasonPending)
	srv.CreationTimestamp = metav1.NewTime(createdAt)

	ctrl := gomock.NewController(t)

	mockProvider := mocktypes.NewMockProvider(ctrl)
	mockProvider.EXPECT().
		UpdateServerState(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ *unikornv1.Identity, s *unikornv1.Server) error {
			s.SetActiveCondition(unikornv1.ActiveConditionReasonBuilding)
			s.Status.LaunchedAt = &launchedAt

			return nil
		})
	mockProvider.EXPECT().
		Region(gomock.Any()).
		Return(regionFixture(), nil).
		AnyTimes()
	mockProvider.EXPECT().
		Flavors(gomock.Any()).
		Return(providerTypes.FlavorList{{ID: flavorID, Name: flavorName}}, nil).
		AnyTimes()

	mockProviders := mockproviders.NewMockProviders(ctrl)
	mockProviders.EXPECT().LookupCloud(regionID).Return(mockProvider, nil).AnyTimes()

	ctx := logr.NewContext(t.Context(), logr.Discard())
	checker := healthserver.New(newFakeClient(t, identityFixture(), srv), namespace, mockProviders, m)
	require.NoError(t, checker.Check(ctx))

	require.Empty(t, collectHistogram(t, reader))
	require.Empty(t, collectSchedulingHistogram(t, reader))
}
