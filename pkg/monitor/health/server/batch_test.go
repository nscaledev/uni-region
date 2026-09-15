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
	goerrors "errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.uber.org/mock/gomock"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	idstest "github.com/unikorn-cloud/region/pkg/ids/idstest"
	healthserver "github.com/unikorn-cloud/region/pkg/monitor/health/server"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	providerTypes "github.com/unikorn-cloud/region/pkg/providers/types"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

var (
	errProvider = goerrors.New("provider unavailable")
	errModified = goerrors.New("the object has been modified")
)

// observation is how one identity's project read behaves: listErr fails the
// whole read, otherwise observe runs per server.
type observation struct {
	listErr error
	observe func(*unikornv1.Server) error
}

// batchServer is a server in a named region and identity.
func batchServer(name, region, identity string, phase unikornv1.ActiveConditionReason) *unikornv1.Server {
	server := &unikornv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel: orgID,
				constants.RegionLabel:           region,
				constants.IdentityLabel:         identity,
			},
		},
		Spec: unikornv1.ServerSpec{
			FlavorID: idstest.MustParseFlavorID(flavorID),
		},
	}

	server.SetActiveCondition(phase)

	return server
}

func batchIdentity(name string) *unikornv1.Identity {
	return &unikornv1.Identity{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
}

// batchHarness runs Check over servers whose identities behave as described,
// counting the provider reads it took.
type batchHarness struct {
	client client.Client
	sink   *captureSink
	reads  *atomic.Int64
	err    error
}

// batchOptions are the parts of the harness a test may vary.
type batchOptions struct {
	// cancelled runs the cycle against an already-cancelled context.
	cancelled bool
	// metrics attaches a real meter so the state gauge can be read back.
	metrics *healthserver.Metrics
	// patchErr fails every status patch, modelling the reconciler winning the
	// optimistic-lock race.
	patchErr error
}

func runBatchCheck(t *testing.T, objects []runtime.Object, byIdentity map[string]*observation) *batchHarness {
	t.Helper()

	return runBatchCheckWith(t, batchOptions{}, objects, byIdentity)
}

func runBatchCheckWith(t *testing.T, opts batchOptions, objects []runtime.Object, byIdentity map[string]*observation) *batchHarness {
	t.Helper()

	parent := t.Context()

	if opts.cancelled {
		cancelled, cancel := context.WithCancel(parent)
		cancel()

		parent = cancelled
	}

	ctrl := gomock.NewController(t)
	reads := &atomic.Int64{}

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().Region(gomock.Any()).Return(regionFixture(), nil).AnyTimes()
	provider.EXPECT().
		Flavors(gomock.Any()).
		Return(providerTypes.FlavorList{{ID: flavorID, Name: flavorName}}, nil).
		AnyTimes()

	provider.EXPECT().
		ObserveServers(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, identity *unikornv1.Identity) (providerTypes.ServerObserver, error) {
			reads.Add(1)

			behaviour, ok := byIdentity[identity.Name]
			if !ok {
				return nil, errProvider
			}

			if behaviour.listErr != nil {
				return nil, behaviour.listErr
			}

			observer := mocktypes.NewMockServerObserver(ctrl)
			observer.EXPECT().
				Observe(gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, s *unikornv1.Server) error {
					return behaviour.observe(s)
				}).
				AnyTimes()

			return observer, nil
		}).
		AnyTimes()

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(gomock.Any()).Return(provider, nil).AnyTimes()

	sink := newCaptureSink()
	ctx := logr.NewContext(parent, logr.New(sink))
	fake := newFakeClient(t, objects...)

	var k8sClient client.Client = fake

	if opts.patchErr != nil {
		k8sClient = interceptor.NewClient(fake, interceptor.Funcs{
			SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
				return opts.patchErr
			},
		})
	}

	checker := healthserver.New(k8sClient, namespace, providers, opts.metrics)

	return &batchHarness{client: k8sClient, sink: sink, reads: reads, err: checker.Check(ctx)}
}

func (h *batchHarness) phase(t *testing.T, name string) unikornv1.ActiveConditionReason {
	t.Helper()

	server := &unikornv1.Server{}
	require.NoError(t, h.client.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: name}, server))

	active, err := unikornv1.GetActiveCondition(server)
	require.NoError(t, err)

	return active.Reason
}

func (h *batchHarness) resourceVersion(t *testing.T, name string) string {
	t.Helper()

	server := &unikornv1.Server{}
	require.NoError(t, h.client.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: name}, server))

	return server.ResourceVersion
}

func setRunning(s *unikornv1.Server) error {
	s.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)

	return nil
}

func noChange(_ *unikornv1.Server) error { return nil }

// TestCheckReadsOnceForManyServersOfOneIdentity is the whole point of the
// change: the servers of one identity share one provider read.
func TestCheckReadsOnceForManyServersOfOneIdentity(t *testing.T) {
	t.Parallel()

	harness := runBatchCheck(t,
		[]runtime.Object{
			batchIdentity("identity-a"),
			batchServer("server-1", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding),
			batchServer("server-2", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding),
			batchServer("server-3", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding),
		},
		map[string]*observation{"identity-a": {observe: setRunning}},
	)

	require.NoError(t, harness.err)
	require.Equal(t, int64(1), harness.reads.Load())

	for _, name := range []string{"server-1", "server-2", "server-3"} {
		require.Equal(t, unikornv1.ActiveConditionReasonRunning, harness.phase(t, name))
	}
}

// TestCheckReadsOncePerIdentity pins that the read is per identity, not per
// estate: two identities cost two reads however many servers they hold.
func TestCheckReadsOncePerIdentity(t *testing.T) {
	t.Parallel()

	harness := runBatchCheck(t,
		[]runtime.Object{
			batchIdentity("identity-a"),
			batchIdentity("identity-b"),
			batchServer("server-a1", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding),
			batchServer("server-a2", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding),
			batchServer("server-b1", regionID, "identity-b", unikornv1.ActiveConditionReasonBuilding),
			batchServer("server-b2", regionID, "identity-b", unikornv1.ActiveConditionReasonBuilding),
		},
		map[string]*observation{
			"identity-a": {observe: setRunning},
			"identity-b": {observe: setRunning},
		},
	)

	require.NoError(t, harness.err)
	require.Equal(t, int64(2), harness.reads.Load())
	require.Equal(t, unikornv1.ActiveConditionReasonRunning, harness.phase(t, "server-a1"))
	require.Equal(t, unikornv1.ActiveConditionReasonRunning, harness.phase(t, "server-b2"))
}

// TestCheckFailedIdentityReadSpareseOtherIdentities is the best-effort
// contract at its widest blast radius: one identity's read failing costs that
// identity's servers this cycle and nothing else.
func TestCheckFailedIdentityReadSparesOtherIdentities(t *testing.T) {
	t.Parallel()

	harness := runBatchCheck(t,
		[]runtime.Object{
			batchIdentity("identity-a"),
			batchIdentity("identity-b"),
			batchServer("server-a1", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding),
			batchServer("server-b1", regionID, "identity-b", unikornv1.ActiveConditionReasonBuilding),
		},
		map[string]*observation{
			"identity-a": {listErr: errProvider},
			"identity-b": {observe: setRunning},
		},
	)

	require.NoError(t, harness.err)
	require.Equal(t, unikornv1.ActiveConditionReasonBuilding, harness.phase(t, "server-a1"))
	require.Equal(t, unikornv1.ActiveConditionReasonRunning, harness.phase(t, "server-b1"))
	require.Contains(t, harness.sink.errorsSnapshot(), "failed to observe identity servers, skipping")
}

// TestCheckMissingIdentitySparesOtherIdentities covers the other per-group
// failure: the Identity resource itself cannot be read.
func TestCheckMissingIdentitySparesOtherIdentities(t *testing.T) {
	t.Parallel()

	harness := runBatchCheck(t,
		[]runtime.Object{
			batchIdentity("identity-b"),
			batchServer("server-a1", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding),
			batchServer("server-b1", regionID, "identity-b", unikornv1.ActiveConditionReasonBuilding),
		},
		map[string]*observation{"identity-b": {observe: setRunning}},
	)

	require.NoError(t, harness.err)
	require.Equal(t, unikornv1.ActiveConditionReasonBuilding, harness.phase(t, "server-a1"))
	require.Equal(t, unikornv1.ActiveConditionReasonRunning, harness.phase(t, "server-b1"))
	require.Contains(t, harness.sink.errorsSnapshot(), "failed to get identity, skipping servers")
}

// TestCheckFailedObserveSparesOtherServers is the per-server end of best
// effort: one server's projection failing leaves its neighbours written.
func TestCheckFailedObserveSparesOtherServers(t *testing.T) {
	t.Parallel()

	harness := runBatchCheck(t,
		[]runtime.Object{
			batchIdentity("identity-a"),
			batchServer("server-1", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding),
			batchServer("server-2", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding),
		},
		map[string]*observation{
			"identity-a": {observe: func(s *unikornv1.Server) error {
				if s.Name == "server-1" {
					return errProvider
				}

				return setRunning(s)
			}},
		},
	)

	require.NoError(t, harness.err)
	require.Equal(t, unikornv1.ActiveConditionReasonBuilding, harness.phase(t, "server-1"))
	require.Equal(t, unikornv1.ActiveConditionReasonRunning, harness.phase(t, "server-2"))
	require.Contains(t, harness.sink.errorsSnapshot(), "failed to observe server, skipping")
}

// TestCheckSkipsPatchWhenProjectionUnchanged is what keeps a steady estate from
// rewriting every server's status every poll. resourceVersion is the witness:
// the fake client bumps it on any write.
func TestCheckSkipsPatchWhenProjectionUnchanged(t *testing.T) {
	t.Parallel()

	server := batchServer("server-1", regionID, "identity-a", unikornv1.ActiveConditionReasonRunning)

	harness := runBatchCheck(t,
		[]runtime.Object{batchIdentity("identity-a"), server},
		map[string]*observation{"identity-a": {observe: noChange}},
	)

	require.NoError(t, harness.err)
	require.Equal(t, server.ResourceVersion, harness.resourceVersion(t, "server-1"))
}

// TestCheckPatchesWhenProjectionChanged is the same guard the other way: a real
// change must still be written.
func TestCheckPatchesWhenProjectionChanged(t *testing.T) {
	t.Parallel()

	server := batchServer("server-1", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding)

	harness := runBatchCheck(t,
		[]runtime.Object{batchIdentity("identity-a"), server},
		map[string]*observation{"identity-a": {observe: setRunning}},
	)

	require.NoError(t, harness.err)
	require.NotEqual(t, server.ResourceVersion, harness.resourceVersion(t, "server-1"))
	require.Equal(t, unikornv1.ActiveConditionReasonRunning, harness.phase(t, "server-1"))
}

// TestCheckGroupsByIdentityAcrossRegions pins that the group key is the
// identity within a region, not the identity alone.
func TestCheckGroupsByIdentityAcrossRegions(t *testing.T) {
	t.Parallel()

	harness := runBatchCheck(t,
		[]runtime.Object{
			batchIdentity("identity-a"),
			batchServer("server-r1", "region-1", "identity-a", unikornv1.ActiveConditionReasonBuilding),
			batchServer("server-r2", "region-2", "identity-a", unikornv1.ActiveConditionReasonBuilding),
		},
		map[string]*observation{"identity-a": {observe: setRunning}},
	)

	require.NoError(t, harness.err)
	require.Equal(t, int64(2), harness.reads.Load())
}

// TestCheckSkipsServersMissingLabels pins that a server we cannot place is
// skipped rather than failing the cycle or joining the wrong group.
func TestCheckSkipsServersMissingLabels(t *testing.T) {
	t.Parallel()

	noRegion := batchServer("server-no-region", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding)
	delete(noRegion.Labels, constants.RegionLabel)

	noIdentity := batchServer("server-no-identity", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding)
	delete(noIdentity.Labels, constants.IdentityLabel)

	harness := runBatchCheck(t,
		[]runtime.Object{batchIdentity("identity-a"), noRegion, noIdentity},
		map[string]*observation{"identity-a": {observe: setRunning}},
	)

	require.NoError(t, harness.err)
	require.Equal(t, int64(0), harness.reads.Load())
	require.Equal(t, unikornv1.ActiveConditionReasonBuilding, harness.phase(t, "server-no-region"))
	require.Equal(t, unikornv1.ActiveConditionReasonBuilding, harness.phase(t, "server-no-identity"))
}

// TestCheckSkipsDeletingServers pins that a server on its way out is not
// observed, as before the change.
func TestCheckSkipsDeletingServers(t *testing.T) {
	t.Parallel()

	deleting := batchServer("server-deleting", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding)
	deleting.DeletionTimestamp = ptrTime(metav1.Now())
	deleting.Finalizers = []string{"unikorn"}

	harness := runBatchCheck(t,
		[]runtime.Object{batchIdentity("identity-a"), deleting},
		map[string]*observation{"identity-a": {observe: setRunning}},
	)

	require.NoError(t, harness.err)
	require.Equal(t, int64(0), harness.reads.Load())
}

func ptrTime(t metav1.Time) *metav1.Time { return &t }

// runBatchCheckWithMetrics is runBatchCheck with a real meter attached, so the
// state gauge can be read back.
func runBatchCheckWithMetrics(t *testing.T, objects []runtime.Object, byIdentity map[string]*observation) (*batchHarness, *sdkmetric.ManualReader) {
	t.Helper()

	meter, reader := newTestMeter(t)

	metrics, err := healthserver.NewMetrics(meter)
	require.NoError(t, err)

	return runBatchCheckWith(t, batchOptions{metrics: metrics}, objects, byIdentity), reader
}

// TestCheckKeepsAbsentServersOutOfTheStateGauge pins the documented rule that a
// server with no provider instance contributes nothing to the gauge: there is no
// provider state to count, and a phase read off nothing is not a phase.
func TestCheckKeepsAbsentServersOutOfTheStateGauge(t *testing.T) {
	t.Parallel()

	harness, reader := runBatchCheckWithMetrics(t,
		[]runtime.Object{
			batchIdentity("identity-a"),
			batchServer("server-present", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding),
			batchServer("server-absent", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding),
		},
		map[string]*observation{
			"identity-a": {observe: func(s *unikornv1.Server) error {
				if s.Name == "server-absent" {
					// The observer's contract: record the absent observation, then
					// surface the absence.
					s.Status.Observed = &unikornv1.ServerObservedStatus{Generation: 3}

					return coreerrors.ErrResourceNotFound
				}

				return setRunning(s)
			}},
		},
	)

	require.NoError(t, harness.err)

	var total int64
	for _, point := range collectGauge(t, reader) {
		total += point.Value
	}

	require.Equal(t, int64(1), total, "only the present server may be counted")

	// The absent server is still written, because that write is the observed wake.
	absent := &unikornv1.Server{}
	require.NoError(t, harness.client.Get(t.Context(),
		client.ObjectKey{Namespace: namespace, Name: "server-absent"}, absent))
	require.NotNil(t, absent.Status.Observed)
	require.Equal(t, int64(3), absent.Status.Observed.Generation)
}

// TestCheckCancelledContextAbortsTheCycle pins that the context going away is
// the one failure that is not best effort, and that it does not log an error per
// identity on the way out.
func TestCheckCancelledContextAbortsTheCycle(t *testing.T) {
	t.Parallel()

	harness := runBatchCheckWith(t, batchOptions{cancelled: true},
		[]runtime.Object{
			batchIdentity("identity-a"),
			batchIdentity("identity-b"),
			batchServer("server-a1", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding),
			batchServer("server-b1", regionID, "identity-b", unikornv1.ActiveConditionReasonBuilding),
		},
		map[string]*observation{
			"identity-a": {listErr: context.Canceled},
			"identity-b": {listErr: context.Canceled},
		},
	)

	require.ErrorIs(t, harness.err, context.Canceled)
	require.Empty(t, harness.sink.errorsSnapshot(),
		"an orderly shutdown must not log an error per identity")
}

// TestCheckLogsProviderDeadlineWhileRunning is the regression guard for a
// wedged provider being mistaken for a shutdown. The shared provider client
// bounds each request with an http.Client timeout, and an expiry of that wraps
// context.DeadlineExceeded exactly as a cancelled cycle does — so suppressing on
// the error rather than on the cycle's own context would make a broken Nova
// silent, which is the one condition an operator must hear about.
func TestCheckLogsProviderDeadlineWhileRunning(t *testing.T) {
	t.Parallel()

	wedged := fmt.Errorf("Get \"http://nova/servers/detail\": %w (Client.Timeout exceeded while awaiting headers)",
		context.DeadlineExceeded)

	require.ErrorIs(t, wedged, context.DeadlineExceeded, "the fixture must look like a real client timeout")

	harness := runBatchCheck(t,
		[]runtime.Object{
			batchIdentity("identity-a"),
			batchServer("server-a1", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding),
		},
		map[string]*observation{"identity-a": {listErr: wedged}},
	)

	require.NoError(t, harness.err, "a wedged identity must not fail the cycle")
	require.Contains(t, harness.sink.errorsSnapshot(), "failed to observe identity servers, skipping",
		"a wedged provider must be logged, not mistaken for a shutdown")
}

// TestCheckStateGaugeCountsEveryBucket pins the aggregation across the fan-out.
// Each bucket returns its own slice and they are merged after the group, so a
// merge that loses or collides a bucket loses those servers from the gauge
// entirely — a silent under-count rather than an error. More buckets than
// checkConcurrency, so an index collapsed onto the concurrency window is caught
// too; it asserts the merge, not the scheduling.
func TestCheckStateGaugeCountsEveryBucket(t *testing.T) {
	t.Parallel()

	objects := []runtime.Object{}
	byIdentity := map[string]*observation{}

	// More identities than checkConcurrency.
	for identity := range 6 {
		name := fmt.Sprintf("identity-%d", identity)

		objects = append(objects, batchIdentity(name))
		byIdentity[name] = &observation{observe: setRunning}

		for server := range 3 {
			objects = append(objects, batchServer(
				fmt.Sprintf("server-%d-%d", identity, server),
				regionID, name, unikornv1.ActiveConditionReasonBuilding))
		}
	}

	meter, reader := newTestMeter(t)

	metrics, err := healthserver.NewMetrics(meter)
	require.NoError(t, err)

	harness := runBatchCheckWith(t, batchOptions{metrics: metrics}, objects, byIdentity)

	require.NoError(t, harness.err)
	require.Equal(t, int64(6), harness.reads.Load())

	var total int64
	for _, point := range collectGauge(t, reader) {
		total += point.Value
	}

	require.Equal(t, int64(18), total, "every bucket's servers must reach the gauge")
}

// TestCheckClaimsAbsencePersistedOnlyWhenWritten pins that the absent-server log
// describes what happened. A server already recorded as absent projects
// identically, so the patch is skipped, and saying the observation was persisted
// would send an operator looking for a write that never occurred.
func TestCheckClaimsAbsencePersistedOnlyWhenWritten(t *testing.T) {
	t.Parallel()

	const persisted = "server not found in provider, absent observation persisted"

	// First sighting: the observation changes, so it is written and reported.
	fresh := batchServer("server-gone", regionID, "identity-a", unikornv1.ActiveConditionReasonRunning)

	first := runBatchCheck(t,
		[]runtime.Object{batchIdentity("identity-a"), fresh},
		map[string]*observation{"identity-a": {observe: observeAbsent}},
	)

	require.NoError(t, first.err)
	require.NotEqual(t, fresh.ResourceVersion, first.resourceVersion(t, "server-gone"))
	require.Len(t, first.sink.entriesWithMsg(persisted), 1)

	// Already recorded absent: the projection matches, nothing is written, and
	// nothing may claim otherwise.
	settled := batchServer("server-gone", regionID, "identity-a", unikornv1.ActiveConditionReasonRunning)
	settled.Status.Observed = &unikornv1.ServerObservedStatus{}

	second := runBatchCheck(t,
		[]runtime.Object{batchIdentity("identity-a"), settled},
		map[string]*observation{"identity-a": {observe: observeAbsent}},
	)

	require.NoError(t, second.err)
	require.Equal(t, settled.ResourceVersion, second.resourceVersion(t, "server-gone"))
	require.Empty(t, second.sink.entriesWithMsg(persisted),
		"nothing was persisted, so nothing may say it was")
}

// observeAbsent is the observer contract for a server with no provider row: the
// absent observation is recorded, then the absence is surfaced.
func observeAbsent(s *unikornv1.Server) error {
	if s.Status.Observed == nil {
		s.Status.Observed = &unikornv1.ServerObservedStatus{}
	}

	s.Status.Observed.Errored = false

	return coreerrors.ErrResourceNotFound
}

// TestCheckLogsAndDropsAPatchConflict pins the documented answer to losing the
// optimistic-lock race: the reconciler won, so the projection is dropped and
// re-derived next poll rather than rewritten from a stale base. Dropping it
// silently would make that indistinguishable from a healthy skip.
func TestCheckLogsAndDropsAPatchConflict(t *testing.T) {
	t.Parallel()

	conflict := kerrors.NewConflict(
		schema.GroupResource{Group: "region.unikorn-cloud.org", Resource: "servers"},
		"server-a1", errModified)

	harness := runBatchCheckWith(t, batchOptions{patchErr: conflict},
		[]runtime.Object{
			batchIdentity("identity-a"),
			batchServer("server-a1", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding),
			batchServer("server-a2", regionID, "identity-a", unikornv1.ActiveConditionReasonBuilding),
		},
		map[string]*observation{"identity-a": {observe: setRunning}},
	)

	require.NoError(t, harness.err, "a lost race must not fail the cycle")
	require.Equal(t, unikornv1.ActiveConditionReasonBuilding, harness.phase(t, "server-a1"))

	logged := harness.sink.errorsSnapshot()
	require.Equal(t, 2, countOf(logged, "failed to patch server status, skipping"),
		"every server that lost the race must say so")
}

func countOf(entries []string, want string) int {
	total := 0

	for _, entry := range entries {
		if entry == want {
			total++
		}
	}

	return total
}
