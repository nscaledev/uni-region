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

//nolint:testpackage // Tests cover the unexported watch predicate directly.
package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/event"
)

func serverWithProviderCreateFailure() *unikornv1.Server {
	server := &unikornv1.Server{}
	server.SetActiveCondition(unikornv1.ActiveConditionReasonError)

	return server
}

func TestProviderCreateFailureUpdate(t *testing.T) {
	t.Parallel()

	t.Run("PreLaunchError", func(t *testing.T) {
		t.Parallel()

		require.True(t, providerCreateFailureUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: &unikornv1.Server{},
			ObjectNew: serverWithProviderCreateFailure(),
		}))
	})

	t.Run("AlreadyErrored", func(t *testing.T) {
		t.Parallel()

		server := serverWithProviderCreateFailure()

		require.False(t, providerCreateFailureUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: server,
			ObjectNew: server.DeepCopy(),
		}))
	})

	t.Run("AlreadyLaunched", func(t *testing.T) {
		t.Parallel()

		server := serverWithProviderCreateFailure()
		launchedAt := metav1.NewTime(time.Now())
		server.Status.LaunchedAt = &launchedAt

		require.False(t, providerCreateFailureUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: &unikornv1.Server{},
			ObjectNew: server,
		}))
	})

	t.Run("RunningWithoutLaunchTimestamp", func(t *testing.T) {
		t.Parallel()

		server := serverWithProviderCreateFailure()
		server.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)

		require.False(t, providerCreateFailureUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: &unikornv1.Server{},
			ObjectNew: server,
		}))
	})

	// A server that has ever been provisioned must never re-arm the rebuild path,
	// even if its launch timestamp has been lost and the error phase then appears
	// (e.g. a flaky-provider re-reconcile after a controller restart).
	t.Run("ProvisionedWithoutLaunchTimestamp", func(t *testing.T) {
		t.Parallel()

		server := serverWithProviderCreateFailure()
		provisionedAt := metav1.NewTime(time.Now().Add(-time.Hour))
		server.Status.ProvisionedAt = &provisionedAt

		require.False(t, providerCreateFailureUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: &unikornv1.Server{},
			ObjectNew: server,
		}))
	})
}

func serverWithRebuildState(state unikornv1.ServerRebuildState) *unikornv1.Server {
	server := &unikornv1.Server{}
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{State: state}

	return server
}

func TestRebuildSettledUpdate(t *testing.T) {
	t.Parallel()

	t.Run("PendingSettles", func(t *testing.T) {
		t.Parallel()

		require.True(t, serverRebuildSettledUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: serverWithRebuildState(unikornv1.ServerRebuildStateRebuilding),
			ObjectNew: serverWithRebuildState(unikornv1.ServerRebuildStateSucceeded),
		}))
	})

	t.Run("NilOld", func(t *testing.T) {
		t.Parallel()

		require.False(t, serverRebuildSettledUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: nil,
			ObjectNew: serverWithRebuildState(unikornv1.ServerRebuildStateSucceeded),
		}))
	})

	t.Run("NilNew", func(t *testing.T) {
		t.Parallel()

		require.False(t, serverRebuildSettledUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: serverWithRebuildState(unikornv1.ServerRebuildStateRebuilding),
			ObjectNew: nil,
		}))
	})
}

func serverWithObserved(observed *unikornv1.ServerObservedStatus) *unikornv1.Server {
	server := &unikornv1.Server{}
	server.Status.Observed = observed

	return server
}

// TestServerObservedUpdate covers the wake arm for the monitor's write region.
// A predicate sees only the old and new objects, so without the comparison the
// arm would return true for every update, including the reconciler's own status
// writes.
//
// The comparison is whole-subtree rather than per-field so facts added to the
// region later wake the reconciler without touching this predicate. That is safe
// not because the region has a single writer — the reconciler's create-retry path
// reaches the same projection — but because a self-wake converges: the next pass
// writes the same value and the arm falls quiet. The sibling arms are
// field-specific edge detectors because they guard conditions, which both status
// writers share.
func TestServerObservedUpdate(t *testing.T) {
	t.Parallel()

	imageID := idstest.MustParseImageID("33333333-3333-4333-a333-333333333333")
	otherImageID := idstest.MustParseImageID("44444444-4444-4444-a444-444444444444")

	t.Run("FirstObservation", func(t *testing.T) {
		t.Parallel()

		require.True(t, serverObservedUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: &unikornv1.Server{},
			ObjectNew: serverWithObserved(&unikornv1.ServerObservedStatus{Generation: 1}),
		}))
	})

	t.Run("ImageChange", func(t *testing.T) {
		t.Parallel()

		require.True(t, serverObservedUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: serverWithObserved(&unikornv1.ServerObservedStatus{Generation: 1, Image: &imageID}),
			ObjectNew: serverWithObserved(&unikornv1.ServerObservedStatus{Generation: 1, Image: &otherImageID}),
		}))
	})

	t.Run("GenerationChange", func(t *testing.T) {
		t.Parallel()

		require.True(t, serverObservedUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: serverWithObserved(&unikornv1.ServerObservedStatus{Generation: 1, Image: &imageID}),
			ObjectNew: serverWithObserved(&unikornv1.ServerObservedStatus{Generation: 2, Image: &imageID}),
		}))
	})

	t.Run("ErrorAppears", func(t *testing.T) {
		t.Parallel()

		require.True(t, serverObservedUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: serverWithObserved(&unikornv1.ServerObservedStatus{Generation: 1}),
			ObjectNew: serverWithObserved(&unikornv1.ServerObservedStatus{
				Generation: 1,
				Error:      &unikornv1.ServerObservedError{Code: ptr.To(int32(500)), Message: "No valid host was found"},
			}),
		}))
	})

	t.Run("ErrorClears", func(t *testing.T) {
		t.Parallel()

		require.True(t, serverObservedUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: serverWithObserved(&unikornv1.ServerObservedStatus{
				Generation: 1,
				Error:      &unikornv1.ServerObservedError{Code: ptr.To(int32(500)), Message: "No valid host was found"},
			}),
			ObjectNew: serverWithObserved(&unikornv1.ServerObservedStatus{Generation: 1}),
		}))
	})

	// The reconciler's own status write carries the region back unchanged. If that
	// woke the reconciler the controller would spin against itself.
	t.Run("UnchangedObservation", func(t *testing.T) {
		t.Parallel()

		server := serverWithObserved(&unikornv1.ServerObservedStatus{Generation: 1, Image: &imageID})

		require.False(t, serverObservedUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: server,
			ObjectNew: server.DeepCopy(),
		}))
	})

	t.Run("ChangeOutsideTheRegion", func(t *testing.T) {
		t.Parallel()

		old := serverWithObserved(&unikornv1.ServerObservedStatus{Generation: 1, Image: &imageID})
		updated := old.DeepCopy()
		updated.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)

		require.False(t, serverObservedUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: old,
			ObjectNew: updated,
		}))
	})

	// Same instant, different time.Location pointer. A reflect-based comparison
	// reports these unequal and would wake the reconciler for nothing every poll
	// that re-decoded a fault time; semantic equality compares the instant.
	t.Run("EquivalentFaultTimestamps", func(t *testing.T) {
		t.Parallel()

		instant := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
		relocated := instant.In(time.FixedZone("", 0))

		require.False(t, serverObservedUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: serverWithObserved(&unikornv1.ServerObservedStatus{
				Generation: 1,
				Error:      &unikornv1.ServerObservedError{At: ptr.To(metav1.NewTime(instant))},
			}),
			ObjectNew: serverWithObserved(&unikornv1.ServerObservedStatus{
				Generation: 1,
				Error:      &unikornv1.ServerObservedError{At: ptr.To(metav1.NewTime(relocated))},
			}),
		}))
	})

	t.Run("NilOld", func(t *testing.T) {
		t.Parallel()

		require.False(t, serverObservedUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: nil,
			ObjectNew: serverWithObserved(&unikornv1.ServerObservedStatus{Generation: 1}),
		}))
	})

	t.Run("NilNew", func(t *testing.T) {
		t.Parallel()

		require.False(t, serverObservedUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: serverWithObserved(&unikornv1.ServerObservedStatus{Generation: 1}),
			ObjectNew: nil,
		}))
	})
}
