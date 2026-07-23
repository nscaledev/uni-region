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

	"github.com/stretchr/testify/require"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	serverprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/server"

	corev1 "k8s.io/api/core/v1"
)

// withRebuildState records a rebuild marker in the given lifecycle state.
func withRebuildState(state regionv1.ServerRebuildState) func(*regionv1.Server) {
	return func(server *regionv1.Server) {
		server.Status.Rebuild = &regionv1.ServerRebuildStatus{State: state}
	}
}

// withAvailableReason writes the core-owned Available condition with the given
// reason, the way the core reconciler records provision outcomes.
func withAvailableReason(reason unikornv1core.ConditionReason) func(*regionv1.Server) {
	return func(server *regionv1.Server) {
		status := corev1.ConditionFalse
		if reason == unikornv1core.ConditionReasonProvisioned {
			status = corev1.ConditionTrue
		}

		server.StatusConditionWrite(unikornv1core.ConditionAvailable, status, reason, "")
	}
}

func TestRebuildSettled(t *testing.T) {
	t.Parallel()

	// A Succeeded observation is a terminal outcome the reconciler has not yet
	// acted on (the settlement pass clears the marker): fire.
	t.Run("SucceededFires", func(t *testing.T) {
		t.Parallel()

		old := testServer(withRebuildState(regionv1.ServerRebuildStateRebuilding))
		updated := testServer(withRebuildState(regionv1.ServerRebuildStateSucceeded))

		require.True(t, serverprovisioner.RebuildSettled(old, updated))
	})

	// LEVEL semantics: a repeated identical Succeeded write (the monitor
	// re-asserts its observation every poll) fires again, so a lost settlement
	// pass or dropped wake re-fires next cycle. The settlement pass's marker
	// clear is what removes the level.
	t.Run("SucceededFiresOnRepeatedIdenticalWrite", func(t *testing.T) {
		t.Parallel()

		old := testServer(withRebuildState(regionv1.ServerRebuildStateSucceeded))
		updated := old.DeepCopy()

		require.True(t, serverprovisioner.RebuildSettled(old, updated))
	})

	// A Failed observation on a not-yet-parked server needs its park pass.
	t.Run("FailedFiresWhenNotParked", func(t *testing.T) {
		t.Parallel()

		old := testServer(withRebuildState(regionv1.ServerRebuildStateRebuilding))
		updated := testServer(withRebuildState(regionv1.ServerRebuildStateFailed))

		require.True(t, serverprovisioner.RebuildSettled(old, updated))
	})

	// A Failed observation still fires when Available reads Provisioned: the
	// park has not happened (or its write was lost), so it must re-fire.
	t.Run("FailedFiresWhenAvailableProvisioned", func(t *testing.T) {
		t.Parallel()

		old := testServer(withRebuildState(regionv1.ServerRebuildStateFailed), withAvailableReason(unikornv1core.ConditionReasonProvisioned))
		updated := old.DeepCopy()

		require.True(t, serverprovisioner.RebuildSettled(old, updated))
	})

	// Parked = the core-owned Available condition reads Errored, which is the
	// exact reason core's handleReconcileCondition writes for a terminal
	// (ErrUserActionRequired) provision result. A parked server's steady-state
	// monitor re-assertions must stay quiet or the reconciler is woken in a
	// loop by a park it has already performed.
	t.Run("FailedQuietWhenParked", func(t *testing.T) {
		t.Parallel()

		old := testServer(withRebuildState(regionv1.ServerRebuildStateFailed), withAvailableReason(unikornv1core.ConditionReasonErrored))
		updated := old.DeepCopy()

		require.False(t, serverprovisioner.RebuildSettled(old, updated))
	})

	// Initiated is unsettled intent: the arm pass's own yield drives the
	// submission, no wake is needed.
	t.Run("InitiatedQuiet", func(t *testing.T) {
		t.Parallel()

		old := testServer(withRebuildState(regionv1.ServerRebuildStateInitiated))
		updated := old.DeepCopy()

		require.False(t, serverprovisioner.RebuildSettled(old, updated))
	})

	// Rebuilding is in flight: nothing to settle yet.
	t.Run("RebuildingQuiet", func(t *testing.T) {
		t.Parallel()

		old := testServer(withRebuildState(regionv1.ServerRebuildStateRebuilding))
		updated := old.DeepCopy()

		require.False(t, serverprovisioner.RebuildSettled(old, updated))
	})

	// No marker, nothing to settle: ordinary status churn must not fire.
	t.Run("NilMarkerQuiet", func(t *testing.T) {
		t.Parallel()

		old := testServer()
		updated := testServer()

		require.False(t, serverprovisioner.RebuildSettled(old, updated))
	})

	t.Run("NilNew", func(t *testing.T) {
		t.Parallel()

		old := testServer(withRebuildState(regionv1.ServerRebuildStateSucceeded))

		require.False(t, serverprovisioner.RebuildSettled(old, nil))
	})
}
