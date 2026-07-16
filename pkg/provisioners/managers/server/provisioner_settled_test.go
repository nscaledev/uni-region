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

// withRebuildPending stamps a Nova-accepted rebuild marker: intent recorded and
// at least one accepted attempt, so RebuildPending() is true.
func withRebuildPending(server *regionv1.Server) {
	server.Status.Rebuild = &regionv1.ServerRebuildStatus{AcceptedAttempts: 1}
}

// withRebuildIntentOnly records rebuild intent that Nova never accepted
// (AcceptedAttempts == 0): nothing destructive is in flight, so RebuildPending()
// is false.
func withRebuildIntentOnly(server *regionv1.Server) {
	server.Status.Rebuild = &regionv1.ServerRebuildStatus{AcceptedAttempts: 0}
}

// withHealthyReason writes the Healthy condition with the given reason. The
// status value tracks the reason the way the monitor writes it (Healthy is the
// only True reason), but the predicate keys off the reason alone.
func withHealthyReason(reason unikornv1core.ConditionReason) func(*regionv1.Server) {
	return func(server *regionv1.Server) {
		status := corev1.ConditionFalse
		if reason == unikornv1core.ConditionReasonHealthy {
			status = corev1.ConditionTrue
		}

		server.StatusConditionWrite(unikornv1core.ConditionHealthy, status, reason, "")
	}
}

func TestRebuildSettled(t *testing.T) {
	t.Parallel()

	// A pending rebuild whose Healthy condition transitions from the in-flight
	// Provisioning reason to a settled success is the wake signal.
	t.Run("PendingProvisioningToHealthy", func(t *testing.T) {
		t.Parallel()

		old := testServer(withRebuildPending, withHealthyReason(unikornv1core.ConditionReasonProvisioning))
		updated := testServer(withRebuildPending, withHealthyReason(unikornv1core.ConditionReasonHealthy))

		require.True(t, serverprovisioner.RebuildSettled(old, updated))
	})

	// A pending rebuild that settles into an error also needs a wake: the
	// reconciler decides whether to park the server.
	t.Run("PendingProvisioningToErrored", func(t *testing.T) {
		t.Parallel()

		old := testServer(withRebuildPending, withHealthyReason(unikornv1core.ConditionReasonProvisioning))
		updated := testServer(withRebuildPending, withHealthyReason(unikornv1core.ConditionReasonErrored))

		require.True(t, serverprovisioner.RebuildSettled(old, updated))
	})

	// Old lacking the Healthy condition entirely counts as a transition into a
	// settled reason.
	t.Run("PendingAbsentToHealthy", func(t *testing.T) {
		t.Parallel()

		old := testServer(withRebuildPending)
		updated := testServer(withRebuildPending, withHealthyReason(unikornv1core.ConditionReasonHealthy))

		require.True(t, serverprovisioner.RebuildSettled(old, updated))
	})

	// A rebuilt-then-broken server transitions settled->settled (Healthy to
	// Errored); it still needs its park pass, so this must fire.
	t.Run("PendingHealthyToErrored", func(t *testing.T) {
		t.Parallel()

		old := testServer(withRebuildPending, withHealthyReason(unikornv1core.ConditionReasonHealthy))
		updated := testServer(withRebuildPending, withHealthyReason(unikornv1core.ConditionReasonErrored))

		require.True(t, serverprovisioner.RebuildSettled(old, updated))
	})

	// A parked server's repeated Errored writes are the same reason each time;
	// they must stay quiet so the reconciler is not woken in a loop.
	t.Run("PendingErroredToErrored", func(t *testing.T) {
		t.Parallel()

		old := testServer(withRebuildPending, withHealthyReason(unikornv1core.ConditionReasonErrored))
		updated := testServer(withRebuildPending, withHealthyReason(unikornv1core.ConditionReasonErrored))

		require.False(t, serverprovisioner.RebuildSettled(old, updated))
	})

	// A still-rebuilding server stays on the Provisioning reason; no settled
	// transition, no wake.
	t.Run("PendingProvisioningToProvisioning", func(t *testing.T) {
		t.Parallel()

		old := testServer(withRebuildPending, withHealthyReason(unikornv1core.ConditionReasonProvisioning))
		updated := testServer(withRebuildPending, withHealthyReason(unikornv1core.ConditionReasonProvisioning))

		require.False(t, serverprovisioner.RebuildSettled(old, updated))
	})

	// Without a pending rebuild marker there is nothing to settle, so an ordinary
	// health transition must not fire this predicate.
	t.Run("NoMarkerProvisioningToHealthy", func(t *testing.T) {
		t.Parallel()

		old := testServer(withHealthyReason(unikornv1core.ConditionReasonProvisioning))
		updated := testServer(withHealthyReason(unikornv1core.ConditionReasonHealthy))

		require.False(t, serverprovisioner.RebuildSettled(old, updated))
	})

	// Recorded intent that Nova never accepted (AcceptedAttempts == 0) is not a
	// pending rebuild; a health transition must not fire.
	t.Run("IntentOnlyProvisioningToHealthy", func(t *testing.T) {
		t.Parallel()

		old := testServer(withRebuildIntentOnly, withHealthyReason(unikornv1core.ConditionReasonProvisioning))
		updated := testServer(withRebuildIntentOnly, withHealthyReason(unikornv1core.ConditionReasonHealthy))

		require.False(t, serverprovisioner.RebuildSettled(old, updated))
	})

	t.Run("NilOld", func(t *testing.T) {
		t.Parallel()

		updated := testServer(withRebuildPending, withHealthyReason(unikornv1core.ConditionReasonHealthy))

		require.False(t, serverprovisioner.RebuildSettled(nil, updated))
	})

	t.Run("NilNew", func(t *testing.T) {
		t.Parallel()

		old := testServer(withRebuildPending, withHealthyReason(unikornv1core.ConditionReasonProvisioning))

		require.False(t, serverprovisioner.RebuildSettled(old, nil))
	})
}
