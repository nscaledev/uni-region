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

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	server "github.com/unikorn-cloud/region/pkg/provisioners/managers/server"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// TestProviderCreateFailureReadsObservation pins the guard onto the monitor-owned
// boot latch: a server that has ever booted is never a create failure, however
// the legacy copy of the latch reads.
func TestProviderCreateFailureReadsObservation(t *testing.T) {
	t.Parallel()

	booted := metav1.NewTime(time.Now().Add(-time.Hour))

	srv := &unikornv1.Server{}
	srv.SetActiveCondition(unikornv1.ActiveConditionReasonError)
	srv.Status.Observed = &unikornv1.ServerObservedStatus{ProvisionedAt: &booted}

	require.False(t, server.ProviderCreateFailure(srv),
		"a server observed booted is never a create failure, even in an error state")

	fresh := &unikornv1.Server{}
	fresh.SetActiveCondition(unikornv1.ActiveConditionReasonError)
	fresh.Status.Observed = &unikornv1.ServerObservedStatus{ServerGeneration: 1}

	require.True(t, server.ProviderCreateFailure(fresh),
		"an errored server that never booted is a create failure")
}

// TestResetProviderCreateRuntimeStatusLeavesObservedFactsAlone pins the ownership
// boundary: the retry reset may clear only what the reconciler owns. The monitor
// overwrites its own facts on the next poll, and its boot latch must never be
// cleared — the retry guard keys off it to avoid destroying a server that booted.
func TestResetProviderCreateRuntimeStatusLeavesObservedFactsAlone(t *testing.T) {
	t.Parallel()

	launched := metav1.NewTime(time.Now().Add(-time.Minute))
	scheduled := metav1.NewTime(time.Now().Add(-2 * time.Minute))
	mac := "e0:9d:73:86:cc:18"

	srv := &unikornv1.Server{}
	srv.Status.PrivateIP = ptr.To("10.0.0.1")
	srv.Status.PublicIP = ptr.To("192.0.2.1")
	srv.Status.LaunchedAt = &launched
	srv.Status.ScheduledAt = &scheduled
	srv.Status.Observed = &unikornv1.ServerObservedStatus{
		ServerGeneration: 1,
		MACAddress:       &mac,
		LaunchedAt:       &launched,
		ScheduledAt:      &scheduled,
		ProvisionedAt:    &launched,
	}

	server.ResetProviderCreateRuntimeStatusForTest(srv)

	require.Nil(t, srv.Status.PrivateIP, "reconciler-owned addresses are cleared")
	require.Nil(t, srv.Status.PublicIP, "reconciler-owned addresses are cleared")

	// These two are the assertions that fail before the change: the reset
	// currently clears both legacy timestamps, which are monitor-owned.
	require.NotNil(t, srv.Status.LaunchedAt, "the legacy launchedAt is monitor-owned and not the reconciler's to clear")
	require.NotNil(t, srv.Status.ScheduledAt, "the legacy scheduledAt is monitor-owned and not the reconciler's to clear")

	require.Equal(t, &launched, srv.Status.Observed.LaunchedAt, "monitor-owned timestamps are not the reconciler's to clear")
	require.Equal(t, &scheduled, srv.Status.Observed.ScheduledAt, "monitor-owned timestamps are not the reconciler's to clear")
	require.Equal(t, &launched, srv.Status.Observed.ProvisionedAt, "the boot latch is never cleared")
	require.Equal(t, &mac, srv.Status.Observed.MACAddress, "the MAC is not the reconciler's to clear")
}
