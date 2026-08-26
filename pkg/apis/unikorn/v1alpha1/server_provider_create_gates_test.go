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

package v1alpha1_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

const testProviderCreateGate = "example.unikorn-cloud.org/pre-create-ready"

func TestLockedProviderCreateGate(t *testing.T) {
	t.Parallel()

	server := &regionv1.Server{
		Spec: regionv1.ServerSpec{
			ProviderCreateGates: []regionv1.ServerProviderCreateGate{{ConditionType: testProviderCreateGate}},
		},
	}

	// No state reported yet: Closed by default, not Locked.
	_, ok := server.LockedProviderCreateGate()
	require.False(t, ok)

	// Reported Closed (transient, still working): not Locked.
	server.ProviderCreateGateStatusWrite(testProviderCreateGate, regionv1.ServerProviderCreateGateClosed, "svc", "AllocatingPKey", "still programming")
	_, ok = server.LockedProviderCreateGate()
	require.False(t, ok)

	// Locked: returned with its reason.
	server.ProviderCreateGateStatusWrite(testProviderCreateGate, regionv1.ServerProviderCreateGateLocked, "svc", "NoPKeyAvailable", "p_key pool exhausted")
	gate, ok := server.LockedProviderCreateGate()
	require.True(t, ok)
	require.Equal(t, "NoPKeyAvailable", gate.Reason)
	require.Equal(t, regionv1.ServerProviderCreateGateLocked, gate.State)

	// Open (satisfied): not Locked.
	server.ProviderCreateGateStatusWrite(testProviderCreateGate, regionv1.ServerProviderCreateGateOpen, "svc", "Programmed", "done")
	_, ok = server.LockedProviderCreateGate()
	require.False(t, ok)
}

// TestProviderCreateGateClosedSelfLoop covers a satisfier re-reporting Closed to
// refresh its reason while it keeps working. The state stays Closed (the gate
// is not resolved), the reason updates, and the transition time is preserved
// because the state did not change.
func TestProviderCreateGateClosedSelfLoop(t *testing.T) {
	t.Parallel()

	server := &regionv1.Server{
		Spec: regionv1.ServerSpec{
			ProviderCreateGates: []regionv1.ServerProviderCreateGate{{ConditionType: testProviderCreateGate}},
		},
	}

	server.ProviderCreateGateStatusWrite(testProviderCreateGate, regionv1.ServerProviderCreateGateClosed, "svc", "AllocatingPKey", "requested p_key")
	require.False(t, server.ProviderCreateGatesReady())

	first, ok := server.ProviderCreateGateStatusRead(testProviderCreateGate)
	require.True(t, ok)

	firstTransitionTime := first.LastTransitionTime

	server.ProviderCreateGateStatusWrite(testProviderCreateGate, regionv1.ServerProviderCreateGateClosed, "svc", "AllocatingPKey", "programming fabric")

	second, ok := server.ProviderCreateGateStatusRead(testProviderCreateGate)
	require.True(t, ok)
	require.Equal(t, regionv1.ServerProviderCreateGateClosed, second.State)
	require.Equal(t, "programming fabric", second.Message)
	require.False(t, server.ProviderCreateGatesReady())
	require.True(t, second.LastTransitionTime.Equal(&firstTransitionTime))
}

func TestServerProviderCreateGates(t *testing.T) {
	t.Parallel()

	server := &regionv1.Server{
		Spec: regionv1.ServerSpec{
			ProviderCreateGates: []regionv1.ServerProviderCreateGate{
				{ConditionType: testProviderCreateGate},
			},
		},
	}

	require.True(t, server.ProviderCreateGateConfigured(testProviderCreateGate))
	require.False(t, server.ProviderCreateGateConfigured("example.unikorn-cloud.org/other"))
	require.False(t, server.ProviderCreateGatesReady())
	require.Equal(t, []string{testProviderCreateGate}, server.RemainingProviderCreateGates())

	server.ProviderCreateGateStatusWrite(testProviderCreateGate, regionv1.ServerProviderCreateGateClosed, "region", "Reset", "provider create will retry")
	require.False(t, server.ProviderCreateGatesReady())
	require.Equal(t, []string{testProviderCreateGate}, server.RemainingProviderCreateGates())

	status, ok := server.ProviderCreateGateStatusRead(testProviderCreateGate)
	require.True(t, ok)
	require.Equal(t, regionv1.ServerProviderCreateGateClosed, status.State)
	require.Equal(t, "region", status.Actor)
	require.Equal(t, "Reset", status.Reason)
	require.Equal(t, "provider create will retry", status.Message)
	closedTransitionTime := status.LastTransitionTime

	server.ProviderCreateGateStatusWrite(testProviderCreateGate, regionv1.ServerProviderCreateGateOpen, "service", "Prepared", "external state is ready")
	require.True(t, server.ProviderCreateGatesReady())
	require.Empty(t, server.RemainingProviderCreateGates())

	status, ok = server.ProviderCreateGateStatusRead(testProviderCreateGate)
	require.True(t, ok)
	require.Equal(t, regionv1.ServerProviderCreateGateOpen, status.State)
	require.Equal(t, "service", status.Actor)
	require.Equal(t, "Prepared", status.Reason)
	require.Equal(t, "external state is ready", status.Message)
	require.True(t, status.LastTransitionTime.After(closedTransitionTime.Time) || status.LastTransitionTime.Equal(&closedTransitionTime))
	openTransitionTime := status.LastTransitionTime

	server.ProviderCreateGateStatusWrite(testProviderCreateGate, regionv1.ServerProviderCreateGateOpen, "other-service", "StillPrepared", "still ready")

	status, ok = server.ProviderCreateGateStatusRead(testProviderCreateGate)
	require.True(t, ok)
	require.Equal(t, regionv1.ServerProviderCreateGateOpen, status.State)
	require.Equal(t, "other-service", status.Actor)
	require.Equal(t, "StillPrepared", status.Reason)
	require.Equal(t, "still ready", status.Message)
	require.True(t, status.LastTransitionTime.Equal(&openTransitionTime))
}

func TestServerProviderCreateGatesReset(t *testing.T) {
	t.Parallel()

	server := &regionv1.Server{
		Spec: regionv1.ServerSpec{
			ProviderCreateGates: []regionv1.ServerProviderCreateGate{
				{ConditionType: testProviderCreateGate},
				{ConditionType: "example.unikorn-cloud.org/second-ready"},
			},
		},
	}

	server.ProviderCreateGateStatusWrite(testProviderCreateGate, regionv1.ServerProviderCreateGateOpen, "service", "Prepared", "")
	server.ProviderCreateGateStatusWrite("example.unikorn-cloud.org/second-ready", regionv1.ServerProviderCreateGateOpen, "service", "Prepared", "")
	require.True(t, server.ProviderCreateGatesReady())

	server.ProviderCreateGatesReset("region", "ProviderCreateRetry", "provider create will retry")

	require.ElementsMatch(t, []string{
		testProviderCreateGate,
		"example.unikorn-cloud.org/second-ready",
	}, server.RemainingProviderCreateGates())

	for _, gate := range server.Status.ProviderCreateGates {
		require.Equal(t, regionv1.ServerProviderCreateGateClosed, gate.State)
		require.Equal(t, "region", gate.Actor)
		require.Equal(t, "ProviderCreateRetry", gate.Reason)
		require.Equal(t, "provider create will retry", gate.Message)
	}
}
