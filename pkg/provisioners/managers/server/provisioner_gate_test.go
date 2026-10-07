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
	"github.com/unikorn-cloud/core/pkg/provisioners"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	serverprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/server"

	corev1 "k8s.io/api/core/v1"
)

// networkWithAvailable returns a named Network carrying the given Available
// condition, or no condition at all when reason is empty.
func networkWithAvailable(reason unikornv1core.ProvisioningConditionReason, status corev1.ConditionStatus) *regionv1.Network {
	network := &regionv1.Network{}
	network.Name = "dep-1"

	if reason != "" {
		network.SetProvisioningCondition(status, reason, "")
	}

	return network
}

// TestClassifyDependency pins how the dependency gate maps a dependency's
// Available condition onto a provisioning disposition: provisioned is ready,
// errored yields DependencyFailed, everything else (including an absent
// condition) yields DependencyNotReady. All non-ready cases yield rather than
// park — the dependency may still recover.
func TestClassifyDependency(t *testing.T) {
	t.Parallel()

	cli := retryClient(t)

	testCases := map[string]struct {
		network    *regionv1.Network
		wantErr    bool
		wantReason unikornv1core.ProvisioningConditionReason
	}{
		"provisioned is ready": {
			network: networkWithAvailable(unikornv1core.ConditionReasonProvisioned, corev1.ConditionTrue),
			wantErr: false,
		},
		"errored yields DependencyFailed": {
			network:    networkWithAvailable(unikornv1core.ConditionReasonErrored, corev1.ConditionFalse),
			wantErr:    true,
			wantReason: unikornv1core.ConditionReasonDependencyFailed,
		},
		"provisioning yields DependencyNotReady": {
			network:    networkWithAvailable(unikornv1core.ConditionReasonProvisioning, corev1.ConditionFalse),
			wantErr:    true,
			wantReason: unikornv1core.ConditionReasonDependencyNotReady,
		},
		"absent condition yields DependencyNotReady": {
			network:    networkWithAvailable("", corev1.ConditionFalse),
			wantErr:    true,
			wantReason: unikornv1core.ConditionReasonDependencyNotReady,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := serverprovisioner.ClassifyDependencyForTest(cli, tc.network)

			if !tc.wantErr {
				require.NoError(t, err)

				return
			}

			var perr *provisioners.Error

			require.ErrorAs(t, err, &perr)
			require.Equal(t, tc.wantReason, perr.Reason())
			require.False(t, provisioners.IsTerminal(err), "a dependency wait yields, it must not park")
		})
	}
}

// TestBlockUntilResourceReadyNotFound pins that a referenced dependency that does
// not exist is TERMINAL (DependencyNotFound): a finalized-but-gone reference is a
// consistency violation, not a transient wait, so it parks rather than yields.
func TestBlockUntilResourceReadyNotFound(t *testing.T) {
	t.Parallel()

	cli := retryClient(t)

	server := &regionv1.Server{}
	server.Namespace = "default"

	err := serverprovisioner.BlockUntilResourceReadyForTest(t.Context(), server, cli, "ghost-network", &regionv1.Network{})

	var perr *provisioners.Error

	require.ErrorAs(t, err, &perr)
	require.Equal(t, unikornv1core.ConditionReasonDependencyNotFound, perr.Reason())
	require.True(t, provisioners.IsTerminal(err), "a missing referenced dependency is terminal")
}

// TestBlockUntilDependenciesReadyGateYieldIsTyped pins the provider-create-gate
// wait as a typed yield carrying the gate names.
//
// WHY: the gate is satisfied by a separate service, so a server can legitimately
// wait here for a long time, and a bare sentinel would make that wait
// indistinguishable from every other one in this function. The message is asserted
// as well as the reason, because the outstanding gate name is the diagnostic
// value.
func TestBlockUntilDependenciesReadyGateYieldIsTyped(t *testing.T) {
	t.Parallel()

	cli := retryClient(t)

	identity := &regionv1.Identity{}
	identity.Name = "identity-1"
	identity.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "")

	newServer := func(gateStatus corev1.ConditionStatus, write bool) *regionv1.Server {
		server := &regionv1.Server{}
		server.Name = "server-1"
		server.Spec.ProviderCreateGates = []regionv1.ServerProviderCreateGate{
			{ConditionType: "fabric.unikorn-cloud.org/partition-ready"},
		}

		if write {
			server.ProviderCreateGateStatusWrite("fabric.unikorn-cloud.org/partition-ready",
				gateStatus, "actor", "Reason", "message")
		}

		return server
	}

	t.Run("UnwrittenGateYieldsTypedAndNamesTheGate", func(t *testing.T) {
		t.Parallel()

		err := serverprovisioner.BlockUntilDependenciesReadyForTest(t.Context(), newServer("", false), cli, identity)
		require.Error(t, err)

		var perr *provisioners.Error

		require.ErrorAs(t, err, &perr, "the gate wait must be a typed provisioners.Error, not a bare wrapped ErrYield")
		require.Equal(t, unikornv1core.ConditionReasonDependencyNotReady, perr.Reason())
		require.Contains(t, perr.Message(), "fabric.unikorn-cloud.org/partition-ready",
			"the message must name the outstanding gate")
		require.False(t, provisioners.IsTerminal(err), "an unsatisfied gate yields, it must not park")
	})

	t.Run("FalseGateYieldsTypedAndNamesTheGate", func(t *testing.T) {
		t.Parallel()

		err := serverprovisioner.BlockUntilDependenciesReadyForTest(t.Context(), newServer(corev1.ConditionFalse, true), cli, identity)
		require.Error(t, err)

		var perr *provisioners.Error

		require.ErrorAs(t, err, &perr)
		require.Equal(t, unikornv1core.ConditionReasonDependencyNotReady, perr.Reason())
		require.Contains(t, perr.Message(), "fabric.unikorn-cloud.org/partition-ready")
	})

	t.Run("SatisfiedGatePasses", func(t *testing.T) {
		t.Parallel()

		err := serverprovisioner.BlockUntilDependenciesReadyForTest(t.Context(), newServer(corev1.ConditionTrue, true), cli, identity)
		require.NoError(t, err, "a satisfied gate must not block the create path")
	})
}
