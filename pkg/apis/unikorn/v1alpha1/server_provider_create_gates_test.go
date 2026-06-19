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

	corev1 "k8s.io/api/core/v1"
)

const testProviderCreateGate = "example.unikorn-cloud.org/pre-create-ready"

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

	server.ProviderCreateGateStatusWrite(testProviderCreateGate, corev1.ConditionUnknown, "region", "Reset", "provider create will retry")
	require.False(t, server.ProviderCreateGatesReady())
	require.Equal(t, []string{testProviderCreateGate}, server.RemainingProviderCreateGates())

	status, ok := server.ProviderCreateGateStatusRead(testProviderCreateGate)
	require.True(t, ok)
	require.Equal(t, corev1.ConditionUnknown, status.Status)
	require.Equal(t, "region", status.Actor)
	require.Equal(t, "Reset", status.Reason)
	require.Equal(t, "provider create will retry", status.Message)
	unknownTransitionTime := status.LastTransitionTime

	server.ProviderCreateGateStatusWrite(testProviderCreateGate, corev1.ConditionTrue, "service", "Prepared", "external state is ready")
	require.True(t, server.ProviderCreateGatesReady())
	require.Empty(t, server.RemainingProviderCreateGates())

	status, ok = server.ProviderCreateGateStatusRead(testProviderCreateGate)
	require.True(t, ok)
	require.Equal(t, corev1.ConditionTrue, status.Status)
	require.Equal(t, "service", status.Actor)
	require.Equal(t, "Prepared", status.Reason)
	require.Equal(t, "external state is ready", status.Message)
	require.True(t, status.LastTransitionTime.After(unknownTransitionTime.Time) || status.LastTransitionTime.Equal(&unknownTransitionTime))
	trueTransitionTime := status.LastTransitionTime

	server.ProviderCreateGateStatusWrite(testProviderCreateGate, corev1.ConditionTrue, "other-service", "StillPrepared", "still ready")

	status, ok = server.ProviderCreateGateStatusRead(testProviderCreateGate)
	require.True(t, ok)
	require.Equal(t, corev1.ConditionTrue, status.Status)
	require.Equal(t, "other-service", status.Actor)
	require.Equal(t, "StillPrepared", status.Reason)
	require.Equal(t, "still ready", status.Message)
	require.True(t, status.LastTransitionTime.Equal(&trueTransitionTime))
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

	server.ProviderCreateGateStatusWrite(testProviderCreateGate, corev1.ConditionTrue, "service", "Prepared", "")
	server.ProviderCreateGateStatusWrite("example.unikorn-cloud.org/second-ready", corev1.ConditionTrue, "service", "Prepared", "")
	require.True(t, server.ProviderCreateGatesReady())

	server.ProviderCreateGatesReset("region", "ProviderCreateRetry", "provider create will retry")

	require.ElementsMatch(t, []string{
		testProviderCreateGate,
		"example.unikorn-cloud.org/second-ready",
	}, server.RemainingProviderCreateGates())

	for _, gate := range server.Status.ProviderCreateGates {
		require.Equal(t, corev1.ConditionUnknown, gate.Status)
		require.Equal(t, "region", gate.Actor)
		require.Equal(t, "ProviderCreateRetry", gate.Reason)
		require.Equal(t, "provider create will retry", gate.Message)
	}
}
