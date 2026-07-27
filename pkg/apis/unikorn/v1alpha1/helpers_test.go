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

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func TestEffectiveReservations(t *testing.T) {
	t.Parallel()

	t.Run("UsesDefaultWhenReservationsOmitted", func(t *testing.T) {
		t.Parallel()

		network := &regionv1.Network{}
		require.NotNil(t, network.EffectiveReservations())
		require.Equal(t, constants.DefaultNetworkReservationPrefixLength, network.EffectiveReservations().PrefixLength)
		require.Equal(t, ptr.To(constants.DefaultNetworkProviderReservedPrefixLength), network.EffectiveReservations().ProviderReservedPrefixLength)
	})

	t.Run("PrefersExplicitReservations", func(t *testing.T) {
		t.Parallel()

		network := &regionv1.Network{
			Spec: regionv1.NetworkSpec{
				Reservations: &regionv1.NetworkReservations{
					PrefixLength:                 25,
					ProviderReservedPrefixLength: ptr.To(28),
				},
			},
		}

		require.Equal(t, 25, network.EffectiveReservations().PrefixLength)
		require.Equal(t, ptr.To(28), network.EffectiveReservations().ProviderReservedPrefixLength)
	})
}

func TestUseProviderNetworks(t *testing.T) {
	t.Parallel()

	t.Run("FalseWhenReceiverNil", func(t *testing.T) {
		t.Parallel()

		var spec *regionv1.RegionOpenstackNetworkSpec

		require.False(t, spec.UseProviderNetworks())
	})

	t.Run("FalseWhenProviderNetworksNil", func(t *testing.T) {
		t.Parallel()

		spec := &regionv1.RegionOpenstackNetworkSpec{}
		require.False(t, spec.UseProviderNetworks())
	})

	t.Run("FalseWhenInnerNetworkNil", func(t *testing.T) {
		t.Parallel()

		spec := &regionv1.RegionOpenstackNetworkSpec{
			ProviderNetworks: &regionv1.ProviderNetworks{},
		}
		require.False(t, spec.UseProviderNetworks())
	})

	t.Run("TrueWhenAllFieldsSet", func(t *testing.T) {
		t.Parallel()

		spec := &regionv1.RegionOpenstackNetworkSpec{
			ProviderNetworks: &regionv1.ProviderNetworks{
				Network: ptr.To("physnet1"),
			},
		}
		require.True(t, spec.UseProviderNetworks())
	})
}

func TestStaticName(t *testing.T) {
	t.Parallel()

	t.Run("OpenstackProvider", func(t *testing.T) {
		t.Parallel()

		region := &regionv1.Region{
			ObjectMeta: metav1.ObjectMeta{Name: "region-a"},
			Spec:       regionv1.RegionSpec{Provider: regionv1.ProviderOpenstack},
		}
		require.Equal(t, "openstack.region-a", region.StaticName())
	})

	t.Run("KubernetesProvider", func(t *testing.T) {
		t.Parallel()

		region := &regionv1.Region{
			ObjectMeta: metav1.ObjectMeta{Name: "region-a"},
			Spec:       regionv1.RegionSpec{Provider: regionv1.ProviderKubernetes},
		}
		require.Equal(t, "kubernetes.region-a", region.StaticName())
	})

	t.Run("SimulatedProvider", func(t *testing.T) {
		t.Parallel()

		region := &regionv1.Region{
			ObjectMeta: metav1.ObjectMeta{Name: "region-a"},
			Spec:       regionv1.RegionSpec{Provider: regionv1.ProviderSimulated},
		}
		require.Equal(t, "simulated.region-a", region.StaticName())
	})
}

func TestVLANSpec(t *testing.T) {
	t.Parallel()

	t.Run("NilForKubernetesProvider", func(t *testing.T) {
		t.Parallel()

		region := &regionv1.Region{Spec: regionv1.RegionSpec{Provider: regionv1.ProviderKubernetes}}
		require.Nil(t, region.VLANSpec())
	})

	t.Run("NilForSimulatedProvider", func(t *testing.T) {
		t.Parallel()

		region := &regionv1.Region{Spec: regionv1.RegionSpec{Provider: regionv1.ProviderSimulated}}
		require.Nil(t, region.VLANSpec())
	})

	t.Run("NilWhenOpenstackConfigAbsent", func(t *testing.T) {
		t.Parallel()

		region := &regionv1.Region{Spec: regionv1.RegionSpec{Provider: regionv1.ProviderOpenstack}}
		require.Nil(t, region.VLANSpec())
	})

	t.Run("NilWhenNetworkAbsent", func(t *testing.T) {
		t.Parallel()

		region := &regionv1.Region{
			Spec: regionv1.RegionSpec{
				Provider:  regionv1.ProviderOpenstack,
				Openstack: &regionv1.RegionOpenstackSpec{},
			},
		}
		require.Nil(t, region.VLANSpec())
	})

	t.Run("NilWhenProviderNetworksAbsent", func(t *testing.T) {
		t.Parallel()

		region := &regionv1.Region{
			Spec: regionv1.RegionSpec{
				Provider: regionv1.ProviderOpenstack,
				Openstack: &regionv1.RegionOpenstackSpec{
					Network: &regionv1.RegionOpenstackNetworkSpec{},
				},
			},
		}
		require.Nil(t, region.VLANSpec())
	})

	t.Run("NilWhenVLANAbsent", func(t *testing.T) {
		t.Parallel()

		region := &regionv1.Region{
			Spec: regionv1.RegionSpec{
				Provider: regionv1.ProviderOpenstack,
				Openstack: &regionv1.RegionOpenstackSpec{
					Network: &regionv1.RegionOpenstackNetworkSpec{
						ProviderNetworks: &regionv1.ProviderNetworks{},
					},
				},
			},
		}
		require.Nil(t, region.VLANSpec())
	})

	t.Run("ReturnsSpecWhenVLANConfigured", func(t *testing.T) {
		t.Parallel()

		vlan := &regionv1.VLANSpec{
			Segments: []regionv1.VLANSegment{
				{StartID: 1, EndID: 4094},
			},
		}

		region := &regionv1.Region{
			Spec: regionv1.RegionSpec{
				Provider: regionv1.ProviderOpenstack,
				Openstack: &regionv1.RegionOpenstackSpec{
					Network: &regionv1.RegionOpenstackNetworkSpec{
						ProviderNetworks: &regionv1.ProviderNetworks{
							VLAN: vlan,
						},
					},
				},
			},
		}

		got := region.VLANSpec()
		require.NotNil(t, got)
		require.Equal(t, vlan, got)
	})
}

func testStampServer(generation int64) *regionv1.Server {
	s := &regionv1.Server{}
	s.Generation = generation

	return s
}

func activeCondition(t *testing.T, s *regionv1.Server) *metav1.Condition {
	t.Helper()

	cond := meta.FindStatusCondition(s.Status.Conditions, string(unikornv1core.ConditionActive))
	require.NotNil(t, cond)

	return cond
}

// The reconciler's Available writes carry the generation of the pass on every
// reason — Provisioning (yield), Errored, and Provisioned alike.
func TestServerAvailableConditionStampsGeneration(t *testing.T) {
	t.Parallel()

	for _, reason := range []unikornv1core.ProvisioningConditionReason{
		unikornv1core.ConditionReasonProvisioning,
		unikornv1core.ConditionReasonErrored,
		unikornv1core.ConditionReasonProvisioned,
	} {
		s := testStampServer(7)
		s.SetProvisioningCondition(corev1.ConditionTrue, reason, "")

		cond := meta.FindStatusCondition(s.Status.Conditions, string(unikornv1core.ConditionAvailable))
		require.NotNil(t, cond)
		require.Equal(t, int64(7), cond.ObservedGeneration, "reason %s must stamp the pass generation", reason)
	}
}

// Every non-advance Active write — handler stop/start seeds, the reconciler's
// markServerRebuildAccepted and create-retry reset, monitor reason rewrites —
// preserves the stored stamp: the latch never regresses through the choke
// point.
func TestServerActiveConditionCarriesStampForward(t *testing.T) {
	t.Parallel()

	s := testStampServer(3)

	// Seed (carry-forward of nothing) leaves the stamp unset.
	s.SetActiveCondition(regionv1.ActiveConditionReasonPending)
	require.Equal(t, int64(0), activeCondition(t, s).ObservedGeneration)

	// The monitor's advance raises it to the current generation.
	s.AdvanceActiveGeneration()
	require.Equal(t, int64(3), activeCondition(t, s).ObservedGeneration)

	// Every subsequent write shape carries it: handler stop, monitor rewrite,
	// rebuild-accepted, create-retry reset.
	for _, reason := range []regionv1.ActiveConditionReason{
		regionv1.ActiveConditionReasonStopping,
		regionv1.ActiveConditionReasonStopped,
		regionv1.ActiveConditionReasonRebuilding,
		regionv1.ActiveConditionReasonPending,
	} {
		s.SetActiveCondition(reason)
		require.Equal(t, int64(3), activeCondition(t, s).ObservedGeneration, "write of %s must carry the latch forward", reason)
	}
}

// The advance is forward-only: it raises to the current generation, never
// lowers, and is a no-op when the condition is absent.
func TestServerAdvanceActiveGenerationForwardOnly(t *testing.T) {
	t.Parallel()

	s := testStampServer(5)

	// Absent condition: no-op, no panic, nothing created.
	s.AdvanceActiveGeneration()
	require.Nil(t, meta.FindStatusCondition(s.Status.Conditions, string(unikornv1core.ConditionActive)))

	s.SetActiveCondition(regionv1.ActiveConditionReasonRunning)
	s.AdvanceActiveGeneration()
	require.Equal(t, int64(5), activeCondition(t, s).ObservedGeneration)

	// A stale-snapshot advance (lower generation) can never lower the stamp.
	s.Generation = 4
	s.AdvanceActiveGeneration()
	require.Equal(t, int64(5), activeCondition(t, s).ObservedGeneration)
}
