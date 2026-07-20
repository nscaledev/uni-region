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

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/server"
	"github.com/unikorn-cloud/region/pkg/openapi"

	"k8s.io/utils/ptr"
)

// TestServerPowerState verifies the server's Active condition (its lifecycle/power
// axis) projects onto the correct API enum value, and that an absent condition or
// an unknown reason returns nil (the field is omitted rather than bogus).
func TestServerPowerState(t *testing.T) {
	t.Parallel()

	serverWithReason := func(reason unikornv1.ActiveConditionReason) *unikornv1.Server {
		s := &unikornv1.Server{}
		s.SetActiveCondition(reason)

		return s
	}

	cases := []struct {
		name  string
		input *unikornv1.Server
		want  *openapi.InstanceLifecyclePhase
	}{
		{
			name:  "Pending",
			input: serverWithReason(unikornv1.ActiveConditionReasonPending),
			want:  ptr.To(openapi.InstanceLifecyclePhasePending),
		},
		{
			name:  "Running",
			input: serverWithReason(unikornv1.ActiveConditionReasonRunning),
			want:  ptr.To(openapi.InstanceLifecyclePhaseRunning),
		},
		{
			name:  "Stopping",
			input: serverWithReason(unikornv1.ActiveConditionReasonStopping),
			want:  ptr.To(openapi.InstanceLifecyclePhaseStopping),
		},
		{
			name:  "Stopped",
			input: serverWithReason(unikornv1.ActiveConditionReasonStopped),
			want:  ptr.To(openapi.InstanceLifecyclePhaseStopped),
		},
		{
			name:  "absent condition returns nil",
			input: &unikornv1.Server{},
			want:  nil,
		},
		{
			name:  "unknown reason returns nil",
			input: serverWithReason("some-future-state"),
			want:  nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := server.ServerPowerState(tc.input)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestConvertPublicIPAllocation verifies nil input returns nil and a populated
// input carries the Enabled flag through.
func TestConvertPublicIPAllocation(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		t.Parallel()

		require.Nil(t, server.ConvertPublicIPAllocation(nil))
	})

	t.Run("enabled true is preserved", func(t *testing.T) {
		t.Parallel()

		in := &unikornv1.ServerPublicIPAllocationSpec{Enabled: true}
		out := server.ConvertPublicIPAllocation(in)
		require.NotNil(t, out)
		require.True(t, out.Enabled)
	})

	t.Run("enabled false is preserved", func(t *testing.T) {
		t.Parallel()

		in := &unikornv1.ServerPublicIPAllocationSpec{Enabled: false}
		out := server.ConvertPublicIPAllocation(in)
		require.NotNil(t, out)
		require.False(t, out.Enabled)
	})
}

// TestGenerateAllowedAddressPairs locks the behavioral contract for CIDR parsing:
// valid CIDRs are included (canonicalized), invalid ones are silently dropped, and
// nil input always yields an empty (non-nil) slice.
func TestGenerateAllowedAddressPairs(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns empty slice", func(t *testing.T) {
		t.Parallel()

		out := server.GenerateAllowedAddressPairs(nil)
		require.NotNil(t, out)
		require.Empty(t, out)
	})

	t.Run("empty list returns empty slice", func(t *testing.T) {
		t.Parallel()

		in := openapi.ServerNetworkAllowedAddressPairList{}
		out := server.GenerateAllowedAddressPairs(&in)
		require.Empty(t, out)
	})

	t.Run("valid CIDR is included", func(t *testing.T) {
		t.Parallel()

		in := openapi.ServerNetworkAllowedAddressPairList{
			{Cidr: "192.168.1.0/24"},
		}

		out := server.GenerateAllowedAddressPairs(&in)
		require.Len(t, out, 1)
		require.Equal(t, "192.168.1.0/24", out[0].CIDR.String())
	})

	t.Run("invalid CIDR is silently dropped without error", func(t *testing.T) {
		t.Parallel()

		in := openapi.ServerNetworkAllowedAddressPairList{
			{Cidr: "not-a-cidr"},
			{Cidr: "192.168.1.0/24"},
		}

		out := server.GenerateAllowedAddressPairs(&in)
		require.Len(t, out, 1, "only the valid CIDR should survive")
		require.Equal(t, "192.168.1.0/24", out[0].CIDR.String())
	})

	t.Run("all invalid CIDRs returns empty slice", func(t *testing.T) {
		t.Parallel()

		in := openapi.ServerNetworkAllowedAddressPairList{
			{Cidr: "bad"},
			{Cidr: "256.0.0.1/24"},
		}

		out := server.GenerateAllowedAddressPairs(&in)
		require.Empty(t, out)
	})

	t.Run("MAC address is captured when present", func(t *testing.T) {
		t.Parallel()

		mac := "fa:16:3e:ab:cd:ef"
		in := openapi.ServerNetworkAllowedAddressPairList{
			{Cidr: "10.0.0.0/8", MacAddress: ptr.To(mac)},
		}

		out := server.GenerateAllowedAddressPairs(&in)
		require.Len(t, out, 1)
		require.Equal(t, mac, out[0].MACAddress)
	})

	t.Run("absent MAC address leaves field empty", func(t *testing.T) {
		t.Parallel()

		in := openapi.ServerNetworkAllowedAddressPairList{
			{Cidr: "10.0.0.0/8"},
		}

		out := server.GenerateAllowedAddressPairs(&in)
		require.Len(t, out, 1)
		require.Empty(t, out[0].MACAddress)
	})

	t.Run("host bits are masked to network address", func(t *testing.T) {
		t.Parallel()

		// net.ParseCIDR masks host bits; 192.168.1.50/24 → 192.168.1.0/24.
		in := openapi.ServerNetworkAllowedAddressPairList{
			{Cidr: "192.168.1.50/24"},
		}

		out := server.GenerateAllowedAddressPairs(&in)
		require.Len(t, out, 1)
		require.Equal(t, "192.168.1.0/24", out[0].CIDR.String())
	})
}
