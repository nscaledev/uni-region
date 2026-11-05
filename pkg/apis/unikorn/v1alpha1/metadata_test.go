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

func TestMetadataKey(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		input    string
		expected string
		ok       bool
	}{
		{
			name:     "ValidSimple",
			input:    "compute.unikorn-cloud.org/instance-id",
			expected: "compute:instance_id",
			ok:       true,
		},
		{
			name:     "ValidOtherService",
			input:    "kubernetes.unikorn-cloud.org/cluster-id",
			expected: "kubernetes:cluster_id",
			ok:       true,
		},
		{
			name:     "ValidHyphenInSubdomain",
			input:    "my-service.unikorn-cloud.org/foo-bar",
			expected: "my-service:foo_bar",
			ok:       true,
		},
		{
			name:  "InvalidNoSlash",
			input: "compute.unikorn-cloud.org",
			ok:    false,
		},
		{
			name:  "InvalidUppercase",
			input: "Compute.unikorn-cloud.org/id",
			ok:    false,
		},
		{
			name:  "InvalidBareName",
			input: "instance-id",
			ok:    false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			got, ok := regionv1.MetadataKey(c.input)
			require.Equal(t, c.ok, ok)

			if c.ok {
				require.Equal(t, c.expected, got)
			}
		})
	}
}

// A gate output is named as a tag would be under the gate's own
// "<service>.<domain>/": "pkey" on "fabric.unikorn-cloud.org/partition-ready"
// is "fabric:pkey". A gate without that prefix, or a key that is not a tag's
// local name, has no metadata key.
func TestProviderCreateGateOutputKey(t *testing.T) {
	t.Parallel()

	key, ok := regionv1.ProviderCreateGateOutputKey("fabric.unikorn-cloud.org/partition-ready", "pkey")
	require.True(t, ok)
	require.Equal(t, "fabric:pkey", key)

	key, ok = regionv1.ProviderCreateGateOutputKey("fabric.unikorn-cloud.org/partition-ready", "a-b")
	require.True(t, ok)
	require.Equal(t, "fabric:a_b", key)

	for _, c := range []struct{ conditionType, key string }{
		{"partition-ready", "pkey"},
		{"test/gate", "pkey"},
		{"Fabric.unikorn-cloud.org/partition-ready", "pkey"},
		{"fabric.unikorn-cloud.org/partition-ready", "P_Key"},
		{"fabric.unikorn-cloud.org/partition-ready", ""},
		{"fabric.unikorn-cloud.org/partition-ready", "fabric:pkey"},
	} {
		_, ok := regionv1.ProviderCreateGateOutputKey(c.conditionType, c.key)
		require.False(t, ok, c)
	}
}

// Only satisfied gates publish. Gates are taken in spec order, and a later
// gate's key replaces an earlier one's, as a later tag's does. An output that
// maps to no metadata key (the API refuses one, so it can only come from a
// status written another way) is returned rather than dropped silently.
func TestServerProviderCreateGateOutputMetadata(t *testing.T) {
	t.Parallel()

	server := &regionv1.Server{
		Spec: regionv1.ServerSpec{
			ProviderCreateGates: []regionv1.ServerProviderCreateGate{
				{ConditionType: "fabric.unikorn-cloud.org/a-ready"},
				{ConditionType: "storage.unikorn-cloud.org/pending"},
				{ConditionType: "nodomain"},
				{ConditionType: "fabric.unikorn-cloud.org/b-ready"},
			},
		},
	}

	server.ProviderCreateGateStatusWrite("fabric.unikorn-cloud.org/b-ready", corev1.ConditionTrue, "b", "Ready", "ready", map[string]string{"pkey": "0x0b00"})
	server.ProviderCreateGateStatusWrite("fabric.unikorn-cloud.org/a-ready", corev1.ConditionTrue, "a", "Ready", "ready", map[string]string{"pkey": "0x0a00", "pkeys": "0x0a00"})
	server.ProviderCreateGateStatusWrite("storage.unikorn-cloud.org/pending", corev1.ConditionUnknown, "s", "Waiting", "waiting", map[string]string{"volume": "v"})
	server.ProviderCreateGateStatusWrite("nodomain", corev1.ConditionTrue, "n", "Ready", "ready", map[string]string{"x": "y"})

	metadata, unmapped := server.ProviderCreateGateOutputMetadata()

	require.Equal(t, map[string]string{"fabric:pkey": "0x0b00", "fabric:pkeys": "0x0a00"}, metadata)
	require.Equal(t, []string{"nodomain: x"}, unmapped)
}
