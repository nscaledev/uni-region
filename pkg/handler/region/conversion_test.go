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

package region_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/region"
	"github.com/unikorn-cloud/region/pkg/openapi"

	"k8s.io/utils/ptr"
)

// TestConvertRegionType verifies the provider → API type mapping for all known
// values and the empty-string fallback for unknown input.
func TestConvertRegionType(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input unikornv1.Provider
		want  openapi.RegionType
	}{
		{
			name:  "Kubernetes",
			input: unikornv1.ProviderKubernetes,
			want:  openapi.RegionTypeKubernetes,
		},
		{
			name:  "Openstack",
			input: unikornv1.ProviderOpenstack,
			want:  openapi.RegionTypeOpenstack,
		},
		{
			name:  "Simulated",
			input: unikornv1.ProviderSimulated,
			want:  openapi.RegionTypeSimulated,
		},
		{
			name:  "unknown provider returns empty string",
			input: "future-provider",
			want:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.want, region.ConvertRegionType(tc.input))
		})
	}
}

// TestConvertPhysicalNetworksFeatureFlag verifies that PhysicalNetworks is true
// only when the region uses Openstack and has ProviderNetworks configured.
func TestConvertPhysicalNetworksFeatureFlag(t *testing.T) {
	t.Parallel()

	t.Run("Openstack with ProviderNetworks sets PhysicalNetworks true", func(t *testing.T) {
		t.Parallel()

		in := &unikornv1.Region{
			Spec: unikornv1.RegionSpec{
				Provider: unikornv1.ProviderOpenstack,
				Openstack: &unikornv1.RegionOpenstackSpec{
					Network: &unikornv1.RegionOpenstackNetworkSpec{
						ProviderNetworks: &unikornv1.ProviderNetworks{
							Network: ptr.To("physnet1"),
						},
					},
				},
			},
		}

		out := region.Convert(in)
		require.True(t, out.Spec.Features.PhysicalNetworks)
	})

	t.Run("Openstack without ProviderNetworks leaves PhysicalNetworks false", func(t *testing.T) {
		t.Parallel()

		in := &unikornv1.Region{
			Spec: unikornv1.RegionSpec{
				Provider: unikornv1.ProviderOpenstack,
				Openstack: &unikornv1.RegionOpenstackSpec{
					Network: &unikornv1.RegionOpenstackNetworkSpec{
						ProviderNetworks: nil,
					},
				},
			},
		}

		out := region.Convert(in)
		require.False(t, out.Spec.Features.PhysicalNetworks)
	})

	t.Run("Openstack without Network spec leaves PhysicalNetworks false", func(t *testing.T) {
		t.Parallel()

		in := &unikornv1.Region{
			Spec: unikornv1.RegionSpec{
				Provider: unikornv1.ProviderOpenstack,
				Openstack: &unikornv1.RegionOpenstackSpec{
					Network: nil,
				},
			},
		}

		out := region.Convert(in)
		require.False(t, out.Spec.Features.PhysicalNetworks)
	})

	t.Run("Openstack with nil Openstack spec leaves PhysicalNetworks false", func(t *testing.T) {
		t.Parallel()

		in := &unikornv1.Region{
			Spec: unikornv1.RegionSpec{
				Provider:  unikornv1.ProviderOpenstack,
				Openstack: nil,
			},
		}

		out := region.Convert(in)
		require.False(t, out.Spec.Features.PhysicalNetworks)
	})

	t.Run("Kubernetes provider leaves PhysicalNetworks false", func(t *testing.T) {
		t.Parallel()

		in := &unikornv1.Region{
			Spec: unikornv1.RegionSpec{
				Provider: unikornv1.ProviderKubernetes,
			},
		}

		out := region.Convert(in)
		require.False(t, out.Spec.Features.PhysicalNetworks)
	})

	t.Run("Simulated provider leaves PhysicalNetworks false", func(t *testing.T) {
		t.Parallel()

		in := &unikornv1.Region{
			Spec: unikornv1.RegionSpec{
				Provider: unikornv1.ProviderSimulated,
			},
		}

		out := region.Convert(in)
		require.False(t, out.Spec.Features.PhysicalNetworks)
	})

	t.Run("region type is correctly set on output", func(t *testing.T) {
		t.Parallel()

		in := &unikornv1.Region{
			Spec: unikornv1.RegionSpec{
				Provider:  unikornv1.ProviderOpenstack,
				Openstack: &unikornv1.RegionOpenstackSpec{},
			},
		}

		out := region.Convert(in)
		require.Equal(t, openapi.RegionTypeOpenstack, out.Spec.Type)
	})
}
