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

package openstack_test

import (
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/flavors"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"

	"k8s.io/utils/ptr"
)

// TestConvertFlavorsAppliesInfiniBandMetadata covers the operator-config half of
// the InfiniBand feature: Region.Spec.Openstack.Compute.Flavors.Metadata[].infiniBand
// overlaying onto the converted types.Flavor. The conversion-layer test covers the
// downstream types.Flavor -> openapi.Flavor mapping; this pins the upstream path.
func TestConvertFlavorsAppliesInfiniBandMetadata(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name              string
		metadata          []unikornv1.FlavorMetadata
		expectedPortCount *int
	}{
		{
			name:              "no metadata leaves InfiniBand unset",
			expectedPortCount: nil,
		},
		{
			name: "metadata for a different flavor is ignored",
			metadata: []unikornv1.FlavorMetadata{
				{
					ID:         "other-flavor",
					InfiniBand: &unikornv1.InfiniBandSpec{PortCount: 8},
				},
			},
			expectedPortCount: nil,
		},
		{
			name: "matching metadata populates the port count",
			metadata: []unikornv1.FlavorMetadata{
				{
					ID:         "flavor-id",
					InfiniBand: &unikornv1.InfiniBandSpec{PortCount: 8},
				},
			},
			expectedPortCount: ptr.To(8),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			region := &unikornv1.Region{
				Spec: unikornv1.RegionSpec{
					Openstack: &unikornv1.RegionOpenstackSpec{},
				},
			}

			if tc.metadata != nil {
				region.Spec.Openstack.Compute = &unikornv1.RegionOpenstackComputeSpec{
					Flavors: &unikornv1.OpenstackFlavorsSpec{
						Metadata: tc.metadata,
					},
				}
			}

			converted := openstack.ConvertFlavors([]flavors.Flavor{{
				ID:    "flavor-id",
				Name:  "flavor-name",
				VCPUs: 16,
				RAM:   1024,
				Disk:  10,
			}}, region)

			require.Len(t, converted, 1)

			if tc.expectedPortCount == nil {
				require.Nil(t, converted[0].InfiniBand)

				return
			}

			require.NotNil(t, converted[0].InfiniBand)
			require.Equal(t, *tc.expectedPortCount, converted[0].InfiniBand.PortCount)
		})
	}
}
