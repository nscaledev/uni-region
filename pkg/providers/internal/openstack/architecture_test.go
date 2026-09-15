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
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/utils/ptr"
)

func TestOpenstackArchitectureFallbacks(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name                string
		defaultArchitecture *unikornv1.Architecture
		flavorArchitecture  *unikornv1.Architecture
		imageArchitecture   any
		expectedFlavor      types.Architecture
		expectedImage       types.Architecture
	}{
		{
			name:           "omitted configuration preserves the legacy fallback",
			expectedFlavor: types.X86_64,
			expectedImage:  types.X86_64,
		},
		{
			name:                "regional aarch64 applies to missing metadata",
			defaultArchitecture: ptr.To(unikornv1.Aarch64),
			expectedFlavor:      types.Aarch64,
			expectedImage:       types.Aarch64,
		},
		{
			name:                "per-flavor metadata overrides the regional default",
			defaultArchitecture: ptr.To(unikornv1.Aarch64),
			flavorArchitecture:  ptr.To(unikornv1.X86_64),
			expectedFlavor:      types.X86_64,
			expectedImage:       types.Aarch64,
		},
		{
			name:                "explicit Glance metadata overrides the regional default",
			defaultArchitecture: ptr.To(unikornv1.Aarch64),
			imageArchitecture:   "x86_64",
			expectedFlavor:      types.Aarch64,
			expectedImage:       types.X86_64,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			region := architectureRegion(tc.defaultArchitecture, tc.flavorArchitecture)
			convertedFlavors := openstack.ConvertFlavors([]flavors.Flavor{{
				ID:    "flavor-id",
				Name:  "flavor-name",
				VCPUs: 1,
				RAM:   1024,
				Disk:  10,
			}}, region)

			require.Len(t, convertedFlavors, 1)
			require.Equal(t, tc.expectedFlavor, convertedFlavors[0].Architecture)

			properties := map[string]any{}
			if tc.imageArchitecture != nil {
				properties["architecture"] = tc.imageArchitecture
			}

			convertedImage, err := openstack.ConvertImageForRegion(&images.Image{Properties: properties}, region)
			require.NoError(t, err)
			require.Equal(t, tc.expectedImage, convertedImage.Architecture)
		})
	}
}

func architectureRegion(defaultArchitecture, flavorArchitecture *unikornv1.Architecture) *unikornv1.Region {
	region := &unikornv1.Region{
		Spec: unikornv1.RegionSpec{
			Openstack: &unikornv1.RegionOpenstackSpec{
				DefaultArchitecture: defaultArchitecture,
			},
		},
	}

	if flavorArchitecture != nil {
		region.Spec.Openstack.Compute = &unikornv1.RegionOpenstackComputeSpec{
			Flavors: &unikornv1.OpenstackFlavorsSpec{
				Metadata: []unikornv1.FlavorMetadata{
					{
						ID: "flavor-id",
						CPU: &unikornv1.CPUSpec{
							Architecture: flavorArchitecture,
						},
					},
				},
			},
		}
	}

	return region
}
