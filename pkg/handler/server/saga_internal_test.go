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

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"
)

func TestValidateVolumeClassFlavor(t *testing.T) {
	t.Parallel()

	const (
		volumeClassID = "fast"
		flavorID      = "11111111-1111-4111-a111-111111111111"
		otherFlavorID = "22222222-2222-4222-a222-222222222222"
	)

	regionWithClasses := func(classes ...regionv1.VolumeClassMetadata) *regionv1.Region {
		return &regionv1.Region{Spec: regionv1.RegionSpec{Openstack: &regionv1.RegionOpenstackSpec{
			BlockStorage: &regionv1.RegionOpenstackBlockStorageSpec{
				VolumeClasses: &regionv1.OpenstackVolumeClassesSpec{Metadata: classes},
			},
		}}}
	}

	tests := []struct {
		name      string
		region    *regionv1.Region
		wantError string
	}{
		{
			name:      "no volume class configuration",
			region:    &regionv1.Region{},
			wantError: `volume class "fast" is not defined in the region`,
		},
		{
			name:      "unknown class",
			region:    regionWithClasses(regionv1.VolumeClassMetadata{ID: "other"}),
			wantError: `volume class "fast" is not defined in the region`,
		},
		{
			name:      "unset allowlist",
			region:    regionWithClasses(regionv1.VolumeClassMetadata{ID: volumeClassID}),
			wantError: "volume class does not support the server flavor",
		},
		{
			name: "empty allowlist",
			region: regionWithClasses(regionv1.VolumeClassMetadata{
				ID:               volumeClassID,
				SupportedFlavors: &regionv1.VolumeClassFlavorSelector{},
			}),
			wantError: "volume class does not support the server flavor",
		},
		{
			name: "restricted class match",
			region: regionWithClasses(regionv1.VolumeClassMetadata{
				ID: volumeClassID,
				SupportedFlavors: &regionv1.VolumeClassFlavorSelector{
					IDs: []regionids.FlavorID{idstest.MustParseFlavorID(flavorID)},
				},
			}),
		},
		{
			name: "restricted class mismatch",
			region: regionWithClasses(regionv1.VolumeClassMetadata{
				ID: volumeClassID,
				SupportedFlavors: &regionv1.VolumeClassFlavorSelector{
					IDs: []regionids.FlavorID{idstest.MustParseFlavorID(otherFlavorID)},
				},
			}),
			wantError: "volume class does not support the server flavor",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateVolumeClassFlavor(tt.region, volumeClassID, flavorID)
			if tt.wantError == "" {
				require.NoError(t, err)

				return
			}

			require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
			require.EqualError(t, err, tt.wantError)
		})
	}
}
