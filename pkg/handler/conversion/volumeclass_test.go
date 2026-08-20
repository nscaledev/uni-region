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

package conversion_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/region/pkg/handler/conversion"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/utils/ptr"
)

func TestConvertVolumeClassesMapsCapacityBounds(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		minimum *int64
		maximum *int64
	}{
		{
			name: "absent bounds",
		},
		{
			name:    "minimum only",
			minimum: ptr.To(int64(10)),
		},
		{
			name:    "maximum only",
			maximum: ptr.To(int64(2000)),
		},
		{
			name:    "both bounds",
			minimum: ptr.To(int64(10)),
			maximum: ptr.To(int64(2000)),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out := conversion.ConvertVolumeClasses(
				idstest.MustParseRegionID("11111111-1111-4111-a111-111111111111"),
				types.VolumeClassList{
					{
						ID:             "volume-class",
						MinimumSizeGiB: tc.minimum,
						MaximumSizeGiB: tc.maximum,
					},
				},
			)

			require.Len(t, out, 1)
			require.Equal(t, tc.minimum, out[0].Spec.MinimumSizeGiB)
			require.Equal(t, tc.maximum, out[0].Spec.MaximumSizeGiB)
		})
	}
}

func TestConvertVolumeClassesMapsSupportedFlavorIDs(t *testing.T) {
	t.Parallel()

	supportedFlavorIDs := []regionids.FlavorID{
		idstest.MustParseFlavorID("22222222-2222-4222-a222-222222222222"),
		idstest.MustParseFlavorID("33333333-3333-4333-a333-333333333333"),
	}

	cases := []struct {
		name string
		ids  []regionids.FlavorID
	}{
		{name: "omitted"},
		{name: "empty", ids: []regionids.FlavorID{}},
		{name: "populated", ids: supportedFlavorIDs},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out := conversion.ConvertVolumeClasses(
				idstest.MustParseRegionID("11111111-1111-4111-a111-111111111111"),
				types.VolumeClassList{{ID: "volume-class", SupportedFlavorIDs: tc.ids}},
			)

			require.Len(t, out, 1)

			if len(tc.ids) == 0 {
				require.Nil(t, out[0].Spec.SupportedFlavorIds)
			} else {
				require.Equal(t, tc.ids, *out[0].Spec.SupportedFlavorIds)
			}
		})
	}
}
