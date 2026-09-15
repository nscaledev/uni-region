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
)

func TestVolumeClassCapacityBoundsValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		minimum  any
		maximum  any
		expected bool
	}{
		{
			name:     "absent bounds",
			expected: true,
		},
		{
			name:     "minimum only",
			minimum:  int64(1),
			expected: true,
		},
		{
			name:     "maximum only",
			maximum:  int64(1024),
			expected: true,
		},
		{
			name:     "equal bounds",
			minimum:  int64(100),
			maximum:  int64(100),
			expected: true,
		},
		{
			name:     "ordered bounds",
			minimum:  int64(100),
			maximum:  int64(200),
			expected: true,
		},
		{
			name:    "zero minimum",
			minimum: int64(0),
		},
		{
			name:    "negative minimum",
			minimum: int64(-1),
		},
		{
			name:    "zero maximum",
			maximum: int64(0),
		},
		{
			name:    "negative maximum",
			maximum: int64(-1),
		},
		{
			name:    "fractional minimum",
			minimum: 1.5,
		},
		{
			name:    "fractional maximum",
			maximum: 1024.5,
		},
		{
			name:    "maximum below minimum",
			minimum: int64(200),
			maximum: int64(100),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resource := regionWithVolumeClassCapacityBounds(tc.minimum, tc.maximum)
			valid := newCRDValidator(t, regionCRDFile).validatesUnstructured(t, resource)

			require.Equal(t, tc.expected, valid)
		})
	}
}

func TestVolumeClassSupportedFlavorsValidation(t *testing.T) {
	t.Parallel()

	validFlavorID := "11111111-1111-4111-a111-111111111111"
	otherFlavorID := "22222222-2222-4222-a222-222222222222"

	cases := []struct {
		name     string
		selector any
		set      bool
		expected bool
	}{
		{name: "omitted", expected: true},
		{name: "empty selector with omitted IDs", selector: map[string]any{}, set: true, expected: true},
		{name: "empty IDs", selector: map[string]any{"ids": []any{}}, set: true, expected: true},
		{name: "populated", selector: map[string]any{"ids": []any{validFlavorID, otherFlavorID}}, set: true, expected: true},
		{name: "duplicate", selector: map[string]any{"ids": []any{validFlavorID, validFlavorID}}, set: true},
		{name: "duplicate uppercase spelling", selector: map[string]any{"ids": []any{validFlavorID, "11111111-1111-4111-A111-111111111111"}}, set: true},
		{name: "duplicate unhyphenated spelling", selector: map[string]any{"ids": []any{validFlavorID, "1111111111114111a111111111111111"}}, set: true},
		{name: "invalid ID", selector: map[string]any{"ids": []any{"not-a-uuid"}}, set: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			metadata := map[string]any{"id": "volume-class"}
			if tc.set {
				metadata["supportedFlavors"] = tc.selector
			}

			valid := newCRDValidator(t, regionCRDFile).validatesUnstructured(t, regionWithVolumeClassMetadata(metadata))
			require.Equal(t, tc.expected, valid)
		})
	}
}

func regionWithVolumeClassCapacityBounds(minimum, maximum any) map[string]any {
	metadata := map[string]any{
		"id": "volume-class",
	}

	if minimum != nil {
		metadata["minimumSizeGiB"] = minimum
	}

	if maximum != nil {
		metadata["maximumSizeGiB"] = maximum
	}

	return regionWithVolumeClassMetadata(metadata)
}

func regionWithVolumeClassMetadata(metadata map[string]any) map[string]any {
	return map[string]any{
		"apiVersion": "region.unikorn-cloud.org/v1alpha1",
		"kind":       "Region",
		"metadata": map[string]any{
			"name":      "region",
			"namespace": "default",
		},
		"spec": map[string]any{
			"provider": "openstack",
			"openstack": map[string]any{
				"endpoint": "https://openstack.example.com:5000",
				"serviceAccountSecret": map[string]any{
					"name":      "credentials",
					"namespace": "default",
				},
				"blockStorage": map[string]any{
					"volumeClasses": map[string]any{
						"selector": map[string]any{
							"ids": []any{"volume-class"},
						},
						"metadata": []any{metadata},
					},
				},
			},
		},
	}
}
