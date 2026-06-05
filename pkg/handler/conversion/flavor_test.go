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
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/ptr"
)

// TestConvertGpuVendor verifies the GPU vendor enum mapping for all known values
// plus the unknown fallback.
func TestConvertGpuVendor(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input types.GPUVendor
		want  openapi.GpuVendor
	}{
		{
			name:  "NVIDIA",
			input: types.Nvidia,
			want:  openapi.GpuVendorNVIDIA,
		},
		{
			name:  "AMD",
			input: types.AMD,
			want:  openapi.GpuVendorAMD,
		},
		{
			name:  "unknown vendor returns empty string",
			input: "unknown-vendor",
			want:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.want, conversion.ConvertGpuVendor(tc.input))
		})
	}
}

// TestConvertFlavor verifies that ConvertFlavor maps all fields correctly across
// the four meaningful input shapes: plain CPU flavor, baremetal, with GPU, and
// with GPU and baremetal.
func TestConvertFlavor(t *testing.T) {
	t.Parallel()

	baseMemory := resource.MustParse("4Gi")
	baseDisk := resource.MustParse("100G")
	gpuMemory := resource.MustParse("16Gi")
	cpuFamily := "Sapphire Rapids"

	t.Run("cpu-only flavor", func(t *testing.T) {
		t.Parallel()

		in := &types.Flavor{
			ID:           "flavor-1",
			Name:         "m1.small",
			Architecture: types.X86_64,
			CPUs:         4,
			CPUFamily:    ptr.To(cpuFamily),
			Memory:       &baseMemory,
			Disk:         &baseDisk,
		}

		out := conversion.ConvertFlavor(in)

		require.Equal(t, "flavor-1", out.Metadata.Id)
		require.Equal(t, "m1.small", out.Metadata.Name)
		require.Equal(t, openapi.ArchitectureX8664, out.Spec.Architecture)
		require.Equal(t, 4, out.Spec.Cpus)
		require.Equal(t, ptr.To(cpuFamily), out.Spec.CpuFamily)
		require.Equal(t, 4, out.Spec.Memory)
		require.Equal(t, 100, out.Spec.Disk)
		require.Nil(t, out.Spec.Gpu)
		require.Nil(t, out.Spec.Baremetal)
	})

	t.Run("baremetal flavor sets baremetal flag", func(t *testing.T) {
		t.Parallel()

		in := &types.Flavor{
			ID:           "flavor-bm",
			Name:         "bm1.large",
			Architecture: types.Aarch64,
			CPUs:         128,
			Memory:       &baseMemory,
			Disk:         &baseDisk,
			Baremetal:    true,
		}

		out := conversion.ConvertFlavor(in)

		require.Equal(t, openapi.ArchitectureAarch64, out.Spec.Architecture)
		require.NotNil(t, out.Spec.Baremetal)
		require.True(t, *out.Spec.Baremetal)
		require.Nil(t, out.Spec.Gpu)
	})

	t.Run("GPU flavor populates gpu spec", func(t *testing.T) {
		t.Parallel()

		in := &types.Flavor{
			ID:           "flavor-gpu",
			Name:         "g1.xlarge",
			Architecture: types.X86_64,
			CPUs:         16,
			Memory:       &baseMemory,
			Disk:         &baseDisk,
			GPU: &types.GPU{
				Vendor:        types.Nvidia,
				Model:         "A100",
				Memory:        &gpuMemory,
				PhysicalCount: 2,
				LogicalCount:  2,
			},
		}

		out := conversion.ConvertFlavor(in)

		require.Nil(t, out.Spec.Baremetal)
		require.NotNil(t, out.Spec.Gpu)
		require.Equal(t, openapi.GpuVendorNVIDIA, out.Spec.Gpu.Vendor)
		require.Equal(t, "A100", out.Spec.Gpu.Model)
		require.Equal(t, 16, out.Spec.Gpu.Memory)
		require.Equal(t, 2, out.Spec.Gpu.PhysicalCount)
		require.Equal(t, 2, out.Spec.Gpu.LogicalCount)
	})

	t.Run("baremetal GPU flavor sets both flags", func(t *testing.T) {
		t.Parallel()

		in := &types.Flavor{
			ID:           "flavor-bm-gpu",
			Name:         "bm1.gpu",
			Architecture: types.X86_64,
			CPUs:         64,
			Memory:       &baseMemory,
			Disk:         &baseDisk,
			Baremetal:    true,
			GPU: &types.GPU{
				Vendor:        types.AMD,
				Model:         "MI250",
				Memory:        &gpuMemory,
				PhysicalCount: 4,
				LogicalCount:  8,
			},
		}

		out := conversion.ConvertFlavor(in)

		require.NotNil(t, out.Spec.Baremetal)
		require.True(t, *out.Spec.Baremetal)
		require.NotNil(t, out.Spec.Gpu)
		require.Equal(t, openapi.GpuVendorAMD, out.Spec.Gpu.Vendor)
	})
}

// TestConvertFlavors verifies that ConvertFlavors maps every element in the
// input slice and that an empty input produces an empty (non-nil) output.
func TestConvertFlavors(t *testing.T) {
	t.Parallel()

	mem := resource.MustParse("2Gi")
	disk := resource.MustParse("50G")

	t.Run("empty slice returns empty output", func(t *testing.T) {
		t.Parallel()

		out := conversion.ConvertFlavors(nil)
		require.Empty(t, out)
	})

	t.Run("multiple flavors all converted", func(t *testing.T) {
		t.Parallel()

		in := []types.Flavor{
			{ID: "a", Name: "small", Architecture: types.X86_64, CPUs: 2, Memory: &mem, Disk: &disk},
			{ID: "b", Name: "medium", Architecture: types.Aarch64, CPUs: 4, Memory: &mem, Disk: &disk},
		}

		out := conversion.ConvertFlavors(in)

		require.Len(t, out, 2)
		require.Equal(t, "a", out[0].Metadata.Id)
		require.Equal(t, "b", out[1].Metadata.Id)
	})
}
