/*
Copyright 2026 the Unikorn Authors.

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

//nolint:testpackage
package conversion

import (
	"testing"

	"github.com/stretchr/testify/require"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/handler/util/testutil"
	"github.com/unikorn-cloud/region/pkg/handler/util/unit"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/utils/ptr"
)

func GPUVendorNvidia() testutil.TypeConversion[types.GPUVendor, regionapi.GpuVendor] {
	return testutil.TypeConversion[types.GPUVendor, regionapi.GpuVendor]{
		Source: types.Nvidia,
		Target: regionapi.GpuVendorNVIDIA,
	}
}

func GPUVendorAMD() testutil.TypeConversion[types.GPUVendor, regionapi.GpuVendor] {
	return testutil.TypeConversion[types.GPUVendor, regionapi.GpuVendor]{
		Source: types.AMD,
		Target: regionapi.GpuVendorAMD,
	}
}

func TestConvertGpuVendor(t *testing.T) {
	t.Parallel()

	type TestCase struct {
		Name string
		Data testutil.TypeConversion[types.GPUVendor, regionapi.GpuVendor]
	}

	testCases := []TestCase{
		{
			Name: "Nvidia GPU vendor",
			Data: GPUVendorNvidia(),
		},
		{
			Name: "AMD GPU vendor",
			Data: GPUVendorAMD(),
		},
		{
			Name: "unknown GPU vendor",
			Data: testutil.TypeConversion[types.GPUVendor, regionapi.GpuVendor]{
				Source: "!@#$%^&*()-+",
				Target: "",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			vendor := ConvertGpuVendor(testCase.Data.Source)
			require.Equal(t, testCase.Data.Target, vendor)
		})
	}
}

func FlavorBasic() *testutil.TypeConversion[*types.Flavor, *regionapi.Flavor] {
	return &testutil.TypeConversion[*types.Flavor, *regionapi.Flavor]{
		Source: &types.Flavor{
			ID:        "0b8ecd4a-1f6c-4c32-8eda-ea5552ba0187",
			Name:      "basic",
			CPUs:      2,
			CPUFamily: ptr.To("intel-xeon-emerald-rapids"),
			Memory:    unit.ResourceQuantityGiB(7),
			Disk:      unit.ResourceQuantityGB(10),
		},
		Target: &regionapi.Flavor{
			Metadata: coreapi.StaticResourceMetadata{
				Id:   "0b8ecd4a-1f6c-4c32-8eda-ea5552ba0187",
				Name: "basic",
			},
			Spec: regionapi.FlavorSpec{
				CpuFamily: ptr.To("intel-xeon-emerald-rapids"),
				Cpus:      2,
				Disk:      10,
				Memory:    7,
			},
		},
	}
}

func FlavorBareMetal() *testutil.TypeConversion[*types.Flavor, *regionapi.Flavor] {
	return &testutil.TypeConversion[*types.Flavor, *regionapi.Flavor]{
		Source: &types.Flavor{
			ID:        "faf2efba-83a0-4058-881d-46e2b7103d23",
			Name:      "bare-metal",
			CPUs:      288,
			CPUFamily: ptr.To("intel-xeon-granite-rapids"),
			Memory:    unit.ResourceQuantityGiB(1080),
			Disk:      unit.ResourceQuantityGB(20),
			Baremetal: true,
		},
		Target: &regionapi.Flavor{
			Metadata: coreapi.StaticResourceMetadata{
				Id:   "faf2efba-83a0-4058-881d-46e2b7103d23",
				Name: "bare-metal",
			},
			Spec: regionapi.FlavorSpec{
				Baremetal: ptr.To(true),
				CpuFamily: ptr.To("intel-xeon-granite-rapids"),
				Cpus:      288,
				Disk:      20,
				Memory:    1080,
			},
		},
	}
}

func FlavorGPUNvidiaGB300() *testutil.TypeConversion[*types.Flavor, *regionapi.Flavor] {
	return &testutil.TypeConversion[*types.Flavor, *regionapi.Flavor]{
		Source: &types.Flavor{
			ID:     "141ce964-b1eb-4ede-8c90-565e61a2615c",
			Name:   "gpu-nvidia-gb300",
			CPUs:   36,
			Memory: unit.ResourceQuantityGiB(20480),
			Disk:   unit.ResourceQuantityGB(1024),
			GPU: &types.GPU{
				Vendor:        types.Nvidia,
				Model:         "GB300",
				Memory:        unit.ResourceQuantityGiB(18626),
				PhysicalCount: 72,
				LogicalCount:  72,
			},
			Baremetal: true,
		},
		Target: &regionapi.Flavor{
			Metadata: coreapi.StaticResourceMetadata{
				Id:   "141ce964-b1eb-4ede-8c90-565e61a2615c",
				Name: "gpu-nvidia-gb300",
			},
			Spec: regionapi.FlavorSpec{
				Baremetal: ptr.To(true),
				Cpus:      36,
				Disk:      1024,
				Gpu: &regionapi.GpuSpec{
					Vendor:        regionapi.GpuVendorNVIDIA,
					Model:         "GB300",
					Memory:        18626,
					PhysicalCount: 72,
					LogicalCount:  72,
				},
				Memory: 20480,
			},
		},
	}
}

func FlavorGPUNvidiaDGXH200() *testutil.TypeConversion[*types.Flavor, *regionapi.Flavor] {
	return &testutil.TypeConversion[*types.Flavor, *regionapi.Flavor]{
		Source: &types.Flavor{
			ID:        "571fd94a-9d44-4937-83a1-d527a4e208d3",
			Name:      "gpu-nvidia-dgx-h200",
			CPUs:      112,
			CPUFamily: ptr.To("intel-xeon-sapphire-rapids"),
			Memory:    unit.ResourceQuantityGiB(2048),
			Disk:      unit.ResourceQuantityGB(20),
			GPU: &types.GPU{
				Vendor:        types.Nvidia,
				Model:         "H200",
				Memory:        unit.ResourceQuantityGiB(1050),
				PhysicalCount: 8,
				LogicalCount:  56,
			},
		},
		Target: &regionapi.Flavor{
			Metadata: coreapi.StaticResourceMetadata{
				Id:   "571fd94a-9d44-4937-83a1-d527a4e208d3",
				Name: "gpu-nvidia-dgx-h200",
			},
			Spec: regionapi.FlavorSpec{
				CpuFamily: ptr.To("intel-xeon-sapphire-rapids"),
				Cpus:      112,
				Disk:      20,
				Gpu: &regionapi.GpuSpec{
					Vendor:        regionapi.GpuVendorNVIDIA,
					Model:         "H200",
					Memory:        1050,
					PhysicalCount: 8,
					LogicalCount:  56,
				},
				Memory: 2048,
			},
		},
	}
}

func FlavorGPUAMDMI300X() *testutil.TypeConversion[*types.Flavor, *regionapi.Flavor] {
	return &testutil.TypeConversion[*types.Flavor, *regionapi.Flavor]{
		Source: &types.Flavor{
			ID:        "744f55b3-ca31-4950-b4ad-5e841d61cbbf",
			Name:      "gpu-amd-mi300x",
			CPUs:      112,
			CPUFamily: ptr.To("intel-xeon-sapphire-rapids"),
			Memory:    unit.ResourceQuantityGiB(2048),
			Disk:      unit.ResourceQuantityGB(20),
			GPU: &types.GPU{
				Vendor:        types.AMD,
				Model:         "MI300X",
				Memory:        unit.ResourceQuantityGiB(1430),
				PhysicalCount: 8,
				LogicalCount:  32,
			},
		},
		Target: &regionapi.Flavor{
			Metadata: coreapi.StaticResourceMetadata{
				Id:   "744f55b3-ca31-4950-b4ad-5e841d61cbbf",
				Name: "gpu-amd-mi300x",
			},
			Spec: regionapi.FlavorSpec{
				CpuFamily: ptr.To("intel-xeon-sapphire-rapids"),
				Cpus:      112,
				Disk:      20,
				Gpu: &regionapi.GpuSpec{
					Vendor:        regionapi.GpuVendorAMD,
					Model:         "MI300X",
					Memory:        1430,
					PhysicalCount: 8,
					LogicalCount:  32,
				},
				Memory: 2048,
			},
		},
	}
}

func TestConvertFlavor(t *testing.T) {
	t.Parallel()

	type TestCase struct {
		Name string
		Data *testutil.TypeConversion[*types.Flavor, *regionapi.Flavor]
	}

	testCases := []TestCase{
		{
			Name: "basic flavor",
			Data: FlavorBasic(),
		},
		{
			Name: "bare metal flavor",
			Data: FlavorBareMetal(),
		},
		{
			Name: "GPU flavor #1",
			Data: FlavorGPUNvidiaGB300(),
		},
		{
			Name: "GPU flavor #2",
			Data: FlavorGPUNvidiaDGXH200(),
		},
		{
			Name: "GPU flavor #3",
			Data: FlavorGPUAMDMI300X(),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			flavor := ConvertFlavor(testCase.Data.Source)
			require.Equal(t, testCase.Data.Target, flavor)
		})
	}
}

func TestConvertFlavors(t *testing.T) {
	t.Parallel()

	type TestCase struct {
		Name     string
		Input    types.FlavorList
		Expected regionapi.Flavors
	}

	testCases := []TestCase{
		{
			Name:     "#1",
			Input:    types.FlavorList{},
			Expected: regionapi.Flavors{},
		},
		{
			Name: "#2",
			Input: types.FlavorList{
				*FlavorBasic().Source,
			},
			Expected: regionapi.Flavors{
				*FlavorBasic().Target,
			},
		},
		{
			Name: "#3",
			Input: types.FlavorList{
				*FlavorBasic().Source,
				*FlavorBareMetal().Source,
			},
			Expected: regionapi.Flavors{
				*FlavorBasic().Target,
				*FlavorBareMetal().Target,
			},
		},
		{
			Name: "#4",
			Input: types.FlavorList{
				*FlavorBasic().Source,
				*FlavorBareMetal().Source,
				*FlavorGPUNvidiaGB300().Source,
				*FlavorGPUNvidiaDGXH200().Source,
				*FlavorGPUAMDMI300X().Source,
			},
			Expected: regionapi.Flavors{
				*FlavorBasic().Target,
				*FlavorBareMetal().Target,
				*FlavorGPUNvidiaGB300().Target,
				*FlavorGPUNvidiaDGXH200().Target,
				*FlavorGPUAMDMI300X().Target,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			flavors := ConvertFlavors(testCase.Input)
			require.Equal(t, testCase.Expected, flavors)
		})
	}
}
