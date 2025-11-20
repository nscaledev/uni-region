/*
Copyright 2025 the Unikorn Authors.

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

package conversion

import (
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/utils/ptr"
)

func ConvertGpuVendor(in types.GPUVendor) openapi.GpuVendor {
	switch in {
	case types.Nvidia:
		return openapi.GpuVendorNVIDIA
	case types.AMD:
		return openapi.GpuVendorAMD
	}

	return ""
}

func ConvertFlavor(in *types.Flavor) *openapi.Flavor {
	out := &openapi.Flavor{
		Metadata: coreapi.StaticResourceMetadata{
			Id:   in.ID,
			Name: in.Name,
		},
		Spec: openapi.FlavorSpec{
			Cpus:      in.CPUs,
			CpuFamily: in.CPUFamily,
			Memory:    int(in.Memory.Value()) >> 30,
			Disk:      int(in.Disk.Value()) / 1000000000,
		},
	}

	if in.Baremetal {
		out.Spec.Baremetal = ptr.To(true)
	}

	if in.GPU != nil {
		out.Spec.Gpu = &openapi.GpuSpec{
			Vendor:        ConvertGpuVendor(in.GPU.Vendor),
			Model:         in.GPU.Model,
			Memory:        int(in.GPU.Memory.Value()) >> 30,
			PhysicalCount: in.GPU.PhysicalCount,
			LogicalCount:  in.GPU.LogicalCount,
		}
	}

	return out
}

func ConvertFlavors(in []types.Flavor) openapi.Flavors {
	out := make(openapi.Flavors, len(in))

	for i := range in {
		out[i] = *ConvertFlavor(&in[i])
	}

	return out
}
