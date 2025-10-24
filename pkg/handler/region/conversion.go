/*
Copyright 2024-2025 the Unikorn Authors.

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

package region

import (
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/utils/ptr"
)

func fromProviderGPUVendor(source types.GPUVendor) openapi.GpuVendor {
	switch source {
	case types.Nvidia:
		return openapi.NVIDIA
	case types.AMD:
		return openapi.AMD
	default:
		return ""
	}
}

func toProviderGPUVendor(source openapi.GpuVendor) types.GPUVendor {
	switch source {
	case openapi.NVIDIA:
		return types.Nvidia
	case openapi.AMD:
		return types.AMD
	default:
		return ""
	}
}

func fromProviderFlavorGPU(source *types.GPU) *openapi.GpuSpec {
	return &openapi.GpuSpec{
		LogicalCount:  source.LogicalCount,
		Memory:        int(source.Memory.Value() >> 30),
		Model:         source.Model,
		PhysicalCount: source.PhysicalCount,
		Vendor:        fromProviderGPUVendor(source.Vendor),
	}
}

func fromProviderFlavor(source *types.Flavor) *openapi.Flavor {
	var gpu *openapi.GpuSpec
	if source.GPU != nil {
		gpu = fromProviderFlavorGPU(source.GPU)
	}

	return &openapi.Flavor{
		Metadata: coreapi.StaticResourceMetadata{
			Id:   source.ID,
			Name: source.Name,
		},
		Spec: openapi.FlavorSpec{
			Baremetal: ptr.To(source.Baremetal),
			CpuFamily: source.CPUFamily,
			Cpus:      source.CPUs,
			Disk:      int(source.Disk.Value() / 1000000000),
			Gpu:       gpu,
			Memory:    int(source.Memory.Value() >> 30),
		},
	}
}

func fromProviderFlavors(sources []types.Flavor) []openapi.Flavor {
	targets := make([]openapi.Flavor, len(sources))

	for i, source := range sources {
		targets[i] = *fromProviderFlavor(&source)
	}

	return targets
}

func fromProviderImageVirtualization(source types.ImageVirtualization) openapi.ImageVirtualization {
	switch source {
	case types.Virtualized:
		return openapi.Virtualized
	case types.Baremetal:
		return openapi.Baremetal
	case types.Any:
		return openapi.Any
	default:
		return ""
	}
}

func toProviderImageVirtualization(source openapi.ImageVirtualization) types.ImageVirtualization {
	switch source {
	case openapi.Virtualized:
		return types.Virtualized
	case openapi.Baremetal:
		return types.Baremetal
	case openapi.Any:
		return types.Any
	default:
		return ""
	}
}

func fromProviderOSKernel(source types.OsKernel) openapi.OsKernel {
	switch source {
	case types.Linux:
		return openapi.Linux
	default:
		return ""
	}
}

func toProviderOSKernel(source openapi.OsKernel) types.OsKernel {
	switch source {
	case openapi.Linux:
		return types.Linux
	default:
		return ""
	}
}

func fromProviderOSFamily(source types.OsFamily) openapi.OsFamily {
	switch source {
	case types.Debian:
		return openapi.Debian
	case types.Redhat:
		return openapi.Redhat
	default:
		return ""
	}
}

func toProviderOSFamily(source openapi.OsFamily) types.OsFamily {
	switch source {
	case openapi.Debian:
		return types.Debian
	case openapi.Redhat:
		return types.Redhat
	default:
		return ""
	}
}

func fromProviderOSDistro(source types.OsDistro) openapi.OsDistro {
	switch source {
	case types.Rocky:
		return openapi.Rocky
	case types.Ubuntu:
		return openapi.Ubuntu
	default:
		return ""
	}
}

func toProviderOSDistro(source openapi.OsDistro) types.OsDistro {
	switch source {
	case openapi.Rocky:
		return types.Rocky
	case openapi.Ubuntu:
		return types.Ubuntu
	default:
		return ""
	}
}

func fromProviderPackages(source types.ImagePackages) openapi.SoftwareVersions {
	target := make(openapi.SoftwareVersions, len(source))

	for name, version := range source {
		target[name] = version
	}

	return target
}

func toProviderPackages(source openapi.SoftwareVersions) types.ImagePackages {
	target := make(types.ImagePackages, len(source))

	for name, version := range source {
		target[name] = version
	}

	return target
}

func fromProviderImageGPU(source *types.ImageGPU) *openapi.ImageGpu {
	var models *[]string
	if source.Models != nil {
		models = &source.Models
	}

	return &openapi.ImageGpu{
		Driver: source.Driver,
		Models: models,
		Vendor: fromProviderGPUVendor(source.Vendor),
	}
}

func toProviderImageGPU(source *openapi.ImageGpu) *types.ImageGPU {
	var models []string
	if source.Models != nil {
		models = *source.Models
	}

	return &types.ImageGPU{
		Vendor: toProviderGPUVendor(source.Vendor),
		Driver: source.Driver,
		Models: models,
	}
}

func fromProviderImageOS(source *types.ImageOS) *openapi.ImageOS {
	return &openapi.ImageOS{
		Codename: source.Codename,
		Distro:   fromProviderOSDistro(source.Distro),
		Family:   fromProviderOSFamily(source.Family),
		Kernel:   fromProviderOSKernel(source.Kernel),
		Variant:  source.Variant,
		Version:  source.Version,
	}
}

func toProviderImageOS(source *openapi.ImageOS) *types.ImageOS {
	return &types.ImageOS{
		Kernel:   toProviderOSKernel(source.Kernel),
		Family:   toProviderOSFamily(source.Family),
		Distro:   toProviderOSDistro(source.Distro),
		Variant:  source.Variant,
		Codename: source.Codename,
		Version:  source.Version,
	}
}

func fromProviderImage(source *types.Image) *openapi.Image {
	var gpu *openapi.ImageGpu

	if source.GPU != nil {
		gpu = fromProviderImageGPU(source.GPU)
	}

	var softwareVersions *openapi.SoftwareVersions

	if source.Packages != nil {
		temp := fromProviderPackages(*source.Packages)
		softwareVersions = &temp
	}

	return &openapi.Image{
		Metadata: openapi.ImageMetadata{
			Id:           source.ID,
			Name:         source.Name,
			CreationTime: source.Created,
		},
		Spec: openapi.ImageSpec{
			Gpu:              gpu,
			Os:               *fromProviderImageOS(&source.OS),
			SizeGiB:          source.SizeGiB,
			SoftwareVersions: softwareVersions,
			Virtualization:   fromProviderImageVirtualization(source.Virtualization),
		},
	}
}

func fromProviderImages(sources []types.Image) []openapi.Image {
	targets := make([]openapi.Image, len(sources))

	for i, source := range sources {
		targets[i] = *fromProviderImage(&source)
	}

	return targets
}

func fromProviderExternalNetwork(in types.ExternalNetwork) openapi.ExternalNetwork {
	return openapi.ExternalNetwork{
		Id:   in.ID,
		Name: in.Name,
	}
}

func fromProviderExternalNetworks(in types.ExternalNetworks) openapi.ExternalNetworks {
	targets := make([]openapi.ExternalNetwork, len(in))

	for i, source := range in {
		targets[i] = fromProviderExternalNetwork(source)
	}

	return targets
}
