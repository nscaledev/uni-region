/*
Copyright 2025 the Unikorn Authors.
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

package image

import (
	"errors"
	"maps"
	"slices"
	"strings"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/handler/conversion"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"
)

var ErrUnknownDiskFormat = errors.New("unknown image format")

// Export this so it can be used for server snapshot.
//
//nolint:gochecknoglobals
var ConvertImage = convertImage

func convertArchitecture(in types.Architecture) openapi.Architecture {
	switch in {
	case types.X86_64:
		return openapi.ArchitectureX8664
	case types.Aarch64:
		return openapi.ArchitectureAarch64
	}

	return ""
}

func convertImageVirtualization(in types.ImageVirtualization) openapi.ImageVirtualization {
	switch in {
	case types.Virtualized:
		return openapi.ImageVirtualizationVirtualized
	case types.Baremetal:
		return openapi.ImageVirtualizationBaremetal
	case types.Any:
		return openapi.ImageVirtualizationAny
	}

	return ""
}

func convertOsKernel(in types.OsKernel) openapi.OsKernel {
	//nolint:gocritic
	switch in {
	case types.Linux:
		return openapi.OsKernelLinux
	}

	return ""
}

func convertOsFamily(in types.OsFamily) openapi.OsFamily {
	switch in {
	case types.Debian:
		return openapi.OsFamilyDebian
	case types.Redhat:
		return openapi.OsFamilyRedhat
	}

	return ""
}

func convertOsDistro(in types.OsDistro) openapi.OsDistro {
	switch in {
	case types.Rocky:
		return openapi.OsDistroRocky
	case types.Ubuntu:
		return openapi.OsDistroUbuntu
	}

	return ""
}

func convertPackages(in *types.ImagePackages) *openapi.SoftwareVersions {
	if in == nil {
		return nil
	}

	out := make(openapi.SoftwareVersions)

	for name, version := range *in {
		out[name] = version
	}

	return &out
}

func convertState(in types.ImageStatus) openapi.ImageState {
	switch in {
	case types.ImageStatusPending:
		return openapi.ImageStatePending
	case types.ImageStatusCreating:
		return openapi.ImageStateCreating
	case types.ImageStatusReady:
		return openapi.ImageStateReady
	case types.ImageStatusFailed:
		return openapi.ImageStateFailed
	}

	return ""
}

func convertTags(in map[string]string) *coreapi.TagList {
	if len(in) == 0 {
		return nil
	}

	var out coreapi.TagList

	for k, v := range in {
		out = append(out, coreapi.Tag{
			Name:  k,
			Value: v,
		})
	}

	slices.SortFunc(out, func(a, b coreapi.Tag) int {
		return strings.Compare(a.Name, b.Name)
	})

	return &out
}

func convertImage(in *types.Image) *openapi.Image {
	out := &openapi.Image{
		Metadata: coreapi.StaticResourceMetadata{
			Id:           in.ID,
			Name:         in.Name,
			Tags:         convertTags(in.Tags),
			CreationTime: in.Created,
		},
		Spec: openapi.ImageSpec{
			Architecture:   convertArchitecture(in.Architecture),
			SizeGiB:        in.SizeGiB,
			Virtualization: convertImageVirtualization(in.Virtualization),
			Os: openapi.ImageOS{
				Kernel:   convertOsKernel(in.OS.Kernel),
				Family:   convertOsFamily(in.OS.Family),
				Distro:   convertOsDistro(in.OS.Distro),
				Codename: in.OS.Codename,
				Variant:  in.OS.Variant,
				Version:  in.OS.Version,
			},
			SoftwareVersions: convertPackages(in.Packages),
		},
		Status: openapi.ImageStatus{
			State: convertState(in.Status),
		},
	}

	if in.GPU != nil {
		gpu := &openapi.ImageGpu{
			Vendor: conversion.ConvertGpuVendor(in.GPU.Vendor),
			Driver: in.GPU.Driver,
		}

		if len(in.GPU.Models) > 0 {
			gpu.Models = &in.GPU.Models
		}

		out.Spec.Gpu = gpu
	}

	return out
}

func convertImages(in []types.Image) openapi.Images {
	out := make(openapi.Images, len(in))

	for i := range in {
		out[i] = *convertImage(&in[i])
	}

	return out
}

func generateArchitecture(in openapi.Architecture) types.Architecture {
	switch in {
	case openapi.ArchitectureX8664:
		return types.X86_64
	case openapi.ArchitectureAarch64:
		return types.Aarch64
	default:
		return ""
	}
}

func generateImageVirtualization(source openapi.ImageVirtualization) types.ImageVirtualization {
	switch source {
	case openapi.ImageVirtualizationVirtualized:
		return types.Virtualized
	case openapi.ImageVirtualizationBaremetal:
		return types.Baremetal
	case openapi.ImageVirtualizationAny:
		return types.Any
	default:
		return ""
	}
}

func generateOSKernel(source openapi.OsKernel) types.OsKernel {
	switch source {
	case openapi.OsKernelLinux:
		return types.Linux
	default:
		return ""
	}
}

func generateOSFamily(source openapi.OsFamily) types.OsFamily {
	switch source {
	case openapi.OsFamilyDebian:
		return types.Debian
	case openapi.OsFamilyRedhat:
		return types.Redhat
	default:
		return ""
	}
}

func generateOSDistro(source openapi.OsDistro) types.OsDistro {
	switch source {
	case openapi.OsDistroRocky:
		return types.Rocky
	case openapi.OsDistroUbuntu:
		return types.Ubuntu
	default:
		return ""
	}
}

func generatePackages(source openapi.SoftwareVersions) types.ImagePackages {
	target := make(types.ImagePackages, len(source))

	for name, version := range source {
		target[name] = version
	}

	return target
}

func generateGPUVendor(source openapi.GpuVendor) types.GPUVendor {
	switch source {
	case openapi.GpuVendorNVIDIA:
		return types.Nvidia
	case openapi.GpuVendorAMD:
		return types.AMD
	default:
		return ""
	}
}

func generateImageGPU(source *openapi.ImageGpu) *types.ImageGPU {
	var models []string
	if source.Models != nil {
		models = *source.Models
	}

	return &types.ImageGPU{
		Vendor: generateGPUVendor(source.Vendor),
		Driver: source.Driver,
		Models: models,
	}
}

func generateImageOS(source *openapi.ImageOS) *types.ImageOS {
	return &types.ImageOS{
		Kernel:   generateOSKernel(source.Kernel),
		Family:   generateOSFamily(source.Family),
		Distro:   generateOSDistro(source.Distro),
		Variant:  source.Variant,
		Codename: source.Codename,
		Version:  source.Version,
	}
}

func generateStatus(in openapi.ImageState) types.ImageStatus {
	switch in {
	case openapi.ImageStatePending:
		return types.ImageStatusPending
	case openapi.ImageStateCreating:
		return types.ImageStatusCreating
	case openapi.ImageStateReady:
		return types.ImageStatusReady
	case openapi.ImageStateFailed:
		return types.ImageStatusFailed
	}

	return ""
}

func GenerateTags(requestTags *coreapi.TagList, extra map[string]string) map[string]string {
	if requestTags == nil && extra == nil {
		return nil
	}

	tags := map[string]string{}

	if requestTags != nil {
		for _, item := range *requestTags {
			tags[item.Name] = item.Value
		}
	}

	if len(extra) > 0 {
		maps.Copy(tags, extra)
	}

	return tags
}
