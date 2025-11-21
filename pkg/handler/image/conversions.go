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

package image

import (
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/handler/conversion"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"
)

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

func convertImage(in *types.Image) *openapi.Image {
	out := &openapi.Image{
		Metadata: coreapi.StaticResourceMetadata{
			Id:           in.ID,
			Name:         in.Name,
			CreationTime: in.Created,
		},
		Spec: openapi.ImageSpec{
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
