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
	"cmp"
	"context"
	"encoding/base64"
	goerrors "errors"
	"fmt"
	"slices"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrResource is raised when a resource is in a bad state.
	ErrResource = goerrors.New("resource error")

	// ErrRegionNotFound is raised when a region doesn't exist.
	ErrRegionNotFound = goerrors.New("region doesn't exist")
)

type Client struct {
	client    client.Client
	namespace string
}

func NewClient(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

func (c *Client) Provider(ctx context.Context, regionID string) (types.Provider, error) {
	return providers.New(ctx, c.client, c.namespace, regionID)
}

func convertRegionType(in unikornv1.Provider) openapi.RegionType {
	switch in {
	case unikornv1.ProviderKubernetes:
		return openapi.Kubernetes
	case unikornv1.ProviderOpenstack:
		return openapi.Openstack
	}

	return ""
}

func convert(in *unikornv1.Region) *openapi.RegionRead {
	out := &openapi.RegionRead{
		Metadata: conversion.ResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.RegionSpec{
			Type: convertRegionType(in.Spec.Provider),
		},
	}

	// Calculate any region specific configuration.
	if in.Spec.Provider == unikornv1.ProviderOpenstack {
		if in.Spec.Openstack.Network != nil && in.Spec.Openstack.Network.ProviderNetworks != nil {
			out.Spec.Features.PhysicalNetworks = true
		}
	}

	return out
}

func (c *Client) convertDetail(ctx context.Context, in *unikornv1.Region) (*openapi.RegionDetailRead, error) {
	out := &openapi.RegionDetailRead{
		Metadata: conversion.ResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.RegionDetailSpec{
			Type: convertRegionType(in.Spec.Provider),
		},
	}

	// Calculate any region specific configuration.
	switch in.Spec.Provider {
	case unikornv1.ProviderKubernetes:
		secret := &corev1.Secret{}

		if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: in.Spec.Kubernetes.KubeconfigSecret.Name}, secret); err != nil {
			return nil, err
		}

		kubeconfig, ok := secret.Data["kubeconfig"]
		if !ok {
			return nil, fmt.Errorf("%w: kubeconfig kye missing in region secret", ErrResource)
		}

		out.Spec.Kubernetes = &openapi.RegionDetailKubernetes{
			Kubeconfig: base64.RawURLEncoding.EncodeToString(kubeconfig),
		}

		if in.Spec.Kubernetes.DomainName != "" {
			out.Spec.Kubernetes.DomainName = &in.Spec.Kubernetes.DomainName
		}
	case unikornv1.ProviderOpenstack:
		if in.Spec.Openstack.Network != nil && in.Spec.Openstack.Network.ProviderNetworks != nil {
			out.Spec.Features.PhysicalNetworks = true
		}
	}

	return out, nil
}

func convertList(in *unikornv1.RegionList) openapi.Regions {
	out := make(openapi.Regions, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i])
	}

	return out
}

func (c *Client) List(ctx context.Context) (openapi.Regions, error) {
	regions := &unikornv1.RegionList{}

	if err := c.client.List(ctx, regions, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, err
	}

	return convertList(regions), nil
}

func (c *Client) GetDetail(ctx context.Context, regionID string) (*openapi.RegionDetailRead, error) {
	result := &unikornv1.Region{}

	fmt.Println("getting region", c.namespace, regionID)

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: regionID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to lookup region").WithError(err)
	}

	return c.convertDetail(ctx, result)
}

func convertGpuVendor(in types.GPUVendor) openapi.GpuVendor {
	switch in {
	case types.Nvidia:
		return openapi.NVIDIA
	case types.AMD:
		return openapi.AMD
	}

	return ""
}

func convertFlavor(in *types.Flavor) *openapi.Flavor {
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
			Vendor:        convertGpuVendor(in.GPU.Vendor),
			Model:         in.GPU.Model,
			Memory:        int(in.GPU.Memory.Value()) >> 30,
			PhysicalCount: in.GPU.PhysicalCount,
			LogicalCount:  in.GPU.LogicalCount,
		}
	}

	return out
}

func convertFlavors(in []types.Flavor) openapi.Flavors {
	out := make(openapi.Flavors, len(in))

	for i := range in {
		out[i] = *convertFlavor(&in[i])
	}

	return out
}

func (c *Client) ListFlavors(ctx context.Context, organizationID, regionID string) (openapi.Flavors, error) {
	provider, err := c.Provider(ctx, regionID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	result, err := provider.Flavors(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to list flavors").WithError(err)
	}

	// Apply ordering guarantees, ascending order with GPUs taking precedence over
	// CPUs and memory.
	slices.SortStableFunc(result, func(a, b types.Flavor) int {
		if v := cmp.Compare(a.GPUCount(), b.GPUCount()); v != 0 {
			return v
		}

		if v := cmp.Compare(a.CPUs, b.CPUs); v != 0 {
			return v
		}

		return cmp.Compare(a.Memory.Value(), b.Memory.Value())
	})

	return convertFlavors(result), nil
}

func convertImageVirtualization(in types.ImageVirtualization) openapi.ImageVirtualization {
	switch in {
	case types.Virtualized:
		return openapi.Virtualized
	case types.Baremetal:
		return openapi.Baremetal
	case types.Any:
		return openapi.Any
	}

	return ""
}

func convertOsKernel(in types.OsKernel) openapi.OsKernel {
	//nolint:gocritic
	switch in {
	case types.Linux:
		return openapi.Linux
	}

	return ""
}

func convertOsFamily(in types.OsFamily) openapi.OsFamily {
	switch in {
	case types.Debian:
		return openapi.Debian
	case types.Redhat:
		return openapi.Redhat
	}

	return ""
}

func convertOsDistro(in types.OsDistro) openapi.OsDistro {
	switch in {
	case types.Rocky:
		return openapi.Rocky
	case types.Ubuntu:
		return openapi.Ubuntu
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
			Vendor: convertGpuVendor(in.GPU.Vendor),
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

func (c *Client) ListImages(ctx context.Context, organizationID, regionID string) (openapi.Images, error) {
	provider, err := c.Provider(ctx, regionID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	result, err := provider.Images(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to list images").WithError(err)
	}

	// Apply ordering guarantees, ordered by name.
	slices.SortStableFunc(result, func(a, b types.Image) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertImages(result), nil
}

func convertExternalNetwork(in types.ExternalNetwork) openapi.ExternalNetwork {
	out := openapi.ExternalNetwork{
		Id:   in.ID,
		Name: in.Name,
	}

	return out
}

func convertExternalNetworks(in types.ExternalNetworks) openapi.ExternalNetworks {
	out := make(openapi.ExternalNetworks, len(in))

	for i := range in {
		out[i] = convertExternalNetwork(in[i])
	}

	return out
}

func (c *Client) ListExternalNetworks(ctx context.Context, regionID string) (openapi.ExternalNetworks, error) {
	provider, err := c.Provider(ctx, regionID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	result, err := provider.ListExternalNetworks(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to list external networks").WithError(err)
	}

	return convertExternalNetworks(result), nil
}
