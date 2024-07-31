/*
Copyright 2024 the Unikorn Authors.

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

package providers

import (
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
)

// GPUVendor defines the GPU vendor.
type GPUVendor string

const (
	Nvidia GPUVendor = "NVIDIA"
	AMD    GPUVendor = "AMD"
)

// Flavor represents a machine type.
type Flavor struct {
	// ID must be an immutable ID, preferably a UUID.
	// If the provider doesn't have the concept of an ID, and the name
	// is immutable you can make one out of that.
	ID string
	// Name of the flavor.
	Name string
	// CPU count.
	CPUs int
	// CPUFamily tells you the CPU type.
	CPUFamily *string
	// Memory available.
	Memory *resource.Quantity
	// Disk available.
	Disk *resource.Quantity
	// GPU describes the GPU(s) if any are available to the flavor.
	GPU *GPU
	// Baremetal is a bare-metal flavor.
	Baremetal bool
}

type GPU struct {
	// Vendor is who makes the GPU, used to determine the drivers etc.
	Vendor GPUVendor
	// Model is the type of GPU.
	Model string
	// Memory is the amount of memory each GPU has.
	Memory *resource.Quantity
	// Count is the number of GPUs in the flavor.
	Count int
}

// FlavorList allows us to attach sort functions and the like.
type FlavorList []Flavor

type ImageVirtualization string

const (
	Virtualized ImageVirtualization = "virtualized"
	Baremetal   ImageVirtualization = "baremetal"
	Any         ImageVirtualization = "any"
)

// Image represents an operating system image.
type Image struct {
	// ID must be an immutable ID, preferably a UUID.
	// If the provider doesn't have the concept of an ID, and the name
	// is immutable you can make one out of that.
	ID string
	// Name of the image.
	Name string
	// Created is when the image was created.
	Created time.Time
	// Modified is when the image was modified.
	Modified time.Time
	// ImageVirtualization defines how the image can be used.
	Virtualization ImageVirtualization
	// KubernetesVersion is only populated if the image contains a pre-installed
	// version of Kubernetes, this acts as a cache and improves provisioning performance.
	// This is pretty much the only source of truth about Kubernetes versions at
	// present, so should be populated.  It must be a semver (starts with a vN.N.N).
	KubernetesVersion string
	// GPU is any GPU specific configuration for scheduling on a specific flavor type.
	GPU *ImageGPU
}

// ImageGPU defines image specific GPU compatibility information.
type ImageGPU struct {
	// Vendor is the vendor a GPU is compatible with.
	Vendor GPUVendor
	// Driver is the driver version string.
	Driver string
	// Models is a list of GPU models a driver is certified with.
	Models []string
}

// ImageList allows us to attach sort functions and the like.
type ImageList []Image

// ExternalNetwork represents an external network.
type ExternalNetwork struct {
	// ID is the provider specific network ID.
	ID string
	// Name is the network name.
	Name string
}

// ExternalNetworks is a list of provider networks.
type ExternalNetworks []ExternalNetwork
