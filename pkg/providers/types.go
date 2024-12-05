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
	// PhysicalCount is the number of physical cards in the flavor.
	// This is primarily for end users, so it's not confusing.
	PhysicalCount int
	// LogicalCount is the number of logical GPUs e.g. an AMD MI250 is 2 MI200s.
	// This is primarily for scheduling e.g. autoscaling.
	LogicalCount int
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
	// GPU is any GPU specific configuration for scheduling on a specific flavor type.
	GPU *ImageGPU
	// OS is the operating system specification.
	OS ImageOS
	// Packages is a list of pre-installed packages and its versions. Versions must be a semver (starts with a vN.N.N)
	Packages *ImagePackages
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

// OsKernel represents the kernel type.
type OsKernel string

const (
	Linux OsKernel = "linux"
)

// OsFamily A family of operating systems.  This typically defines the package format.
type OsFamily string

const (
	Debian OsFamily = "debian"
	Redhat OsFamily = "redhat"
)

// OsDistro A distribution name.
type OsDistro string

const (
	Rocky  OsDistro = "rocky"
	Ubuntu OsDistro = "ubuntu"
)

// ImageOS defines the operating system of an image.
type ImageOS struct {
	// Kernel is the kernel type of the OS.
	Kernel OsKernel
	// Family is the family of the OS.
	Family OsFamily
	// Distro is the distribution of the OS.
	Distro OsDistro
	// Variant is the variant of the OS.
	Variant *string
	// Codename is the codename of the OS.
	Codename *string
	// Version is the version of the OS.
	Version string
}

// ImagePackages is a map of pre-installed package names to versions. Versions must be a semver (starts with a vN.N.N)
type ImagePackages map[string]string

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
