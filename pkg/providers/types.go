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
	Nvidia GPUVendor = "nvidia"
	AMD    GPUVendor = "amd"
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
	// Memory available.
	Memory *resource.Quantity
	// Disk available.
	Disk *resource.Quantity
	// GPU count.
	GPUs int
	// GPUVendor is who makes the GPU, used to determine the drivers etc.
	GPUVendor GPUVendor
	// BareMetal is a bare-metal flavor.
	BareMetal bool
}

// FlavorList allows us to attach sort functions and the like.
type FlavorList []Flavor

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
	// KubernetesVersion is only populated if the image contains a pre-installed
	// version of Kubernetes, this acts as a cache and improves provisioning performance.
	// This is pretty much the only source of truth about Kubernetes versions at
	// present, so should be populated.  It must be a semver (starts with a vN.N.N).
	KubernetesVersion string
}

// ImageList allows us to attach sort functions and the like.
type ImageList []Image

// ClusterInfo is required metadata when using the identity APIs to allow
// tracking of ownership information.
type ClusterInfo struct {
	// OrganizationID defines which organization this belings to.
	OrganizationID string
	// ProjectID defines which project this belongs to.
	ProjectID string
	// ClusterID defines which cluster this belongs to.
	ClusterID string
}

// ProviderType defines the provider to the client, while this is implicit,
// as you had to select a region in the first instance, it's handy to refer to
// to perform provider specific configuration.
type ProviderType string

const (
	ProviderTypeOpenStack ProviderType = "openstack"
)

// OpenStackCloudCredentials define OpenStack specific identity information
// which is usually in the form of a cloud config for most uses.
type OpenStackCloudCredentials struct {
	Cloud       string
	CloudConfig []byte
}

// OpenStackCloudState is used to propagate pertinent inforamtion up to the client
// which is especially relevant for piecing together API logs and provider logs.
type OpenStackCloudState struct {
	// UserID is the unique user ID.
	UserID string
	// ProjectID is the unique project ID.
	ProjectID string
}

// OpenStackCloudConfig bundles together various OpenStack specific state.
type OpenStackCloudConfig struct {
	// Credentials contain login data, bound to a user and project.
	Credentials *OpenStackCloudCredentials
	// State holds other pertinent metadata.
	State *OpenStackCloudState
}

// CloudConfig is a top level provider "agnostic" type to be passed to the HTTP handler.
type CloudConfig struct {
	// Type defines the provider type.
	Type ProviderType
	// OpenStack is populated when the type is "openstack"
	OpenStack *OpenStackCloudConfig
}

// ExternalNetwork represents an external network.
type ExternalNetwork struct {
	// ID is the provider specific netwokr ID.
	ID string
	// Name is the netwokr name.
	Name string
}

// ExternalNetworks is a list of provider networks.
type ExternalNetworks []ExternalNetwork
