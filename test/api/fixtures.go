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

//nolint:revive,staticcheck // dot imports are standard for Ginkgo/Gomega test code
package api

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"

	"k8s.io/utils/ptr"
)

func uniqueName(prefix string) string {
	return fmt.Sprintf("ginkgo-test-%s-%s", prefix, uuid.NewString()[:8])
}

// ImagePayloadBuilder builds ImageCreate payloads for testing.
type ImagePayloadBuilder struct {
	image regionopenapi.ImageCreate
}

// NewImagePayload creates a builder with sensible defaults.
func NewImagePayload() *ImagePayloadBuilder {
	return &ImagePayloadBuilder{
		image: regionopenapi.ImageCreate{
			Metadata: coreapi.ResourceWriteMetadata{
				Name: uniqueName("image"),
			},
			Spec: regionopenapi.ImageCreateSpec{
				Architecture: regionopenapi.ArchitectureX8664,
				Os: regionopenapi.ImageOS{
					Codename: ptr.To("noble"),
					Distro:   "ubuntu",
					Family:   "debian",
					Kernel:   regionopenapi.OsKernelLinux,
					Version:  "23.04",
				},
				Virtualization: regionopenapi.ImageVirtualizationVirtualized,
			},
		},
	}
}

// WithName overrides the image name.
func (b *ImagePayloadBuilder) WithName(name string) *ImagePayloadBuilder {
	b.image.Metadata.Name = name
	return b
}

// WithArchitecture overrides the CPU architecture.
func (b *ImagePayloadBuilder) WithArchitecture(a regionopenapi.Architecture) *ImagePayloadBuilder {
	b.image.Spec.Architecture = a
	return b
}

// WithURI overrides the image source URI.
func (b *ImagePayloadBuilder) WithURI(uri string) *ImagePayloadBuilder {
	b.image.Spec.Uri = uri
	return b
}

// WithVirtualization overrides the virtualization type.
func (b *ImagePayloadBuilder) WithVirtualization(v regionopenapi.ImageVirtualization) *ImagePayloadBuilder {
	b.image.Spec.Virtualization = v
	return b
}

// WithOSCodename overrides the OS codename (e.g. "noble").
func (b *ImagePayloadBuilder) WithOSCodename(codename string) *ImagePayloadBuilder {
	b.image.Spec.Os.Codename = ptr.To(codename)
	return b
}

// WithOSDistro overrides the OS distribution.
func (b *ImagePayloadBuilder) WithOSDistro(distro regionopenapi.OsDistro) *ImagePayloadBuilder {
	b.image.Spec.Os.Distro = distro
	return b
}

// WithOSFamily overrides the OS family.
func (b *ImagePayloadBuilder) WithOSFamily(family regionopenapi.OsFamily) *ImagePayloadBuilder {
	b.image.Spec.Os.Family = family
	return b
}

// WithOSKernel overrides the OS kernel type.
func (b *ImagePayloadBuilder) WithOSKernel(kernel regionopenapi.OsKernel) *ImagePayloadBuilder {
	b.image.Spec.Os.Kernel = kernel
	return b
}

// WithOSVersion overrides the OS version string.
func (b *ImagePayloadBuilder) WithOSVersion(version string) *ImagePayloadBuilder {
	b.image.Spec.Os.Version = version
	return b
}

// Build returns the typed ImageCreate struct.
func (b *ImagePayloadBuilder) Build() regionopenapi.ImageCreate {
	return b.image
}

// NetworkPayloadBuilder builds NetworkV2Create payloads for testing.
type NetworkPayloadBuilder struct {
	network regionopenapi.NetworkV2Create
}

// NewNetworkPayload creates a builder with sensible defaults for a project-scoped v2 network.
func NewNetworkPayload(orgID, projectID, regionID string) *NetworkPayloadBuilder {
	return &NetworkPayloadBuilder{
		network: regionopenapi.NetworkV2Create{
			Metadata: coreapi.ResourceWriteMetadata{
				Name: uniqueName("network"),
			},
			Spec: regionopenapi.NetworkV2CreateSpec{
				OrganizationId: orgID,
				ProjectId:      projectID,
				RegionId:       regionID,
				Prefix:         "10.0.0.0/16",
				DnsNameservers: []regionopenapi.Ipv4Address{"8.8.8.8"},
			},
		},
	}
}

// WithName overrides the network name.
func (b *NetworkPayloadBuilder) WithName(name string) *NetworkPayloadBuilder {
	b.network.Metadata.Name = name
	return b
}

// Build returns the typed NetworkV2Create struct.
func (b *NetworkPayloadBuilder) Build() regionopenapi.NetworkV2Create {
	return b.network
}

// LoadBalancerPayloadBuilder builds LoadBalancerV2Create payloads for testing.
type LoadBalancerPayloadBuilder struct {
	lb regionopenapi.LoadBalancerV2Create
}

// NewLoadBalancerPayload creates a builder with a single TCP listener and empty
// pool members, wired to the given network.
func NewLoadBalancerPayload(networkID string) *LoadBalancerPayloadBuilder {
	return &LoadBalancerPayloadBuilder{
		lb: regionopenapi.LoadBalancerV2Create{
			Metadata: coreapi.ResourceWriteMetadata{
				Name: uniqueName("lb"),
			},
			Spec: regionopenapi.LoadBalancerV2CreateSpec{
				NetworkId: networkID,
				Listeners: []regionopenapi.LoadBalancerListenerV2{
					{
						Name:     "http",
						Protocol: regionopenapi.LoadBalancerListenerProtocolV2("tcp"),
						Port:     80,
						Pool: regionopenapi.LoadBalancerPoolV2{
							Members: []regionopenapi.LoadBalancerMemberV2{},
						},
					},
				},
			},
		},
	}
}

// WithName overrides the load balancer name.
func (b *LoadBalancerPayloadBuilder) WithName(name string) *LoadBalancerPayloadBuilder {
	b.lb.Metadata.Name = name
	return b
}

// WithPublicIP sets whether a public IP should be allocated.
func (b *LoadBalancerPayloadBuilder) WithPublicIP(publicIP bool) *LoadBalancerPayloadBuilder {
	b.lb.Spec.PublicIP = ptr.To(publicIP)
	return b
}

// WithListeners overrides the listener list.
func (b *LoadBalancerPayloadBuilder) WithListeners(listeners []regionopenapi.LoadBalancerListenerV2) *LoadBalancerPayloadBuilder {
	b.lb.Spec.Listeners = listeners
	return b
}

// Build returns the typed LoadBalancerV2Create struct.
func (b *LoadBalancerPayloadBuilder) Build() regionopenapi.LoadBalancerV2Create {
	return b.lb
}

// WaitForImageReady polls until the image appears in the region with state ready.
// Uses a 1-hour timeout to accommodate image download and import times.
func WaitForImageReady(c *APIClient, ctx context.Context, config *TestConfig, imageID string) {
	GinkgoWriter.Printf("Waiting for image %s to be ready\n", imageID)

	Eventually(func() bool {
		images, err := c.ListImages(ctx, config.OrgID, config.RegionID)
		Expect(err).NotTo(HaveOccurred())

		for _, image := range images {
			if image.Metadata.Id == imageID {
				GinkgoWriter.Printf("Image %s state: %s\n", imageID, image.Status.State)
				return image.Status.State == regionopenapi.ImageStateReady
			}
		}

		GinkgoWriter.Printf("Image %s not yet visible in list\n", imageID)

		return false
	}).WithTimeout(time.Hour).WithPolling(15 * time.Second).Should(BeTrue())
}
