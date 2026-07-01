//go:build integration
// +build integration

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

//nolint:revive,testpackage,gci // dot imports and package naming standard for Ginkgo, import grouping
package suites

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"
)

func skipUnlessServerInfrastructureRefConfigured() {
	if config.ServerInfrastructureRef == "" {
		Skip("infrastructureRef server tests require TEST_SERVER_INFRASTRUCTURE_REF")
	}
}

func testFlavorID() string {
	return config.ServerFlavorID
}

func testImageID() string {
	return config.ServerImageID
}

func expectServerInfrastructureRef(server *regionopenapi.ServerV2Read, infrastructureRef string) {
	Expect(server).NotTo(BeNil())
	Expect(server.Status.InfrastructureRef).NotTo(BeNil())
	Expect(*server.Status.InfrastructureRef).To(Equal(infrastructureRef))
}

var _ = Describe("Server Management", func() {
	Context("When creating a server", Ordered, func() {
		var networkID string

		BeforeAll(func() {
			api.SkipUnlessOpenStackRegion(regionClient, ctx, config)
			api.SkipUnlessInternalAPIConfigured(regionClient)
			api.SkipUnlessServerFixtureConfigured(config)

			networkReq := api.NewNetworkPayload(config.OrgID, config.ProjectID, config.RegionID).Build()
			network, cleanupNetwork := api.MustProvisionNetwork(regionClient, ctx, networkReq)
			DeferCleanup(cleanupNetwork)
			networkID = network.Metadata.Id
		})

		Describe("Given a provisioned network and available compute image", func() {
			It("should create the server with correct metadata and status", func() {
				createReq := api.NewServerPayload(networkID, testFlavorID(), testImageID()).Build()

				created, cleanup := api.MustCreateServer(regionClient, ctx, createReq)
				DeferCleanup(cleanup)

				serverID := created.Metadata.Id

				Expect(created.Metadata.Name).To(Equal(createReq.Metadata.Name))
				Expect(created.Metadata.OrganizationId).To(Equal(config.OrgID))
				Expect(created.Metadata.ProjectId).To(Equal(config.ProjectID))
				Expect(created.Metadata.CreatedBy).NotTo(BeNil())
				Expect(*created.Metadata.CreatedBy).To(Equal(config.InternalAPICN))
				Expect(created.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusPending))
				Expect(created.Spec.FlavorId).To(Equal(createReq.Spec.FlavorId))
				Expect(created.Spec.ImageId).To(Equal(createReq.Spec.ImageId))
				Expect(created.Status.RegionId).To(Equal(config.RegionID))
				Expect(created.Status.NetworkId).To(Equal(networkID))

				// List and single-resource GETs are served from the controller-runtime
				// cache, so a just-created server can briefly be absent or stale.
				Eventually(func(g Gomega) {
					list, err := regionClient.ListServers(ctx, config.OrgID, config.ProjectID, config.RegionID, networkID)
					g.Expect(err).NotTo(HaveOccurred())

					var found *regionopenapi.ServerV2Read
					for i := range list {
						if list[i].Metadata.Id == serverID {
							found = &list[i]
							break
						}
					}

					g.Expect(found).NotTo(BeNil(), "created server not found in list")
					g.Expect(found.Metadata.Name).To(Equal(createReq.Metadata.Name))

					got, err := regionClient.GetServer(ctx, serverID)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(got.Metadata.Id).To(Equal(serverID))
					g.Expect(got.Spec.FlavorId).To(Equal(createReq.Spec.FlavorId))
					g.Expect(got.Spec.ImageId).To(Equal(createReq.Spec.ImageId))
					g.Expect(got.Status.NetworkId).To(Equal(networkID))
				}).WithTimeout(5 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())
			})
		})
	})

	Context("When creating a server pinned to provider infrastructure", Ordered, func() {
		var networkID string

		BeforeAll(func() {
			api.SkipUnlessOpenStackRegion(regionClient, ctx, config)
			api.SkipUnlessInternalAPIConfigured(regionClient)
			api.SkipUnlessServerFixtureConfigured(config)
			skipUnlessServerInfrastructureRefConfigured()

			networkReq := api.NewNetworkPayload(config.OrgID, config.ProjectID, config.RegionID).Build()
			network, cleanupNetwork := api.MustProvisionNetwork(regionClient, ctx, networkReq)
			DeferCleanup(cleanupNetwork)
			networkID = network.Metadata.Id
		})

		Describe("Given an infrastructure reference", func() {
			It("should preserve the requested infrastructure reference", func() {
				infrastructureRef := config.ServerInfrastructureRef
				createReq := api.NewServerPayload(networkID, testFlavorID(), testImageID()).
					WithInfrastructureRef(infrastructureRef).
					Build()

				created, cleanup := api.MustCreateServer(regionClient, ctx, createReq)
				DeferCleanup(cleanup)

				serverID := created.Metadata.Id

				expectServerInfrastructureRef(created, infrastructureRef)

				list, err := regionClient.ListServers(ctx, config.OrgID, config.ProjectID, config.RegionID, networkID)
				Expect(err).NotTo(HaveOccurred())

				var found *regionopenapi.ServerV2Read
				for i := range list {
					if list[i].Metadata.Id == serverID {
						found = &list[i]
						break
					}
				}

				Expect(found).NotTo(BeNil(), "created pinned server not found in list")
				expectServerInfrastructureRef(found, infrastructureRef)

				got, err := regionClient.GetServer(ctx, serverID)
				Expect(err).NotTo(HaveOccurred())
				Expect(got.Metadata.Id).To(Equal(serverID))
				expectServerInfrastructureRef(got, infrastructureRef)
			})
		})
	})
})
