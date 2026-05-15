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
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"
)

func skipUnlessOpenStackRegion() {
	regions, err := regionClient.ListRegions(ctx, config.OrgID)
	Expect(err).NotTo(HaveOccurred(), "failed to resolve region provider")

	for _, region := range regions {
		if region.Metadata.Id != config.RegionID {
			continue
		}

		if region.Spec.Type != regionopenapi.RegionTypeOpenstack {
			Skip("server lifecycle tests require an OpenStack-backed region")
		}

		return
	}

	Skip("server lifecycle tests require TEST_REGION_ID to be visible")
}

func skipUnlessInternalAPIConfigured() {
	if !regionClient.InternalAPIConfigured() {
		Skip("server lifecycle tests require local internal API mTLS credentials")
	}
}

func skipUnlessServerFixtureConfigured() {
	if config.ServerFlavorID == "" || config.ServerImageID == "" {
		Skip("server lifecycle tests require TEST_SERVER_FLAVOR_ID and TEST_SERVER_IMAGE_ID")
	}
}

func testFlavorID() string {
	return config.ServerFlavorID
}

func testImageID() string {
	return config.ServerImageID
}

func waitForNetworkProvisioned(networkID string) {
	Eventually(func() coreapi.ResourceProvisioningStatus {
		network, err := regionClient.GetNetwork(ctx, networkID)
		if err != nil {
			GinkgoWriter.Printf("Error retrieving network %s: %v\n", networkID, err)
			return ""
		}

		return network.Metadata.ProvisioningStatus
	}).WithTimeout(2*time.Minute).
		WithPolling(5*time.Second).
		Should(Equal(coreapi.ResourceProvisioningStatusProvisioned),
			"network should be provisioned before server creation")
}

func waitForServerGone(serverID string) {
	Eventually(func() bool {
		_, err := regionClient.GetServer(ctx, serverID)
		return err != nil
	}).WithTimeout(5*time.Minute).
		WithPolling(5*time.Second).
		Should(BeTrue(), "server should disappear after deletion")
}

var _ = Describe("Server Management", func() {
	Context("When creating a server", Ordered, func() {
		var networkID string

		BeforeAll(func() {
			skipUnlessOpenStackRegion()
			skipUnlessInternalAPIConfigured()
			skipUnlessServerFixtureConfigured()

			networkReq := api.NewNetworkPayload(config.OrgID, config.ProjectID, config.RegionID).Build()
			network, err := regionClient.CreateNetwork(ctx, networkReq)
			Expect(err).NotTo(HaveOccurred(), "failed to create network fixture")
			Expect(network).NotTo(BeNil())

			networkID = network.Metadata.Id

			DeferCleanup(func() {
				if err := regionClient.DeleteNetwork(ctx, networkID); err != nil {
					GinkgoWriter.Printf("Warning: cleanup delete network %s: %v\n", networkID, err)
				}
			})

			waitForNetworkProvisioned(networkID)
		})

		Describe("Given a provisioned network and available compute image", func() {
			It("should create the server with correct metadata and status", func() {
				createReq := api.NewServerPayload(networkID, testFlavorID(), testImageID()).Build()

				created, err := regionClient.CreateServer(ctx, createReq)
				Expect(err).NotTo(HaveOccurred(), "failed to create server")
				Expect(created).NotTo(BeNil())
				Expect(created.Metadata.Id).NotTo(BeEmpty())

				serverID := created.Metadata.Id
				DeferCleanup(func() {
					err := regionClient.DeleteServer(ctx, serverID)
					if errors.Is(err, coreclient.ErrResourceNotFound) {
						return
					}
					if err != nil {
						GinkgoWriter.Printf("Warning: cleanup delete server %s: %v\n", serverID, err)
						return
					}
					waitForServerGone(serverID)
				})

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

				list, err := regionClient.ListServers(ctx, config.OrgID, config.ProjectID, config.RegionID, networkID)
				Expect(err).NotTo(HaveOccurred())

				var found *regionopenapi.ServerV2Read
				for i := range list {
					if list[i].Metadata.Id == serverID {
						found = &list[i]
						break
					}
				}

				Expect(found).NotTo(BeNil(), "created server not found in list")
				Expect(found.Metadata.Name).To(Equal(createReq.Metadata.Name))

				got, err := regionClient.GetServer(ctx, serverID)
				Expect(err).NotTo(HaveOccurred())
				Expect(got.Metadata.Id).To(Equal(serverID))
				Expect(got.Spec.FlavorId).To(Equal(createReq.Spec.FlavorId))
				Expect(got.Spec.ImageId).To(Equal(createReq.Spec.ImageId))
				Expect(got.Status.NetworkId).To(Equal(networkID))
			})
		})
	})
})
