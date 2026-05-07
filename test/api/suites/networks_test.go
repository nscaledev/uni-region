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
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/utils/ptr"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"
)

var _ = Describe("Network Management", func() {
	Context("When managing the network lifecycle", Ordered, func() {
		var networkID string
		var networkName string
		var networkPrefix string
		var deletedNetworkID string

		Describe("Given valid organization and project credentials", func() {
			It("should provision a network with correct metadata and prefix", func() {
				createReq := api.NewNetworkPayload(config.OrgID, config.ProjectID, config.RegionID).Build()

				created, err := regionClient.CreateNetwork(ctx, createReq)
				Expect(err).NotTo(HaveOccurred(), "failed to create network")
				Expect(created).NotTo(BeNil())

				Expect(created.Metadata.Id).NotTo(BeEmpty())
				Expect(created.Metadata.Name).To(Equal(createReq.Metadata.Name))
				Expect(created.Metadata.OrganizationId).To(Equal(config.OrgID))
				Expect(created.Metadata.ProjectId).To(Equal(config.ProjectID))
				Expect(created.Metadata.ProvisioningStatus).NotTo(BeEmpty())
				Expect(created.Status.RegionId).To(Equal(config.RegionID))
				Expect(created.Status.Prefix).To(Equal(createReq.Spec.Prefix))

				networkID = created.Metadata.Id
				networkName = created.Metadata.Name
				networkPrefix = created.Status.Prefix

				GinkgoWriter.Printf("Created network: %s (%s)\n", networkName, networkID)
			})
		})

		Describe("Given an existing network", func() {
			It("should appear in the project network list", func() {
				if networkID == "" {
					Skip("No network ID available - create step may have been skipped or failed")
				}

				list, err := regionClient.ListNetworks(ctx, config.OrgID, config.ProjectID, config.RegionID)
				Expect(err).NotTo(HaveOccurred())

				var found *regionopenapi.NetworkV2Read
				for i := range list {
					if list[i].Metadata.Id == networkID {
						found = &list[i]
						break
					}
				}

				Expect(found).NotTo(BeNil(), "created network not found in list")
				Expect(found.Metadata.Name).To(Equal(networkName))
				Expect(found.Metadata.OrganizationId).To(Equal(config.OrgID))
				Expect(found.Metadata.ProjectId).To(Equal(config.ProjectID))
			})

			It("should reach provisioned state and be retrievable by ID", func() {
				if networkID == "" {
					Skip("No network ID available - create step may have been skipped or failed")
				}

				var got *regionopenapi.NetworkV2Read

				Eventually(func() coreapi.ResourceProvisioningStatus {
					var err error
					got, err = regionClient.GetNetwork(ctx, networkID)
					if err != nil {
						return ""
					}
					return got.Metadata.ProvisioningStatus
				}).WithTimeout(2*time.Minute).
					WithPolling(5*time.Second).
					Should(Equal(coreapi.ResourceProvisioningStatusProvisioned),
						"network should reach provisioned state before update")

				Expect(got.Metadata.Id).To(Equal(networkID))
				Expect(got.Metadata.Name).To(Equal(networkName))
				Expect(got.Metadata.OrganizationId).To(Equal(config.OrgID))
				Expect(got.Metadata.ProjectId).To(Equal(config.ProjectID))
				Expect(got.Status.RegionId).To(Equal(config.RegionID))
			})

			It("should reflect updated name and description while preserving the prefix", func() {
				if networkID == "" {
					Skip("No network ID available - create step may have been skipped or failed")
				}

				got, err := regionClient.GetNetwork(ctx, networkID)
				Expect(err).NotTo(HaveOccurred())

				updatedName := networkName + "-upd"
				updateReq := regionopenapi.NetworkV2Update{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        updatedName,
						Description: ptr.To("updated description"),
					},
					Spec: regionopenapi.NetworkV2Spec{
						DnsNameservers: got.Spec.DnsNameservers,
					},
				}

				putResp, err := regionClient.UpdateNetwork(ctx, networkID, updateReq)
				Expect(err).NotTo(HaveOccurred())
				Expect(putResp.Metadata.Name).To(Equal(updatedName))
				Expect(putResp.Metadata.Description).NotTo(BeNil())
				Expect(*putResp.Metadata.Description).To(Equal("updated description"))

				roundTrip, err := regionClient.GetNetwork(ctx, networkID)
				Expect(err).NotTo(HaveOccurred())
				Expect(roundTrip.Metadata.Name).To(Equal(updatedName))
				Expect(roundTrip.Metadata.Description).NotTo(BeNil())
				Expect(*roundTrip.Metadata.Description).To(Equal("updated description"))
				Expect(roundTrip.Status.Prefix).To(Equal(networkPrefix))

				networkName = updatedName
			})
		})

		Describe("Given the network is deleted", func() {
			It("should succeed", func() {
				if networkID == "" {
					Skip("No network ID available - create step may have been skipped or failed")
				}

				Expect(regionClient.DeleteNetwork(ctx, networkID)).To(Succeed())

				GinkgoWriter.Printf("Deleted network: %s\n", networkID)
				deletedNetworkID = networkID
				networkID = "" // suppress AfterAll cleanup — already deleted
			})

			It("should return 404 on subsequent reads", func() {
				if deletedNetworkID == "" {
					Skip("No deleted network ID available - delete step may have been skipped or failed")
				}

				Eventually(func() bool {
					_, err := regionClient.GetNetwork(ctx, deletedNetworkID)
					return err != nil
				}).WithTimeout(30 * time.Second).WithPolling(1 * time.Second).Should(BeTrue())

				path := regionClient.GetEndpoints().GetNetwork(deletedNetworkID)
				resp, _, err := regionClient.DoRegionRequest(ctx, http.MethodGet, path, nil, 0)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusNotFound))

				GinkgoWriter.Printf("Confirmed network deleted: %s\n", deletedNetworkID)
			})
		})

		AfterAll(func() {
			if networkID != "" {
				GinkgoWriter.Printf("Cleaning up network: %s\n", networkID)
				Expect(regionClient.DeleteNetwork(ctx, networkID)).To(Succeed())
			}
		})
	})
})
