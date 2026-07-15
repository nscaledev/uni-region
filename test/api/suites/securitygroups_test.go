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
	"bytes"
	"errors"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/utils/ptr"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"
)

var _ = Describe("SecurityGroup", func() {
	Context("When managing security groups", Ordered, func() {
		var networkID string
		var sgID string
		var createReq regionopenapi.SecurityGroupV2Create

		BeforeAll(func() {
			network, err := regionClient.CreateNetwork(ctx, api.NewNetworkPayload(config.OrgID, config.ProjectID, config.RegionID).Build())
			Expect(err).NotTo(HaveOccurred(), "failed to create network fixture")
			networkID = network.Metadata.Id
			DeferCleanup(func() {
				api.MustDeleteNetwork(regionClient, ctx, networkID)
			})
			GinkgoWriter.Printf("Created network fixture: %s\n", networkID)

			// Reads are served from the controller-runtime cache, so the
			// security group create below can resolve the network reference
			// against a stale cache and 404. Await visibility first.
			api.WaitForNetworkVisible(regionClient, ctx, networkID)

			createReq = api.NewSecurityGroupPayload(networkID).Build()
			created, err := regionClient.CreateSecurityGroup(ctx, createReq)
			Expect(err).NotTo(HaveOccurred(), "failed to create security group fixture")
			sgID = created.Metadata.Id
			DeferCleanup(func() {
				if sgID == "" {
					return
				}
				GinkgoWriter.Printf("Cleaning up security group: %s\n", sgID)
				if err := regionClient.DeleteSecurityGroup(ctx, sgID); err != nil && !errors.Is(err, coreclient.ErrResourceNotFound) {
					GinkgoWriter.Printf("Warning: cleanup delete security group %s: %v\n", sgID, err)
				}
			})
			GinkgoWriter.Printf("Created security group: %s (%s)\n", created.Metadata.Name, sgID)
		})

		Describe("Given a network fixture and valid configuration", func() {
			var deletedSGID string

			It("should create a security group with correct response fields", func() {
				Expect(sgID).NotTo(BeEmpty())
				Expect(createReq.Metadata.Name).NotTo(BeEmpty())

				// Single-resource GETs are served from the controller-runtime cache,
				// so an immediate GET after create can briefly miss the new object.
				Eventually(func(g Gomega) {
					got, err := regionClient.GetSecurityGroup(ctx, sgID)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(got.Metadata.Id).To(Equal(sgID))
					g.Expect(got.Metadata.Name).To(Equal(createReq.Metadata.Name))
					g.Expect(got.Metadata.OrganizationId).To(Equal(config.OrgID))
					g.Expect(got.Metadata.ProjectId).To(Equal(config.ProjectID))
					g.Expect(got.Status.RegionId).To(Equal(config.RegionID))
					g.Expect(got.Status.NetworkId).To(Equal(networkID))
					g.Expect(got.Spec.Rules).To(HaveLen(1))
					g.Expect(got.Spec.Rules[0].Direction).To(Equal(regionopenapi.NetworkDirectionIngress))
					g.Expect(got.Spec.Rules[0].Protocol).To(Equal(regionopenapi.NetworkProtocolTcp))
					g.Expect(got.Spec.Rules[0].Port).To(Equal(ptr.To(22)))
				}).WithTimeout(5 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())
			})

			It("should appear in the list filtered by org, project and region", func() {
				// List GETs are served from the controller-runtime cache, so a
				// just-created security group can briefly be absent from the list.
				Eventually(func(g Gomega) {
					list, err := regionClient.ListSecurityGroups(ctx, config.OrgID, config.ProjectID, config.RegionID)
					g.Expect(err).NotTo(HaveOccurred())

					var found *regionopenapi.SecurityGroupV2Read
					for i := range list {
						if list[i].Metadata.Id == sgID {
							found = &list[i]
							break
						}
					}

					g.Expect(found).NotTo(BeNil(), "created security group %s not found in list", sgID)
					g.Expect(found.Metadata.Name).To(Equal(createReq.Metadata.Name))
					g.Expect(found.Status.NetworkId).To(Equal(networkID))
					GinkgoWriter.Printf("Found security group in list: %s\n", sgID)
				}).WithTimeout(5 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())
			})

			It("should update rules and verify the change persists on re-GET", func() {
				updatedPort := 443
				updateReq := regionopenapi.SecurityGroupV2Update{
					Metadata: coreapi.ResourceWriteMetadata{
						Name: createReq.Metadata.Name,
					},
					Spec: regionopenapi.SecurityGroupV2Spec{
						Rules: regionopenapi.SecurityGroupRuleV2List{
							{
								Direction: regionopenapi.NetworkDirectionIngress,
								Protocol:  regionopenapi.NetworkProtocolTcp,
								Port:      &updatedPort,
							},
							{
								Direction: regionopenapi.NetworkDirectionEgress,
								Protocol:  regionopenapi.NetworkProtocolAny,
							},
						},
					},
				}

				updated, err := regionClient.UpdateSecurityGroup(ctx, sgID, updateReq)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated.Spec.Rules).To(HaveLen(2))

				Eventually(func(g Gomega) {
					roundTrip, err := regionClient.GetSecurityGroup(ctx, sgID)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(roundTrip.Spec.Rules).To(HaveLen(2))
					g.Expect(roundTrip.Spec.Rules[0].Port).To(Equal(ptr.To(443)))
				}).WithTimeout(30 * time.Second).
					WithPolling(1 * time.Second).
					Should(Succeed())
				GinkgoWriter.Printf("Updated security group rules: %s\n", sgID)
			})

			It("should delete the security group", func() {
				deletedSGID = sgID
				Expect(regionClient.DeleteSecurityGroup(ctx, deletedSGID)).To(Succeed())
				sgID = "" // suppress DeferCleanup — already deleted
				GinkgoWriter.Printf("Deleted security group: %s\n", deletedSGID)
			})

			It("should not be found after deletion", func() {
				Eventually(func() error {
					_, err := regionClient.GetSecurityGroup(ctx, deletedSGID)
					return err
				}).WithTimeout(30*time.Second).
					WithPolling(2*time.Second).
					Should(And(HaveOccurred(), MatchError(coreclient.ErrResourceNotFound)),
						"deleted security group should eventually return not found")

				GinkgoWriter.Printf("Confirmed security group deleted: %s\n", deletedSGID)
			})
		})
	})

	Context("When getting a non-existent security group", func() {
		Describe("Given a non-existent security group ID", func() {
			It("should return not found", func() {
				_, err := regionClient.GetSecurityGroup(ctx, "00000000-0000-0000-0000-000000000000")
				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
			})
		})
	})

	Context("When creating a security group with an invalid request body", func() {
		Describe("Given an empty request body", func() {
			It("should reject the request", func() {
				path := regionClient.GetEndpoints().CreateSecurityGroup()
				resp, _, err := regionClient.DoRegionRequest(ctx, http.MethodPost, path, bytes.NewReader([]byte("")), 0)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
			})
		})
	})
})
