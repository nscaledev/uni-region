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

var _ = Describe("LoadBalancer", func() {
	Context("When managing load balancers", func() {
		Describe("Given a valid v2 network", func() {
			var networkID string
			var lbID string

			BeforeEach(func() {
				networkReq := api.NewNetworkPayload(config.OrgID, config.ProjectID, config.RegionID).Build()
				network, err := regionClient.CreateNetwork(ctx, networkReq)
				Expect(err).NotTo(HaveOccurred(), "failed to create network fixture")
				Expect(network).NotTo(BeNil())
				networkID = network.Metadata.Id
				GinkgoWriter.Printf("Created network fixture: %s\n", networkID)

				DeferCleanup(func() {
					if lbID != "" {
						Expect(regionClient.DeleteLoadBalancer(ctx, lbID)).To(Succeed())
					}
					Expect(regionClient.DeleteNetwork(ctx, networkID)).To(Succeed())
				})
			})

			It("creates, lists, gets, updates, and deletes a load balancer", func() {
				createReq := api.NewLoadBalancerPayload(networkID).Build()
				created, err := regionClient.CreateLoadBalancer(ctx, createReq)
				Expect(err).NotTo(HaveOccurred(), "failed to create load balancer")
				Expect(created).NotTo(BeNil())
				lbID = created.Metadata.Id

				By("asserting create response body")
				Expect(created.Metadata.Id).NotTo(BeEmpty())
				Expect(created.Metadata.Name).To(Equal(createReq.Metadata.Name))
				Expect(created.Metadata.OrganizationId).To(Equal(config.OrgID))
				Expect(created.Metadata.ProjectId).To(Equal(config.ProjectID))
				Expect(created.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusPending))
				Expect(created.Status.RegionId).To(Equal(config.RegionID))
				Expect(created.Status.NetworkId).To(Equal(networkID))
				Expect(created.Status.VipAddress).To(BeNil())
				Expect(created.Status.PublicIP).To(BeNil())
				Expect(created.Spec.Listeners).To(HaveLen(1))
				Expect(created.Spec.Listeners[0].Name).To(Equal("http"))
				Expect(created.Spec.Listeners[0].Port).To(Equal(80))

				By("asserting list contains the created load balancer")
				list, err := regionClient.ListLoadBalancers(ctx, config.OrgID, config.ProjectID, config.RegionID)
				Expect(err).NotTo(HaveOccurred())
				var found *regionopenapi.LoadBalancerV2Read
				for i := range list {
					if list[i].Metadata.Id == lbID {
						found = &list[i]
						break
					}
				}
				Expect(found).NotTo(BeNil(), "created load balancer not found in list")
				Expect(found.Metadata.Name).To(Equal(createReq.Metadata.Name))

				By("asserting get returns the created load balancer")
				got, err := regionClient.GetLoadBalancer(ctx, lbID)
				Expect(err).NotTo(HaveOccurred())
				Expect(got.Metadata.Id).To(Equal(lbID))
				Expect(got.Status.NetworkId).To(Equal(networkID))

				By("updating mutable fields and asserting round-trip")
				updated := got
				updated.Spec.PublicIP = ptr.To(false)
				allowedCidrs := []string{"10.0.0.0/8"}
				members := []regionopenapi.LoadBalancerMemberV2{
					{Address: "10.0.1.10", Port: 8080},
				}
				updated.Spec.Listeners[0].AllowedCidrs = &allowedCidrs
				updated.Spec.Listeners[0].Pool.Members = members
				updateReq := regionopenapi.LoadBalancerV2Update{
					Metadata: coreapi.ResourceWriteMetadata{
						Name: updated.Metadata.Name,
					},
					Spec: updated.Spec,
				}
				putResp, err := regionClient.UpdateLoadBalancer(ctx, lbID, updateReq)
				Expect(err).NotTo(HaveOccurred())
				Expect(putResp.Spec.Listeners[0].AllowedCidrs).NotTo(BeNil())
				Expect(*putResp.Spec.Listeners[0].AllowedCidrs).To(Equal(allowedCidrs))
				Expect(putResp.Spec.Listeners[0].Pool.Members).To(Equal(members))

				roundTrip, err := regionClient.GetLoadBalancer(ctx, lbID)
				Expect(err).NotTo(HaveOccurred())
				Expect(*roundTrip.Spec.Listeners[0].AllowedCidrs).To(Equal(allowedCidrs))
				Expect(roundTrip.Spec.Listeners[0].Pool.Members).To(Equal(members))

				By("deleting the load balancer and confirming it disappears")
				Expect(regionClient.DeleteLoadBalancer(ctx, lbID)).To(Succeed())
				Eventually(func() bool {
					_, err := regionClient.GetLoadBalancer(ctx, lbID)
					return err != nil
				}).WithTimeout(30 * time.Second).WithPolling(1 * time.Second).Should(BeTrue())

				_, err = regionClient.GetLoadBalancer(ctx, lbID)
				Expect(err).To(HaveOccurred())
				lbID = "" // suppress cleanup delete — already gone

				// sanity: GET returns a non-2xx once gone
				path := regionClient.GetEndpoints().GetLoadBalancer(created.Metadata.Id)
				resp, _, err := regionClient.DoRegionRequest(ctx, http.MethodGet, path, nil, 0)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode).NotTo(Equal(http.StatusOK))
			})

			It("creates a load balancer with two listeners and asserts both survive round-trips", func() {
				twoListeners := []regionopenapi.LoadBalancerListenerV2{
					{
						Name:     "http",
						Protocol: regionopenapi.LoadBalancerListenerProtocolV2Tcp,
						Port:     80,
						Pool:     regionopenapi.LoadBalancerPoolV2{Members: []regionopenapi.LoadBalancerMemberV2{}},
					},
					{
						Name:     "http-alt",
						Protocol: regionopenapi.LoadBalancerListenerProtocolV2Tcp,
						Port:     8080,
						Pool:     regionopenapi.LoadBalancerPoolV2{Members: []regionopenapi.LoadBalancerMemberV2{}},
					},
				}
				createReq := api.NewLoadBalancerPayload(networkID).WithListeners(twoListeners).Build()
				created, err := regionClient.CreateLoadBalancer(ctx, createReq)
				Expect(err).NotTo(HaveOccurred(), "failed to create two-listener load balancer")
				Expect(created).NotTo(BeNil())
				lbID = created.Metadata.Id

				By("asserting both listeners are present on the create response")
				Expect(created.Spec.Listeners).To(HaveLen(2))
				Expect(created.Spec.Listeners[0].Port).To(Equal(80))
				Expect(created.Spec.Listeners[0].Protocol).To(Equal(regionopenapi.LoadBalancerListenerProtocolV2Tcp))
				Expect(created.Spec.Listeners[1].Port).To(Equal(8080))
				Expect(created.Spec.Listeners[1].Protocol).To(Equal(regionopenapi.LoadBalancerListenerProtocolV2Tcp))

				By("asserting GET returns both listeners")
				got, err := regionClient.GetLoadBalancer(ctx, lbID)
				Expect(err).NotTo(HaveOccurred())
				Expect(got.Spec.Listeners).To(HaveLen(2))

				By("updating pool members on both listeners and asserting round-trip persistence")
				membersHTTP := []regionopenapi.LoadBalancerMemberV2{
					{Address: "10.0.1.10", Port: 80},
				}
				membersAlt := []regionopenapi.LoadBalancerMemberV2{
					{Address: "10.0.1.11", Port: 8080},
				}
				got.Spec.Listeners[0].Pool.Members = membersHTTP
				got.Spec.Listeners[1].Pool.Members = membersAlt
				updateReq := regionopenapi.LoadBalancerV2Update{
					Metadata: coreapi.ResourceWriteMetadata{Name: got.Metadata.Name},
					Spec:     got.Spec,
				}
				putResp, err := regionClient.UpdateLoadBalancer(ctx, lbID, updateReq)
				Expect(err).NotTo(HaveOccurred())
				Expect(putResp.Spec.Listeners[0].Pool.Members).To(Equal(membersHTTP))
				Expect(putResp.Spec.Listeners[1].Pool.Members).To(Equal(membersAlt))

				roundTrip, err := regionClient.GetLoadBalancer(ctx, lbID)
				Expect(err).NotTo(HaveOccurred())
				Expect(roundTrip.Spec.Listeners).To(HaveLen(2))
				Expect(roundTrip.Spec.Listeners[0].Pool.Members).To(Equal(membersHTTP))
				Expect(roundTrip.Spec.Listeners[1].Pool.Members).To(Equal(membersAlt))

				By("deleting the two-listener load balancer and confirming removal")
				Expect(regionClient.DeleteLoadBalancer(ctx, lbID)).To(Succeed())
				Eventually(func() bool {
					_, err := regionClient.GetLoadBalancer(ctx, lbID)
					return err != nil
				}).WithTimeout(30 * time.Second).WithPolling(1 * time.Second).Should(BeTrue())
				lbID = "" // suppress cleanup delete — already gone
			})
		})
	})
})
