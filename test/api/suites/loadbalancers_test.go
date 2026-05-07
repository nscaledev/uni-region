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

var _ = Describe("LoadBalancer", func() {
	Context("When managing load balancer lifecycle", Ordered, func() {
		var (
			networkID string
			lbID      string
			createReq regionopenapi.LoadBalancerV2Create
		)

		BeforeAll(func() {
			networkReq := api.NewNetworkPayload(config.OrgID, config.ProjectID, config.RegionID).Build()
			network, err := regionClient.CreateNetwork(ctx, networkReq)
			Expect(err).NotTo(HaveOccurred(), "failed to create network fixture")
			Expect(network).NotTo(BeNil())
			networkID = network.Metadata.Id
			GinkgoWriter.Printf("Created network fixture: %s\n", networkID)

			DeferCleanup(func() {
				if lbID != "" {
					if err := regionClient.DeleteLoadBalancer(ctx, lbID); err != nil && !errors.Is(err, coreclient.ErrResourceNotFound) {
						GinkgoWriter.Printf("Warning: cleanup delete load balancer %s: %v\n", lbID, err)
					}
					api.WaitForLoadBalancerGone(regionClient, ctx, lbID)
				}
				if err := regionClient.DeleteNetwork(ctx, networkID); err != nil {
					GinkgoWriter.Printf("Warning: cleanup delete network %s: %v\n", networkID, err)
				}
			})
		})

		Describe("Given a backend member and publicIP=true", func() {
			members := []regionopenapi.LoadBalancerMemberV2{
				{Address: "10.0.1.10", Port: 8080},
			}

			It("creates a load balancer in Pending state", func() {
				createReq = api.NewLoadBalancerPayload(networkID).
					WithPublicIP(true).
					WithListeners([]regionopenapi.LoadBalancerListenerV2{
						{
							Name:     "http",
							Protocol: regionopenapi.LoadBalancerListenerProtocolV2Tcp,
							Port:     80,
							Pool: regionopenapi.LoadBalancerPoolV2{
								Members: members,
							},
						},
					}).Build()

				created, err := regionClient.CreateLoadBalancer(ctx, createReq)
				Expect(err).NotTo(HaveOccurred(), "failed to create load balancer")
				Expect(created).NotTo(BeNil())
				lbID = created.Metadata.Id

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
				Expect(created.Spec.Listeners[0].Pool.Members).To(Equal(members))
				Expect(created.Spec.PublicIP).NotTo(BeNil())
				Expect(*created.Spec.PublicIP).To(BeTrue())
			})

			It("appears in the load balancer list", func() {
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
			})

			It("can be retrieved by id", func() {
				got, err := regionClient.GetLoadBalancer(ctx, lbID)
				Expect(err).NotTo(HaveOccurred())
				Expect(got.Metadata.Id).To(Equal(lbID))
				Expect(got.Status.NetworkId).To(Equal(networkID))
			})

			It("eventually reports Provisioned with status.vipAddress and status.publicIP populated", func() {
				api.WaitForLoadBalancerProvisioned(regionClient, ctx, lbID)

				got, err := regionClient.GetLoadBalancer(ctx, lbID)
				Expect(err).NotTo(HaveOccurred())
				Expect(got.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
				Expect(got.Status.VipAddress).NotTo(BeNil())
				Expect(*got.Status.VipAddress).NotTo(BeEmpty())
				Expect(got.Status.PublicIP).NotTo(BeNil())
				Expect(*got.Status.PublicIP).NotTo(BeEmpty())
			})

			It("accepts updates to allowed CIDRs and pool members", func() {
				current, err := regionClient.GetLoadBalancer(ctx, lbID)
				Expect(err).NotTo(HaveOccurred())

				allowedCidrs := []string{"10.0.0.0/8"}
				updatedMembers := []regionopenapi.LoadBalancerMemberV2{
					{Address: "10.0.1.20", Port: 8080},
					{Address: "10.0.1.21", Port: 8080},
				}

				spec := current.Spec
				spec.Listeners[0].AllowedCidrs = &allowedCidrs
				spec.Listeners[0].Pool.Members = updatedMembers

				putResp, err := regionClient.UpdateLoadBalancer(ctx, lbID, regionopenapi.LoadBalancerV2Update{
					Metadata: coreapi.ResourceWriteMetadata{Name: current.Metadata.Name},
					Spec:     spec,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(putResp.Spec.Listeners[0].AllowedCidrs).NotTo(BeNil())
				Expect(*putResp.Spec.Listeners[0].AllowedCidrs).To(Equal(allowedCidrs))
				Expect(putResp.Spec.Listeners[0].Pool.Members).To(Equal(updatedMembers))

				roundTrip, err := regionClient.GetLoadBalancer(ctx, lbID)
				Expect(err).NotTo(HaveOccurred())
				Expect(roundTrip.Spec.Listeners[0].AllowedCidrs).NotTo(BeNil())
				Expect(*roundTrip.Spec.Listeners[0].AllowedCidrs).To(Equal(allowedCidrs))
				Expect(roundTrip.Spec.Listeners[0].Pool.Members).To(Equal(updatedMembers))
			})

			It("eventually clears status.publicIP when publicIP is toggled to false", func() {
				current, err := regionClient.GetLoadBalancer(ctx, lbID)
				Expect(err).NotTo(HaveOccurred())
				originalVIP := current.Status.VipAddress

				spec := current.Spec
				spec.PublicIP = ptr.To(false)

				putResp, err := regionClient.UpdateLoadBalancer(ctx, lbID, regionopenapi.LoadBalancerV2Update{
					Metadata: coreapi.ResourceWriteMetadata{Name: current.Metadata.Name},
					Spec:     spec,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(putResp.Spec.PublicIP).NotTo(BeNil())
				Expect(*putResp.Spec.PublicIP).To(BeFalse())

				Eventually(func(g Gomega) *regionopenapi.Ipv4Address {
					got, err := regionClient.GetLoadBalancer(ctx, lbID)
					g.Expect(err).NotTo(HaveOccurred())
					return got.Status.PublicIP
				}).WithTimeout(5 * time.Minute).WithPolling(10 * time.Second).Should(BeNil())

				final, err := regionClient.GetLoadBalancer(ctx, lbID)
				Expect(err).NotTo(HaveOccurred())
				Expect(final.Status.VipAddress).To(Equal(originalVIP), "VIP must be preserved across publicIP toggle")
			})

			It("deletes the load balancer and confirms it disappears", func() {
				Expect(regionClient.DeleteLoadBalancer(ctx, lbID)).To(Succeed())
				api.WaitForLoadBalancerGone(regionClient, ctx, lbID)

				path := regionClient.GetEndpoints().GetLoadBalancer(lbID)
				resp, _, err := regionClient.DoRegionRequest(ctx, http.MethodGet, path, nil, 0)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode).NotTo(Equal(http.StatusOK))

				lbID = "" // suppress cleanup re-delete
			})
		})
	})

	Context("When delete is invoked repeatedly during cleanup", Ordered, func() {
		var (
			networkID string
			lbID      string
		)

		BeforeAll(func() {
			networkReq := api.NewNetworkPayload(config.OrgID, config.ProjectID, config.RegionID).Build()
			network, err := regionClient.CreateNetwork(ctx, networkReq)
			Expect(err).NotTo(HaveOccurred(), "failed to create network fixture")
			Expect(network).NotTo(BeNil())
			networkID = network.Metadata.Id
			GinkgoWriter.Printf("Created network fixture: %s\n", networkID)

			DeferCleanup(func() {
				if lbID != "" {
					if err := regionClient.DeleteLoadBalancer(ctx, lbID); err != nil && !errors.Is(err, coreclient.ErrResourceNotFound) {
						GinkgoWriter.Printf("Warning: cleanup delete load balancer %s: %v\n", lbID, err)
					}
					api.WaitForLoadBalancerGone(regionClient, ctx, lbID)
				}
				if err := regionClient.DeleteNetwork(ctx, networkID); err != nil {
					GinkgoWriter.Printf("Warning: cleanup delete network %s: %v\n", networkID, err)
				}
			})
		})

		Describe("Given a provisioned load balancer", func() {
			It("creates and reaches Provisioned", func() {
				req := api.NewLoadBalancerPayload(networkID).Build()
				created, err := regionClient.CreateLoadBalancer(ctx, req)
				Expect(err).NotTo(HaveOccurred())
				Expect(created).NotTo(BeNil())
				lbID = created.Metadata.Id

				api.WaitForLoadBalancerProvisioned(regionClient, ctx, lbID)
			})

			It("acknowledges the first delete", func() {
				Expect(regionClient.DeleteLoadBalancer(ctx, lbID)).To(Succeed())
			})

			It("treats an immediate second delete as idempotent", func() {
				path := regionClient.GetEndpoints().DeleteLoadBalancer(lbID)
				resp, _, err := regionClient.DoRegionRequest(ctx, http.MethodDelete, path, nil, 0)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode).To(BeElementOf(http.StatusAccepted, http.StatusNotFound),
					"second delete should return 202 or 404, got: %d", resp.StatusCode)
			})

			It("treats subsequent retries as idempotent until the load balancer is gone", func() {
				path := regionClient.GetEndpoints().DeleteLoadBalancer(lbID)
				Consistently(func() int {
					resp, _, err := regionClient.DoRegionRequest(ctx, http.MethodDelete, path, nil, 0)
					if err != nil {
						return -1
					}
					return resp.StatusCode
				}).WithTimeout(15*time.Second).WithPolling(1*time.Second).
					Should(BeElementOf(http.StatusAccepted, http.StatusNotFound),
						"delete must remain idempotent across in-progress cleanup")

				api.WaitForLoadBalancerGone(regionClient, ctx, lbID)
				lbID = "" // suppress cleanup re-delete
			})
		})
	})
})
