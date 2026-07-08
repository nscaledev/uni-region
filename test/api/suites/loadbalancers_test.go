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

			// Reads are served from the controller-runtime cache, so the
			// load balancer create below can resolve the network reference
			// against a stale cache and 404. Await visibility first.
			api.WaitForNetworkVisible(regionClient, ctx, networkID)

			DeferCleanup(func() {
				if lbID != "" {
					if err := regionClient.DeleteLoadBalancer(ctx, lbID); err != nil && !errors.Is(err, coreclient.ErrResourceNotFound) {
						GinkgoWriter.Printf("Warning: cleanup delete load balancer %s: %v\n", lbID, err)
					}
					api.WaitForLoadBalancerGone(regionClient, ctx, lbID)
				}
				api.MustDeleteNetwork(regionClient, ctx, networkID)
			})
		})

		Describe("Given a backend member and publicIP=true", func() {
			members := []regionopenapi.LoadBalancerMemberV2{
				{Address: "10.0.1.10", Port: 8080},
			}
			var originalVIP *regionopenapi.Ipv4Address
			var deletedLBID string

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
				// List GETs are served from the controller-runtime cache, so a
				// just-created load balancer can briefly be absent from the list.
				Eventually(func(g Gomega) {
					list, err := regionClient.ListLoadBalancers(ctx, config.OrgID, config.ProjectID, config.RegionID)
					g.Expect(err).NotTo(HaveOccurred())

					var found *regionopenapi.LoadBalancerV2Read
					for i := range list {
						if list[i].Metadata.Id == lbID {
							found = &list[i]
							break
						}
					}
					g.Expect(found).NotTo(BeNil(), "created load balancer not found in list")
					g.Expect(found.Metadata.Name).To(Equal(createReq.Metadata.Name))
				}).WithTimeout(5 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())
			})

			It("can be retrieved by id", func() {
				// Single-resource GETs are served from the controller-runtime cache,
				// so an immediate GET after create can briefly miss the new object.
				Eventually(func(g Gomega) {
					got, err := regionClient.GetLoadBalancer(ctx, lbID)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(got.Metadata.Id).To(Equal(lbID))
					g.Expect(got.Status.NetworkId).To(Equal(networkID))
				}).WithTimeout(5 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())
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

				// The API server reads single-resource GETs through the controller-runtime cache,
				// so an immediate GET after PUT can briefly observe the pre-update object.
				Eventually(func(g Gomega) {
					roundTrip, err := regionClient.GetLoadBalancer(ctx, lbID)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(roundTrip.Spec.Listeners[0].AllowedCidrs).NotTo(BeNil())
					g.Expect(*roundTrip.Spec.Listeners[0].AllowedCidrs).To(Equal(allowedCidrs))
					g.Expect(roundTrip.Spec.Listeners[0].Pool.Members).To(Equal(updatedMembers))
				}).WithTimeout(5 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())
			})

			It("accepts an update toggling publicIP to false", func() {
				current, err := regionClient.GetLoadBalancer(ctx, lbID)
				Expect(err).NotTo(HaveOccurred())
				originalVIP = current.Status.VipAddress

				spec := current.Spec
				spec.PublicIP = ptr.To(false)

				putResp, err := regionClient.UpdateLoadBalancer(ctx, lbID, regionopenapi.LoadBalancerV2Update{
					Metadata: coreapi.ResourceWriteMetadata{Name: current.Metadata.Name},
					Spec:     spec,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(putResp.Spec.PublicIP).NotTo(BeNil())
				Expect(*putResp.Spec.PublicIP).To(BeFalse())
			})

			It("eventually clears status.publicIP and preserves the VIP after publicIP is toggled", func() {
				Eventually(func(g Gomega) *regionopenapi.Ipv4Address {
					got, err := regionClient.GetLoadBalancer(ctx, lbID)
					g.Expect(err).NotTo(HaveOccurred())
					return got.Status.PublicIP
				}).WithTimeout(5 * time.Minute).WithPolling(10 * time.Second).Should(BeNil())

				final, err := regionClient.GetLoadBalancer(ctx, lbID)
				Expect(err).NotTo(HaveOccurred())
				Expect(final.Status.VipAddress).To(Equal(originalVIP), "VIP must be preserved across publicIP toggle")
			})

			It("deletes the load balancer", func() {
				deletedLBID = lbID
				Expect(regionClient.DeleteLoadBalancer(ctx, lbID)).To(Succeed())
				api.WaitForLoadBalancerGone(regionClient, ctx, lbID)
				lbID = "" // suppress cleanup re-delete
			})

			It("is no longer accessible after deletion", func() {
				path := regionClient.GetEndpoints().GetLoadBalancer(deletedLBID)
				resp, _, err := regionClient.DoRegionRequest(ctx, http.MethodGet, path, nil, 0)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode).NotTo(Equal(http.StatusOK))
			})
		})
	})

	Context("When creating a UDP listener without idleTimeoutSeconds", Ordered, func() {
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

			// Reads are served from the controller-runtime cache, so the
			// load balancer create below can resolve the network reference
			// against a stale cache and 404. Await visibility first.
			api.WaitForNetworkVisible(regionClient, ctx, networkID)

			DeferCleanup(func() {
				if lbID != "" {
					if err := regionClient.DeleteLoadBalancer(ctx, lbID); err != nil && !errors.Is(err, coreclient.ErrResourceNotFound) {
						GinkgoWriter.Printf("Warning: cleanup delete load balancer %s: %v\n", lbID, err)
					}
					api.WaitForLoadBalancerGone(regionClient, ctx, lbID)
				}
				api.MustDeleteNetwork(regionClient, ctx, networkID)
			})
		})

		Describe("Given a UDP listener on port 53 with idleTimeoutSeconds omitted", func() {
			It("creates the load balancer and persists idleTimeoutSeconds as nil", func() {
				createReq := api.NewLoadBalancerPayload(networkID).
					WithListeners([]regionopenapi.LoadBalancerListenerV2{
						{
							Name:     "dns",
							Protocol: regionopenapi.LoadBalancerListenerProtocolV2Udp,
							Port:     53,
							Pool: regionopenapi.LoadBalancerPoolV2{
								Members: []regionopenapi.LoadBalancerMemberV2{
									{Address: "10.0.1.10", Port: 53},
								},
							},
						},
					}).Build()

				created, err := regionClient.CreateLoadBalancer(ctx, createReq)
				Expect(err).NotTo(HaveOccurred(), "failed to create UDP load balancer")
				Expect(created).NotTo(BeNil())
				lbID = created.Metadata.Id

				Expect(created.Spec.Listeners).To(HaveLen(1))
				Expect(created.Spec.Listeners[0].Name).To(Equal("dns"))
				Expect(created.Spec.Listeners[0].Protocol).To(Equal(regionopenapi.LoadBalancerListenerProtocolV2Udp))
				Expect(created.Spec.Listeners[0].Port).To(Equal(53))
				Expect(created.Spec.Listeners[0].IdleTimeoutSeconds).To(BeNil())

				roundTrip, err := regionClient.GetLoadBalancer(ctx, lbID)
				Expect(err).NotTo(HaveOccurred())
				Expect(roundTrip.Spec.Listeners[0].IdleTimeoutSeconds).To(BeNil())
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

			// Reads are served from the controller-runtime cache, so the
			// load balancer create below can resolve the network reference
			// against a stale cache and 404. Await visibility first.
			api.WaitForNetworkVisible(regionClient, ctx, networkID)

			DeferCleanup(func() {
				if lbID != "" {
					if err := regionClient.DeleteLoadBalancer(ctx, lbID); err != nil && !errors.Is(err, coreclient.ErrResourceNotFound) {
						GinkgoWriter.Printf("Warning: cleanup delete load balancer %s: %v\n", lbID, err)
					}
					api.WaitForLoadBalancerGone(regionClient, ctx, lbID)
				}
				api.MustDeleteNetwork(regionClient, ctx, networkID)
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

	Context("When accessing a load balancer that does not exist", func() {
		Describe("Given a non-existent load balancer ID", func() {
			It("should return not found on GET", func() {
				_, err := regionClient.GetLoadBalancer(ctx, "00000000-0000-0000-0000-000000000000")
				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
			})

			It("should return not found on DELETE", func() {
				err := regionClient.DeleteLoadBalancer(ctx, "00000000-0000-0000-0000-000000000000")
				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
			})
		})
	})

	Context("When creating a load balancer with an invalid request body", func() {
		Describe("Given an empty request body", func() {
			It("should reject the request", func() {
				path := regionClient.GetEndpoints().CreateLoadBalancer()
				resp, _, err := regionClient.DoRegionRequest(ctx, http.MethodPost, path, bytes.NewReader([]byte("")), 0)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
			})
		})
	})
})
