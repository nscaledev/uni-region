//go:build e2e
// +build e2e

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

const providerCreateGateConditionType = "example.unikorn-cloud.org/pre-create-ready"

func eventuallyProviderCreateGateServerProvisioned(serverID string) {
	Eventually(func(g Gomega) {
		got, err := regionClient.GetServer(ctx, serverID)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(got.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
		g.Expect(got.Status.PowerState).NotTo(BeNil())
		g.Expect(*got.Status.PowerState).To(Equal(regionopenapi.InstanceLifecyclePhaseRunning))
		g.Expect(got.Status.PrivateIP).NotTo(BeNil())
	}).WithTimeout(20*time.Minute).
		WithPolling(10*time.Second).
		Should(Succeed(), "provider create should run after the gate is satisfied")
}

var _ = Describe("Server provider-create gates", func() {
	Context("When creating a server with a provider-create gate", Ordered, func() {
		var networkID string
		var flavorID string
		var imageID string

		BeforeAll(func() {
			api.SkipUnlessOpenStackRegion(regionClient, ctx, config)
			api.SkipUnlessInternalAPIConfigured(regionClient)
			api.SkipUnlessServerFixtureConfigured(config)
			flavorID = config.ServerFlavorID
			imageID = config.ServerImageID

			networkReq := api.NewNetworkPayload(config.OrgID, config.ProjectID, config.RegionID).Build()
			network := api.MustProvisionNetwork(regionClient, ctx, networkReq)
			networkID = network.Metadata.Id
		})

		Describe("Given an unsatisfied provider-create gate", func() {
			It("holds provider create until the gate is satisfied", Label("slow"), func() {
				createReq := api.NewServerPayload(networkID, flavorID, imageID).
					WithProviderCreateGate(providerCreateGateConditionType).
					Build()

				created, cleanup := api.MustCreateServer(regionClient, ctx, createReq)
				DeferCleanup(cleanup)

				serverID := created.Metadata.Id

				Expect(created.Status.RemainingProviderCreateGates).NotTo(BeNil())
				Expect(*created.Status.RemainingProviderCreateGates).To(ConsistOf(providerCreateGateConditionType))

				Eventually(func(g Gomega) {
					got, err := regionClient.GetServer(ctx, serverID)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(got.Status.RemainingProviderCreateGates).NotTo(BeNil())
					g.Expect(*got.Status.RemainingProviderCreateGates).To(ConsistOf(providerCreateGateConditionType))
				}).WithTimeout(5*time.Second).
					WithPolling(250*time.Millisecond).
					Should(Succeed(), "created server should expose its remaining provider-create gate")

				Consistently(func(g Gomega) {
					got, err := regionClient.GetServer(ctx, serverID)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(got.Metadata.ProvisioningStatus).NotTo(Equal(coreapi.ResourceProvisioningStatusError))
					g.Expect(got.Status.RemainingProviderCreateGates).NotTo(BeNil())
					g.Expect(*got.Status.RemainingProviderCreateGates).To(ConsistOf(providerCreateGateConditionType))
				}).WithTimeout(12*time.Second).
					WithPolling(time.Second).
					Should(Succeed(), "provider create should stay blocked while the gate is unsatisfied")

				action := regionopenapi.ServerProviderCreateGateAction{
					ConditionType: providerCreateGateConditionType,
					Reason:        "ExternalStatePrepared",
					Message:       "external state required before provider create is ready",
				}

				Expect(regionClient.SatisfyServerProviderCreateGate(ctx, serverID, action)).To(Succeed())

				Eventually(func(g Gomega) {
					got, err := regionClient.GetServer(ctx, serverID)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(got.Status.RemainingProviderCreateGates).NotTo(BeNil())
					g.Expect(*got.Status.RemainingProviderCreateGates).To(BeEmpty())
				}).WithTimeout(15*time.Second).
					WithPolling(250*time.Millisecond).
					Should(Succeed(), "satisfied gate should disappear from the remaining-gates projection")

				eventuallyProviderCreateGateServerProvisioned(serverID)
			})
		})
	})
})
