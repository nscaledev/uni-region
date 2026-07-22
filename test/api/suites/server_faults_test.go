//go:build integration || e2e
// +build integration e2e

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

//nolint:revive,testpackage // dot imports and package naming standard for Ginkgo
package suites

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"
)

// Monitor poll period defaults to ~1 min and DefaultYieldTimeout to 10s, so one
// retry cycle is roughly 90s (<=60s detect + 2x10s yields + deploy/undeploy) and
// three attempts land around 4-5 min. The terminal timeout allows ~12 min for the
// retry chain to park; recovery allows ~10 min for a fresh create to become
// Running/Healthy. Both sit comfortably under the 2h slow-lane cap.
const (
	serverFaultTerminalTimeout = 12 * time.Minute
	serverFaultRecoveryTimeout = 10 * time.Minute
	serverFaultPollInterval    = 10 * time.Second
)

func countDeployFailures(events []api.FakeControlEvent) int {
	failures := 0

	for _, event := range events {
		if event.Op == "deploy" && event.Outcome == "fail" {
			failures++
		}
	}

	return failures
}

var _ = Describe("Server fault injection", func() {
	Context("When a fake-controllable node is programmed to fail deploy", Ordered, Label("slow"), func() {
		var (
			networkID   string
			fakeControl *api.FakeControlClient
			nodeUUID    string
		)

		BeforeAll(func() {
			api.SkipUnlessOpenStackRegion(regionClient, ctx, config)
			api.SkipUnlessInternalAPIConfigured(regionClient)
			api.SkipUnlessServerFixtureConfigured(config)
			skipUnlessServerInfrastructureRefConfigured()
			api.SkipUnlessFakeControlConfigured(config)

			fakeControl = api.NewFakeControlClient(config)
			nodeUUID = api.FakeControlNodeUUID(config.ServerInfrastructureRef)

			networkReq := api.NewNetworkPayload(config.OrgID, config.ProjectID, config.RegionID).Build()
			network, cleanupNetwork := api.MustProvisionNetwork(regionClient, ctx, networkReq)
			DeferCleanup(cleanupNetwork)
			networkID = network.Metadata.Id
		})

		Describe("Given the node fails every deploy", func() {
			It("drives the pinned server to a terminal error park after retrying deploy", Label("slow"), func() {
				fakeControl.ProgramNodeBehavior(ctx, nodeUUID, map[string]any{"deploy": "fail"})
				DeferCleanup(func() {
					fakeControl.ResetNode(ctx, nodeUUID)
				})

				createReq := api.NewServerPayload(networkID, testFlavorID(), testImageID()).
					WithInfrastructureRef(config.ServerInfrastructureRef).
					Build()

				created, cleanup := api.MustCreateServer(regionClient, ctx, createReq)
				DeferCleanup(cleanup)

				serverID := created.Metadata.Id

				// ProvisioningStatus == error is the stable terminal park: it is set
				// only once the retry cap is hit, and the last failed Nova instance
				// stays attached there, so it does not flap like the health signal.
				Eventually(func(g Gomega) {
					server, err := regionClient.GetServer(ctx, serverID)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(server.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusError))
				}).WithTimeout(serverFaultTerminalTimeout).WithPolling(serverFaultPollInterval).
					Should(Succeed(), "pinned server should reach the terminal error park")

				parked, err := regionClient.GetServer(ctx, serverID)
				Expect(err).NotTo(HaveOccurred())
				Expect(parked.Metadata.HealthStatus).To(Equal(coreapi.ResourceHealthStatusError),
					"health should be errored while parked at the retry cap")

				events := fakeControl.NodeEvents(ctx, nodeUUID)
				Expect(countDeployFailures(events)).To(BeNumerically(">=", 2),
					"driver should have failed deploy across at least one retry")
			})
		})

		Describe("Given the node is reset to healthy", func() {
			It("provisions a fresh pinned server on the recovered node", Label("slow"), func() {
				// Terminal is a hard park, so recovery cannot revive the parked server;
				// the previous It's cleanup deleted it and returned the node to available.
				fakeControl.ResetNode(ctx, nodeUUID)

				createReq := api.NewServerPayload(networkID, testFlavorID(), testImageID()).
					WithInfrastructureRef(config.ServerInfrastructureRef).
					Build()

				created, cleanup := api.MustCreateServer(regionClient, ctx, createReq)
				DeferCleanup(cleanup)

				serverID := created.Metadata.Id

				Eventually(func(g Gomega) {
					server, err := regionClient.GetServer(ctx, serverID)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(server.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
					g.Expect(server.Metadata.HealthStatus).To(Equal(coreapi.ResourceHealthStatusHealthy))
				}).WithTimeout(serverFaultRecoveryTimeout).WithPolling(serverFaultPollInterval).
					Should(Succeed(), "fresh pinned server should provision and become healthy on the recovered node")
			})
		})
	})
})
