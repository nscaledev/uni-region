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

//nolint:revive,testpackage // dot imports and package naming standard for Ginkgo
package suites

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"
)

// One retry cycle is ~90s (<=60s monitor poll + 2x10s yields + deploy/undeploy), so
// three attempts land around 4-5 min. Both timeouts leave headroom on that and sit
// well under the 2h slow-lane cap.
const (
	serverFaultTerminalTimeout = 12 * time.Minute
	serverFaultRecoveryTimeout = 10 * time.Minute
	serverFaultPollInterval    = 10 * time.Second

	// The driver consults the sidecar on its first deploy attempt, which follows
	// placement and the start of the Nova build rather than the create call itself.
	serverFaultWiringTimeout = 8 * time.Minute

	// Long enough to span several reconciles, so a rebuild that is wrongly reported as
	// settled is caught rather than missed between polls.
	serverFaultRebuildWindow = 3 * time.Minute
)

// Only deploy is reachable through a server's lifecycle on this fixture. The
// fake-controllable deploy interface subclasses Ironic's FakeDeploy, whose deploy and
// tear_down do nothing, so the conductor never drives a power action or sets a boot device
// while provisioning, deleting or stopping a server — the node is never powered on at all,
// and its event log carries deploy entries and nothing else. The client's power and
// management programs are therefore covered only by the hermetic sidecar tests; reaching
// them end to end needs a fixture whose deploy interface performs real power work.

// resetAndVerifyNode clears the node's program and proves the reset landed. The fixture
// node is shared, so a surviving program corrupts the next run rather than the run that set
// it — the one failure mode that reports against innocent code.
func resetAndVerifyNode(fakeControl *api.FakeControlClient, nodeUUID string) {
	fakeControl.ResetNode(ctx, nodeUUID)
	Expect(fakeControl.NodeBehavior(ctx, nodeUUID)).To(BeEmpty(),
		"fault injection must leave the shared fixture node unprogrammed")
}

func skipUnlessFaultInjectionConfigured() {
	api.SkipUnlessOpenStackRegion(regionClient, ctx, config)
	api.SkipUnlessInternalAPIConfigured(regionClient)
	api.SkipUnlessServerFixtureConfigured(config)
	skipUnlessServerInfrastructureRefConfigured()
	api.SkipUnlessFakeControlConfigured(config)
}

func mustCreatePinnedServer(networkID string) (*regionopenapi.ServerV2Read, func()) {
	createReq := api.NewServerPayload(networkID, testFlavorID(), testImageID()).
		WithInfrastructureRef(config.ServerInfrastructureRef).
		Build()

	return api.MustCreateServer(regionClient, ctx, createReq)
}

// eventuallyNodeOpFailed waits until the driver has recorded a failed op against the node.
// It is the wiring proof, and it runs before any slow status assertion: the sidecar's node
// store is create-on-write, so a mistyped or scheme-prefixed node UUID is accepted by every
// endpoint, injects no fault, and reports no error. Without this gate that mistake — or an
// undeployed driver — surfaces only as a status timeout minutes later, which reads like a
// region API fault rather than a harness misconfiguration.
func eventuallyNodeOpFailed(fakeControl *api.FakeControlClient, nodeUUID, op string, timeout time.Duration) {
	Eventually(func(g Gomega) {
		events := fakeControl.NodeEvents(ctx, nodeUUID)
		g.Expect(api.CountEvents(events, op, api.FakeControlOutcomeFail)).To(BeNumerically(">=", 1))
	}).WithTimeout(timeout).WithPolling(serverFaultPollInterval).
		Should(Succeed(), "driver should have recorded a failed %s against node %s", op, nodeUUID)
}

func eventuallyServerProvisionedAndHealthy(serverID string, timeout time.Duration, description string) {
	Eventually(func(g Gomega) {
		server, err := regionClient.GetServer(ctx, serverID)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(server.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
		g.Expect(server.Metadata.HealthStatus).To(Equal(coreapi.ResourceHealthStatusHealthy))
	}).WithTimeout(timeout).WithPolling(serverFaultPollInterval).
		Should(Succeed(), description)
}

var _ = Describe("Server fault injection", func() {
	Context("When a fake-controllable node is programmed to fail an operation", Ordered, Label("slow"), func() {
		var (
			networkID   string
			fakeControl *api.FakeControlClient
			nodeUUID    string
		)

		BeforeAll(func() {
			skipUnlessFaultInjectionConfigured()

			fakeControl = api.NewFakeControlClient(config)

			// The pinned host is enrolled as a fake-controllable Ironic node, so the
			// ref the server pins on is also the UUID the sidecar keys on.
			nodeUUID = api.FakeControlNodeUUID(config.ServerInfrastructureRef)

			networkReq := api.NewNetworkPayload(config.OrgID, config.ProjectID, config.RegionID).Build()
			network, cleanupNetwork := api.MustProvisionNetwork(regionClient, ctx, networkReq)
			DeferCleanup(cleanupNetwork)
			networkID = network.Metadata.Id
		})

		Describe("Given the node fails every deploy", func() {
			It("drives the pinned server to a terminal error park after retrying deploy", Label("slow"), func() {
				var serverCleanup func()

				// One cleanup, so the ordering is explicit rather than a consequence of
				// DeferCleanup's LIFO: the fail program must be cleared before the delete,
				// or teardown of a node parked in a hard error runs against a driver still
				// told to fail every op. Registered before anything is programmed, so
				// neither the program nor the create can leave the shared node faulted.
				DeferCleanup(func() {
					resetAndVerifyNode(fakeControl, nodeUUID)

					if serverCleanup != nil {
						serverCleanup()
					}
				})

				// Only DELETE clears the event log; PUT /behavior does not. Resetting
				// first makes the deploy-failure count below attributable to this spec
				// rather than to residue from a run that died before its cleanup.
				fakeControl.ResetNode(ctx, nodeUUID)
				fakeControl.ProgramNodeBehavior(ctx, nodeUUID, api.FailDeploy())

				created, cleanup := mustCreatePinnedServer(networkID)
				serverCleanup = cleanup

				serverID := created.Metadata.Id

				By("proving the driver ran the injected deploy against the programmed node")
				eventuallyNodeOpFailed(fakeControl, nodeUUID, api.FakeControlOpDeploy, serverFaultWiringTimeout)

				// ProvisioningStatus == error is the stable terminal park: it is set only
				// once the retry cap is hit. Health is asserted in the same poll because it
				// flaps on the way there, so a single read after the fact is racy.
				//
				// Health accepts error or degraded because the subject here is the region
				// API's park behaviour, not Nova's internal outcome: a failed deploy that
				// reaches Nova ERROR reports error, one that stalls reports degraded, and
				// both are correct reports of an unhealthy server. Healthy and unknown
				// still fail.
				By("waiting for the retry budget to be spent and the server to park")
				Eventually(func(g Gomega) {
					server, err := regionClient.GetServer(ctx, serverID)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(server.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusError))
					g.Expect(server.Metadata.HealthStatus).To(BeElementOf(
						coreapi.ResourceHealthStatusError,
						coreapi.ResourceHealthStatusDegraded,
					))
				}).WithTimeout(serverFaultTerminalTimeout).WithPolling(serverFaultPollInterval).
					Should(Succeed(), "pinned server should park at provisioning=error and report unhealthy")

				events := fakeControl.NodeEvents(ctx, nodeUUID)
				Expect(api.CountEvents(events, api.FakeControlOpDeploy, api.FakeControlOutcomeFail)).
					To(BeNumerically(">=", 2), "driver should have failed deploy across at least one retry")
			})
		})

		Describe("Given the node recovers while the create is still retrying", func() {
			It("converges the in-flight server on success instead of parking", Label("slow"), func() {
				var serverCleanup func()

				DeferCleanup(func() {
					resetAndVerifyNode(fakeControl, nodeUUID)

					if serverCleanup != nil {
						serverCleanup()
					}
				})

				fakeControl.ResetNode(ctx, nodeUUID)
				fakeControl.ProgramNodeBehavior(ctx, nodeUUID, api.FailDeploy())

				created, cleanup := mustCreatePinnedServer(networkID)
				serverCleanup = cleanup

				serverID := created.Metadata.Id

				// Gated on the event log rather than a sleep, so the reset lands after at
				// least one failure but before the retry budget is spent. That window is
				// the whole point: the recovery spec below only proves a fresh create
				// works on a healthy node, so without this nothing proves the retry loop
				// can converge on success rather than only ever parking.
				//
				// Assumes the deployed region allows at least two create attempts, the
				// same assumption the deploy-failure count above rests on.
				By("clearing the fault after the first injected failure, mid-retry")
				eventuallyNodeOpFailed(fakeControl, nodeUUID, api.FakeControlOpDeploy, serverFaultWiringTimeout)
				fakeControl.ResetNode(ctx, nodeUUID)

				eventuallyServerProvisionedAndHealthy(serverID, serverFaultRecoveryTimeout,
					"a create that failed once should still converge once the node recovers")
			})
		})

		Describe("Given the node has been reset to healthy", func() {
			It("provisions a fresh pinned server on the recovered node", Label("slow"), func() {
				// Terminal is a hard park, so recovery cannot revive a parked server; the
				// earlier specs' cleanups deleted theirs and returned the node to available.
				fakeControl.ResetNode(ctx, nodeUUID)

				created, cleanup := mustCreatePinnedServer(networkID)
				DeferCleanup(cleanup)

				eventuallyServerProvisionedAndHealthy(created.Metadata.Id, serverFaultRecoveryTimeout,
					"fresh pinned server should provision and become healthy on the recovered node")
			})
		})
	})

	Context("When a rebuild is deployed onto a node programmed to fail deploy", Ordered, Label("slow"), func() {
		var (
			fakeControl *api.FakeControlClient
			nodeUUID    string
			serverID    string
		)

		BeforeAll(func() {
			skipUnlessFaultInjectionConfigured()
			skipUnlessServerRebuildImageConfigured()

			fakeControl = api.NewFakeControlClient(config)
			nodeUUID = api.FakeControlNodeUUID(config.ServerInfrastructureRef)
			fakeControl.ResetNode(ctx, nodeUUID)

			networkReq := api.NewNetworkPayload(config.OrgID, config.ProjectID, config.RegionID).Build()
			network, cleanupNetwork := api.MustProvisionNetwork(regionClient, ctx, networkReq)
			DeferCleanup(cleanupNetwork)

			created, cleanupServer := mustCreatePinnedServer(network.Metadata.Id)

			DeferCleanup(func() {
				fakeControl.ResetNode(ctx, nodeUUID)
				cleanupServer()
			})

			serverID = EventuallyServerProvisioned(created.Metadata.Id).Metadata.Id
		})

		Describe("Given the provisioned server is rebuilt while the node fails deploy", func() {
			It("never reports provisioned while the rebuild's deploy is failing", Label("slow"), func() {
				fakeControl.ProgramNodeBehavior(ctx, nodeUUID, api.FailDeploy())

				server, err := regionClient.GetServer(ctx, serverID)
				Expect(err).NotTo(HaveOccurred())

				update := api.ServerUpdateFromRead(server).WithImageID(rebuildImageID()).Build()

				updated, err := regionClient.UpdateServer(ctx, serverID, update)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated.Spec.ImageId).To(Equal(update.Spec.ImageId))

				By("observing the server leave provisioned once the controller arms the rebuild")
				EventuallyServerProvisioning(serverID)

				By("proving the injected fault reached the rebuild's deploy")
				eventuallyNodeOpFailed(fakeControl, nodeUUID, api.FakeControlOpDeploy, serverFaultWiringTimeout)

				// deriveProvisioningStatus (pkg/handler/server/client_v2.go) masks
				// provisioned to provisioning while a rebuild marker is live, because
				// consumers gate on provisioned meaning the spec is fully realized. A
				// rebuild whose deploy failed has not realized it, and Spec.ImageId flips
				// to the target at accept, so provisioned here is indistinguishable from a
				// successful rebuild. Error is equally correct — that same contract passes
				// a parked rebuild's error through so failures stay visible — which leaves
				// provisioned as the only wrong answer.
				By("checking the failed rebuild never reports the spec as realized")
				Consistently(func(g Gomega) {
					got, err := regionClient.GetServer(ctx, serverID)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(got.Metadata.ProvisioningStatus).To(BeElementOf(
						coreapi.ResourceProvisioningStatusProvisioning,
						coreapi.ResourceProvisioningStatusError,
					))
				}).WithTimeout(serverFaultRebuildWindow).WithPolling(serverFaultPollInterval).
					Should(Succeed(), "a failed rebuild must not report provisioned: the target image was never written")
			})
		})
	})
})
