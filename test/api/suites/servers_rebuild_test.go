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
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/google/uuid"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"
)

const (
	// A server rebuild is a destructive Nova operation measured in minutes, so
	// the settle watch is generous and polled coarsely.
	rebuildWatchTimeout = 30 * time.Minute
	rebuildPollInterval = 15 * time.Second

	// The controller arms the rebuild asynchronously; once armed, the
	// provisioning window lasts the whole rebuild, so a modest timeout with a
	// tight poll reliably catches the transition without racing the arm.
	rebuildProvisioningTimeout = 15 * time.Minute
	rebuildProvisioningPoll    = 2 * time.Second

	// One-second polling makes a violated Nova atomicity window practically
	// observable against a rebuild that otherwise takes minutes.
	novaProbeTimeout      = 30 * time.Minute
	novaProbePollInterval = 1 * time.Second
)

func rebuildImageID() string {
	return config.ServerRebuildImageID
}

func skipUnlessServerRebuildImageConfigured() {
	if config.ServerRebuildImageID == "" {
		Skip("server rebuild tests require TEST_SERVER_REBUILD_IMAGE_ID")
	}
}

func skipUnlessRebuildEnvironmentConfigured() {
	api.SkipUnlessOpenStackRegion(regionClient, ctx, config)
	api.SkipUnlessInternalAPIConfigured(regionClient)
	api.SkipUnlessServerFixtureConfigured(config)
	skipUnlessServerRebuildImageConfigured()
}

// mustProvisionServerForRebuild provisions a network and a server, registers
// their cleanup, and returns the server once it has settled as provisioned.
func mustProvisionServerForRebuild() *regionopenapi.ServerV2Read {
	networkReq := api.NewNetworkPayload(config.OrgID, config.ProjectID, config.RegionID).Build()
	network, cleanupNetwork := api.MustProvisionNetwork(regionClient, ctx, networkReq)
	DeferCleanup(cleanupNetwork)

	createReq := api.NewServerPayload(network.Metadata.Id, config.ServerFlavorID, config.ServerImageID).Build()
	created, cleanupServer := api.MustCreateServer(regionClient, ctx, createReq)
	DeferCleanup(cleanupServer)

	return EventuallyServerProvisioned(created.Metadata.Id)
}

func EventuallyServerProvisioned(serverID string) *regionopenapi.ServerV2Read {
	var server *regionopenapi.ServerV2Read

	Eventually(func(g Gomega) {
		var err error
		server, err = regionClient.GetServer(ctx, serverID)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(server.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
	}).WithTimeout(rebuildWatchTimeout).
		WithPolling(rebuildPollInterval).
		Should(Succeed(), "server should become provisioned")

	return server
}

// EventuallyServerProvisioning asserts the settled gate: an accepted rebuild
// intent must surface as provisioning, never remain provisioned while the
// desired image is unrealized.
func EventuallyServerProvisioning(serverID string) {
	Eventually(func(g Gomega) {
		got, err := regionClient.GetServer(ctx, serverID)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(got.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioning))
	}).WithTimeout(rebuildProvisioningTimeout).
		WithPolling(rebuildProvisioningPoll).
		Should(Succeed(), "rebuild intent must read as provisioning before it settles")
}

func EventuallyServerPowerState(serverID string, phase regionopenapi.InstanceLifecyclePhase) *regionopenapi.ServerV2Read {
	var server *regionopenapi.ServerV2Read

	Eventually(func(g Gomega) {
		var err error
		server, err = regionClient.GetServer(ctx, serverID)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(server.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
		g.Expect(server.Status.PowerState).NotTo(BeNil())
		g.Expect(*server.Status.PowerState).To(Equal(phase))
	}).WithTimeout(rebuildWatchTimeout).
		WithPolling(rebuildPollInterval).
		Should(Succeed(), fmt.Sprintf("server should settle at power state %s", phase))

	return server
}

var _ = Describe("Server rebuild", func() {
	Context("When changing a provisioned v2 server's image", Ordered, func() {
		var server *regionopenapi.ServerV2Read

		BeforeAll(func() {
			skipUnlessRebuildEnvironmentConfigured()
			server = mustProvisionServerForRebuild()
		})

		// Declared before the destructive rebuild so it runs against the pristine
		// provisioned server and does not depend on the rebuild succeeding.
		Describe("Given the server flavor is immutable", func() {
			It("rejects a flavor change with an actionable 422", func() {
				update := api.ServerUpdateFromRead(server).WithFlavorID(uuid.NewString()).Build()

				apiError, err := regionClient.UpdateServerExpectError(ctx, server.Metadata.Id, update, http.StatusUnprocessableEntity)
				Expect(err).NotTo(HaveOccurred())
				Expect(apiError.Error).To(Equal(coreapi.UnprocessableContent))
				Expect(apiError.ErrorDescription).To(ContainSubstring("flavor is immutable"))
			})
		})

		Describe("Given the server has settled as provisioned", func() {
			It("rebuilds in place, retaining identity and addresses, and reports provisioning until it settles", Label("slow"), func() {
				serverID := server.Metadata.Id
				originalPrivateIP := server.Status.PrivateIP

				update := api.ServerUpdateFromRead(server).WithImageID(rebuildImageID()).Build()

				updated, err := regionClient.UpdateServer(ctx, serverID, update)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated.Metadata.Id).To(Equal(serverID))
				Expect(updated.Spec.ImageId).To(Equal(update.Spec.ImageId))

				By("observing the server leave provisioned while the rebuild is in flight")
				EventuallyServerProvisioning(serverID)

				By("waiting for the rebuild to settle back to provisioned on the new image")
				var settled *regionopenapi.ServerV2Read
				Eventually(func(g Gomega) {
					got, err := regionClient.GetServer(ctx, serverID)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(got.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
					g.Expect(got.Spec.ImageId).To(Equal(update.Spec.ImageId))
					settled = got
				}).WithTimeout(rebuildWatchTimeout).
					WithPolling(rebuildPollInterval).
					Should(Succeed(), "server should settle on the new image")

				Expect(settled.Metadata.Id).To(Equal(serverID), "rebuild must retain the server identity")
				Expect(settled.Status.NetworkId).To(Equal(server.Status.NetworkId), "rebuild must retain the server network")

				if originalPrivateIP != nil {
					Expect(settled.Status.PrivateIP).NotTo(BeNil())
					Expect(*settled.Status.PrivateIP).To(Equal(*originalPrivateIP), "rebuild must retain the server address")
				}
			})
		})
	})

	Context("When changing a stopped v2 server's image", Ordered, func() {
		var server *regionopenapi.ServerV2Read

		BeforeAll(func() {
			skipUnlessRebuildEnvironmentConfigured()
			server = mustProvisionServerForRebuild()
		})

		Describe("Given the server has been stopped", func() {
			It("rebuilds the stopped server and settles it back to stopped", Label("slow"), func() {
				serverID := server.Metadata.Id

				By("waiting for the server to be running before stopping it")
				// provisioned reflects reconcile settlement, not guest boot; Nova
				// rejects power operations until the server reaches ACTIVE.
				EventuallyServerPowerState(serverID, regionopenapi.InstanceLifecyclePhaseRunning)

				By("stopping the server and waiting for it to settle as stopped")
				Expect(regionClient.StopServer(ctx, serverID)).To(Succeed())
				stopped := EventuallyServerPowerState(serverID, regionopenapi.InstanceLifecyclePhaseStopped)
				originalPrivateIP := stopped.Status.PrivateIP

				update := api.ServerUpdateFromRead(stopped).WithImageID(rebuildImageID()).Build()

				updated, err := regionClient.UpdateServer(ctx, serverID, update)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated.Metadata.Id).To(Equal(serverID))

				By("observing the stopped server enter the rebuild")
				EventuallyServerProvisioning(serverID)

				By("waiting for the stopped server to settle back to stopped on the new image")
				var settled *regionopenapi.ServerV2Read
				Eventually(func(g Gomega) {
					got, err := regionClient.GetServer(ctx, serverID)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(got.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
					g.Expect(got.Spec.ImageId).To(Equal(update.Spec.ImageId))
					g.Expect(got.Status.PowerState).NotTo(BeNil())
					g.Expect(*got.Status.PowerState).To(Equal(regionopenapi.InstanceLifecyclePhaseStopped))
					settled = got
				}).WithTimeout(rebuildWatchTimeout).
					WithPolling(rebuildPollInterval).
					Should(Succeed(), "stopped server should settle back to stopped on the new image")

				Expect(settled.Metadata.Id).To(Equal(serverID))

				if originalPrivateIP != nil {
					Expect(settled.Status.PrivateIP).NotTo(BeNil())
					Expect(*settled.Status.PrivateIP).To(Equal(*originalPrivateIP), "rebuild must retain the server address")
				}
			})
		})
	})
})

// The rebuild design rests on two Nova facts that this probe verifies against a
// live cloud: (F2) at API accept, Nova atomically flips the server's image ref
// to the target AND sets a non-empty OS-EXT-STS:task_state; (F14) that
// task_state is visible to the region's credential class. If either fails, a
// just-accepted rebuild is briefly indistinguishable from a settled one,
// opening a lag window the settled gate cannot close. The facts are properties
// of Nova itself, so the probe drives Nova directly with its own throwaway
// no-NIC server — servers created through the service land in per-identity
// projects this credential cannot list. The typed-wrapper rule governs the
// service API under test, not the infrastructure this test observes to justify
// the service's design.
var _ = Describe("Nova rebuild atomicity probe", func() {
	Context("When the region is OpenStack and Nova credentials are present", func() {
		Describe("Given a Nova server whose image is then rebuilt", func() {
			It("sees the target image ref carry a non-empty task_state at accept and clear only once settled", Label("slow"), func() {
				skipUnlessRebuildEnvironmentConfigured()
				skipUnlessNovaProbeConfigured()

				compute := mustNewNovaComputeClient()
				targetImageID := rebuildImageID()

				By("booting a throwaway no-NIC probe server")
				novaID := mustCreateNovaProbeServer(compute)

				By("confirming the Nova baseline is settled on a different image")
				Eventually(func(g Gomega) {
					baseline, err := servers.Get(ctx, compute, novaID).Extract()
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(baseline.Status).To(Equal("ACTIVE"))
					g.Expect(baseline.TaskState).To(BeEmpty())
					g.Expect(novaServerImageID(baseline)).NotTo(Equal(targetImageID))
				}).WithTimeout(rebuildWatchTimeout).
					WithPolling(rebuildPollInterval).
					Should(Succeed(), "Nova baseline should be settled before the rebuild")

				By("rebuilding the server toward the target image")
				_, err := servers.Rebuild(ctx, compute, novaID, servers.RebuildOpts{ImageRef: targetImageID}).Extract()
				Expect(err).NotTo(HaveOccurred(), "submitting the Nova rebuild")

				By("polling Nova at 1s to catch the atomic accept and the settle")
				assertNovaRebuildAtomicity(compute, novaID, targetImageID)
			})
		})
	})
})

func skipUnlessNovaProbeConfigured() {
	if os.Getenv("OS_AUTH_URL") == "" {
		Skip("Nova atomicity probe requires OpenStack auth in the environment (OS_AUTH_URL etc., e.g. from a sourced openrc)")
	}
}

func mustNewNovaComputeClient() *gophercloud.ServiceClient {
	authOptions, err := openstack.AuthOptionsFromEnv()
	Expect(err).NotTo(HaveOccurred(), "resolving OpenStack auth from the environment")

	// gophercloud's default provider client uses net/http's default transport,
	// which honors http.ProxyFromEnvironment; do not substitute a custom
	// Transport here or proxied clouds become unreachable.
	provider, err := openstack.AuthenticatedClient(ctx, authOptions)
	Expect(err).NotTo(HaveOccurred(), "authenticating against OpenStack")

	compute, err := openstack.NewComputeV2(provider, gophercloud.EndpointOpts{
		Region: os.Getenv("OS_REGION_NAME"),
	})
	Expect(err).NotTo(HaveOccurred(), "creating a Nova compute client")

	return compute
}

// mustCreateNovaProbeServer boots a minimal server in the probe credential's
// own project and registers its deletion. Networks "none" needs compute
// microversion 2.37+.
func mustCreateNovaProbeServer(compute *gophercloud.ServiceClient) string {
	compute.Microversion = "2.37"

	createOpts := servers.CreateOpts{
		Name:      api.UniqueName("nova-probe"),
		ImageRef:  config.ServerImageID,
		FlavorRef: config.ServerFlavorID,
		Networks:  "none",
	}

	created, err := servers.Create(ctx, compute, createOpts, nil).Extract()
	Expect(err).NotTo(HaveOccurred(), "creating the Nova probe server")

	DeferCleanup(func() {
		_ = servers.Delete(ctx, compute, created.ID).ExtractErr()
	})

	return created.ID
}

func novaServerImageID(server *servers.Server) string {
	if server.Image == nil {
		return ""
	}

	id, _ := server.Image["id"].(string)

	return id
}

func assertNovaRebuildAtomicity(compute *gophercloud.ServiceClient, novaID, targetImageID string) {
	pollCtx, cancel := context.WithTimeout(ctx, novaProbeTimeout)
	defer cancel()

	ticker := time.NewTicker(novaProbePollInterval)
	defer ticker.Stop()

	firstTargetSeen := false

	for {
		server, err := servers.Get(pollCtx, compute, novaID).Extract()
		Expect(err).NotTo(HaveOccurred(), "polling the Nova server during rebuild")

		onTarget := novaServerImageID(server) == targetImageID

		if onTarget && !firstTargetSeen {
			firstTargetSeen = true

			// F2 + F14: the instant Nova reports the target image ref, task_state
			// must already be non-empty. An empty task_state here is exactly the
			// lag window the design must not have.
			Expect(server.TaskState).NotTo(BeEmpty(),
				"target image ref observed with an empty task_state: rebuild accept was not atomic, or task_state is not visible to these credentials")
		}

		if firstTargetSeen && server.TaskState == "" {
			// Settled: ref == target AND task_state empty, reached only after a
			// non-empty transient.
			Expect(novaServerImageID(server)).To(Equal(targetImageID),
				"settled server must remain on the target image")

			return
		}

		select {
		case <-pollCtx.Done():
			Fail(fmt.Sprintf("Nova server %s did not settle on target image %s within %s (firstTargetSeen=%t)", novaID, targetImageID, novaProbeTimeout, firstTargetSeen))
		case <-ticker.C:
		}
	}
}
