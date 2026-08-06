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

	"github.com/google/uuid"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"
)

const (
	simulatedUpdateSettleTimeout = 2 * time.Minute
	simulatedUpdateSettlePoll    = time.Second
	// The rebuild window opens on the reconcile pass the update wakes and stays
	// open across two requeue intervals, so it must be observed well within this.
	simulatedRebuildObserveTimeout = 30 * time.Second
)

// simulatedImageRunsOnFlavor mirrors the handler's flavor-dependent image gate
// (architecture, root-disk capacity, virtualization) so the resolved fixture
// only offers a pair the image update will accept.
func simulatedImageRunsOnFlavor(image regionopenapi.Image, flavor regionopenapi.Flavor) bool {
	if image.Spec.Architecture != flavor.Spec.Architecture {
		return false
	}

	if flavor.Spec.Disk < image.Spec.SizeGiB {
		return false
	}

	baremetal := flavor.Spec.Baremetal != nil && *flavor.Spec.Baremetal

	switch image.Spec.Virtualization {
	case regionopenapi.ImageVirtualizationBaremetal:
		return baremetal
	case regionopenapi.ImageVirtualizationVirtualized:
		return !baremetal
	case regionopenapi.ImageVirtualizationAny:
		return true
	default:
		return true
	}
}

func simulatedCompatibleReadyImageIDs(images regionopenapi.Images, flavor regionopenapi.Flavor) []string {
	ids := make([]string, 0, len(images))

	for _, image := range images {
		if image.Status.State != regionopenapi.ImageStateReady {
			continue
		}

		if !simulatedImageRunsOnFlavor(image, flavor) {
			continue
		}

		ids = append(ids, image.Metadata.Id)
	}

	return ids
}

// simulatedLifecycleFixture names the flavor and the two ready images an image
// update moves the server between.
type simulatedLifecycleFixture struct {
	flavorID       string
	initialImageID string
	targetImageID  string
}

// mustResolveSimulatedLifecycleFixture resolves the fixture from the region itself.
// The simulated provider serves deterministic built-ins and the integration
// environment configures no server fixture IDs, so the pair is discovered rather
// than read from the TEST_SERVER_* variables the OpenStack suites rely on.
func mustResolveSimulatedLifecycleFixture() simulatedLifecycleFixture {
	flavors, err := regionClient.ListFlavors(ctx, config.OrgID, config.RegionID)
	Expect(err).NotTo(HaveOccurred(), "failed to list region flavors")

	images, err := regionClient.ListImages(ctx, config.OrgID, config.RegionID)
	Expect(err).NotTo(HaveOccurred(), "failed to list region images")

	for _, flavor := range flavors {
		// A pinned-only flavor demands an infrastructureRef this suite does not
		// supply, so it cannot host the fixture server.
		if flavor.Spec.PinnedOnly != nil && *flavor.Spec.PinnedOnly {
			continue
		}

		if compatible := simulatedCompatibleReadyImageIDs(images, flavor); len(compatible) >= 2 {
			return simulatedLifecycleFixture{
				flavorID:       flavor.Metadata.Id,
				initialImageID: compatible[0],
				targetImageID:  compatible[1],
			}
		}
	}

	Skip("server lifecycle tests require a region flavor with two compatible ready images")

	return simulatedLifecycleFixture{}
}

var _ = Describe("Server Lifecycle", func() {
	Context("When managing a server on a simulated region", Ordered, func() {
		var (
			networkID      string
			targetImageID  string
			provisioned    *regionopenapi.ServerV2Read
			updatedImageID regionopenapi.ImageId
		)

		BeforeAll(func() {
			api.SkipUnlessSimulatedRegion(regionClient, ctx, config)
			api.SkipUnlessInternalAPIConfigured(regionClient)

			fixture := mustResolveSimulatedLifecycleFixture()
			targetImageID = fixture.targetImageID

			networkReq := api.NewNetworkPayload(config.OrgID, config.ProjectID, config.RegionID).Build()
			network, cleanupNetwork := api.MustProvisionNetwork(regionClient, ctx, networkReq)
			DeferCleanup(cleanupNetwork)
			networkID = network.Metadata.Id

			createReq := api.NewServerPayload(networkID, fixture.flavorID, fixture.initialImageID).Build()
			created, cleanupServer := api.MustCreateServer(regionClient, ctx, createReq)
			DeferCleanup(cleanupServer)

			Expect(created.Metadata.Name).To(Equal(createReq.Metadata.Name))
			Expect(created.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusPending))
			Expect(created.Spec.ImageId).To(Equal(createReq.Spec.ImageId))
			Expect(created.Spec.FlavorId).To(Equal(createReq.Spec.FlavorId))
			// The ID types are UUID-backed named types, so compare their string
			// forms against the fixture IDs rather than the values themselves.
			Expect(created.Status.NetworkId.String()).To(Equal(networkID))
			Expect(created.Status.RegionId.String()).To(Equal(config.RegionID))

			api.WaitForServerProvisioned(regionClient, ctx, created.Metadata.Id)

			ready, err := regionClient.GetServer(ctx, created.Metadata.Id)
			Expect(err).NotTo(HaveOccurred())
			Expect(ready.Spec.ImageId).To(Equal(createReq.Spec.ImageId))
			provisioned = ready
		})

		// Declared before the destructive image update so it runs against the
		// pristine server and does not depend on the update succeeding.
		Describe("Given the server flavor is immutable", func() {
			It("should reject a flavor change with an actionable 422", func() {
				update := api.ServerUpdateFromRead(provisioned).WithFlavorID(uuid.NewString()).Build()

				apiError, err := regionClient.UpdateServerExpectError(ctx, provisioned.Metadata.Id, update, http.StatusUnprocessableEntity)
				Expect(err).NotTo(HaveOccurred())
				Expect(apiError.Error).To(Equal(coreapi.UnprocessableContent))
				Expect(apiError.ErrorDescription).To(ContainSubstring("flavor is immutable"))
			})
		})

		Describe("Given a provisioned server", func() {
			It("should accept the image update and report the new image in the spec", func() {
				update := api.ServerUpdateFromRead(provisioned).WithImageID(targetImageID).Build()
				updatedImageID = update.Spec.ImageId

				updated, err := regionClient.UpdateServer(ctx, provisioned.Metadata.Id, update)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated.Metadata.Id).To(Equal(provisioned.Metadata.Id))
				Expect(updated.Metadata.Name).To(Equal(provisioned.Metadata.Name))
				Expect(updated.Spec.ImageId).To(Equal(updatedImageID))
				Expect(updated.Spec.FlavorId).To(Equal(provisioned.Spec.FlavorId))
				Expect(updated.Status.NetworkId.String()).To(Equal(networkID))
			})

			It("should report the rebuild in flight and leave provisioned while it converges", func() {
				// The window is reconciler-driven — the accepting pass stamps the
				// Rebuilding phase and yields — so both signals are deterministic:
				// no monitor poll needs to land inside the window.
				Eventually(func(g Gomega) {
					got, err := regionClient.GetServer(ctx, provisioned.Metadata.Id)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(got.Metadata.ProvisioningStatus).NotTo(Equal(coreapi.ResourceProvisioningStatusProvisioned), "an in-flight rebuild must not read as settled")
					g.Expect(got.Status.PowerState).NotTo(BeNil())
					g.Expect(*got.Status.PowerState).To(Equal(regionopenapi.InstanceLifecyclePhaseRebuilding), "an in-flight rebuild must surface the documented Rebuilding phase")
					g.Expect(got.Spec.ImageId).To(Equal(updatedImageID), "the spec must reflect the accepted intent while the rebuild converges")
				}).WithTimeout(simulatedRebuildObserveTimeout).
					WithPolling(simulatedUpdateSettlePoll).
					Should(Succeed(), "server should report the rebuild in flight")
			})

			It("should settle on the new image", func() {
				Eventually(func(g Gomega) {
					got, err := regionClient.GetServer(ctx, provisioned.Metadata.Id)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(got.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
					g.Expect(got.Spec.ImageId).To(Equal(updatedImageID))
					g.Expect(got.Metadata.Id).To(Equal(provisioned.Metadata.Id), "an image update must retain the server identity")
					g.Expect(got.Spec.FlavorId).To(Equal(provisioned.Spec.FlavorId), "an image update must not change the flavor")
					g.Expect(got.Status.NetworkId.String()).To(Equal(networkID), "an image update must retain the server network")
					g.Expect(got.Status.PowerState).NotTo(BeNil())
					g.Expect(*got.Status.PowerState).To(Equal(regionopenapi.InstanceLifecyclePhaseRunning), "a settled rebuild must return to the Running phase")
				}).WithTimeout(simulatedUpdateSettleTimeout).
					WithPolling(simulatedUpdateSettlePoll).
					Should(Succeed(), "server should settle on the new image")
			})
		})
	})
})
