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
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"
)

const fakeDCVolumeSizeGiB = int64(1)

var _ = Describe("Block Storage", func() {
	Context("When using the Fake Data Center", func() {
		Describe("Given an attachable volume class and an existing network", func() {
			It("provisions a volume and attaches it to a running server", Label("fake-dc"), func() {
				if config.FakeRegionID == "" || config.FakeNetworkID == "" || config.FakeVolumeClassID == "" ||
					config.FakeServerFlavorID == "" || config.FakeServerImageID == "" {
					Skip("Fake DC region, network, volume class, server flavor, and server image configuration are required")
				}
				api.SkipUnlessInternalAPIConfigured(regionClient)

				By("verifying the Fake DC advertises the expected attachable volume class")
				volumeClasses, err := regionClient.ListVolumeClasses(ctx, config.FakeRegionID)
				Expect(err).NotTo(HaveOccurred())

				classIndex := slices.IndexFunc(volumeClasses, func(class regionopenapi.VolumeClassV2Read) bool {
					return class.Metadata.Id == config.FakeVolumeClassID
				})
				Expect(classIndex).To(BeNumerically(">=", 0), "expected Fake DC volume class was not advertised")
				Expect(volumeClasses[classIndex].Spec.SupportedFlavorIds).NotTo(BeNil())
				Expect(*volumeClasses[classIndex].Spec.SupportedFlavorIds).To(ContainElement(idstest.MustParseFlavorID(config.FakeServerFlavorID)))

				By("creating and provisioning a block storage volume")
				volumeReq := api.NewVolumePayload(config.FakeNetworkID, config.FakeVolumeClassID).Build()
				volume, cleanupVolume := api.MustCreateVolume(regionClient, ctx, volumeReq)
				DeferCleanup(cleanupVolume)

				Expect(volume.Metadata.Name).To(Equal(volumeReq.Metadata.Name))
				Expect(volume.Metadata.OrganizationId).To(Equal(config.OrgID))
				Expect(volume.Metadata.ProjectId).To(Equal(config.ProjectID))
				Expect(volume.Spec).To(Equal(volumeReq.Spec))
				Expect(volume.Status.RegionId).To(Equal(idstest.MustParseRegionID(config.FakeRegionID)))

				Eventually(func(g Gomega) {
					got, err := regionClient.GetVolume(ctx, volume.Metadata.Id)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(got.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
					g.Expect(got.Status.SizeGiB).NotTo(BeNil())
					g.Expect(*got.Status.SizeGiB).To(Equal(fakeDCVolumeSizeGiB))
					g.Expect(got.Status.AttachedAt).To(BeNil())
				}).WithTimeout(5*time.Minute).
					WithPolling(5*time.Second).
					Should(Succeed(), "volume should become available before attachment")

				By("creating a server that requests the volume")
				serverReq := api.NewServerPayload(config.FakeNetworkID, config.FakeServerFlavorID, config.FakeServerImageID).
					WithSSHInjection(regionopenapi.SshInjectionNone).
					WithVolumes(volume.Metadata.Id).
					Build()
				server, cleanupServer := api.MustCreateServer(regionClient, ctx, serverReq)
				DeferCleanup(cleanupServer)

				Expect(server.Spec.Volumes).NotTo(BeNil())
				Expect(*server.Spec.Volumes).To(ConsistOf(Equal(idstest.MustParseVolumeID(volume.Metadata.Id))))

				By("waiting for the server and volume attachment to converge")
				Eventually(func(g Gomega) {
					gotServer, err := regionClient.GetServer(ctx, server.Metadata.Id)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(gotServer.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
					g.Expect(gotServer.Status.PowerState).NotTo(BeNil())
					g.Expect(*gotServer.Status.PowerState).To(Equal(regionopenapi.InstanceLifecyclePhaseRunning))
					g.Expect(gotServer.Status.Volumes).NotTo(BeNil())
					g.Expect(*gotServer.Status.Volumes).To(ConsistOf(
						And(
							HaveField("Id", idstest.MustParseVolumeID(volume.Metadata.Id)),
							HaveField("ProvisioningStatus", coreapi.ResourceProvisioningStatusProvisioned),
						),
					))

					gotVolume, err := regionClient.GetVolume(ctx, volume.Metadata.Id)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(gotVolume.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
					g.Expect(gotVolume.Status.AttachedAt).NotTo(BeNil())
				}).WithTimeout(20*time.Minute).
					WithPolling(10*time.Second).
					Should(Succeed(), "volume should attach to the running server")
			})
		})
	})
})
