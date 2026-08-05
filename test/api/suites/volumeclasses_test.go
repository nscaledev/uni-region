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

//nolint:revive,testpackage // dot imports and package naming are standard for Ginkgo tests
package suites

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
)

const missingVolumeClassRegionID = "00000000-0000-4000-8000-000000000147"

var _ = Describe("VolumeClass Discovery", func() {
	Context("When listing VolumeClass metadata", func() {
		Describe("Given a visible Region with default simulated provider configuration", func() {
			It("should return only the selected Region's enriched provider inventory", func() {
				volumeClasses, err := regionClient.ListVolumeClasses(
					ctx,
					missingVolumeClassRegionID,
					config.PrivateRegionID,
					config.PrivateRegionID,
				)

				Expect(err).NotTo(HaveOccurred())
				Expect(volumeClasses).To(HaveLen(2))

				byID := map[string]regionopenapi.VolumeClassV2Read{}
				for _, volumeClass := range volumeClasses {
					Expect(volumeClass.Metadata.Id).NotTo(BeEmpty())
					Expect(volumeClass.Metadata.Name).NotTo(BeEmpty())
					Expect(volumeClass.Spec.RegionId.String()).To(Equal(config.PrivateRegionID))

					byID[volumeClass.Metadata.Id] = volumeClass
				}

				standard, found := byID["33333333-3333-3333-3333-333333333333"]
				Expect(found).To(BeTrue())
				Expect(standard.Metadata.Name).To(Equal("sim-standard-volume"))
				Expect(standard.Metadata.Description).To(HaveValue(Equal("Simulated SSD block storage")))
				Expect(standard.Spec.MinimumSizeGiB).To(HaveValue(Equal(int64(1))))
				Expect(standard.Spec.MaximumSizeGiB).To(HaveValue(Equal(int64(16384))))
				Expect(standard.Spec.Media).To(HaveValue(Equal(regionopenapi.VolumeClassV2MediaSsd)))
				Expect(standard.Spec.Performance).To(BeNil())
				Expect(standard.Spec.Encrypted).To(BeFalse())

				fast, found := byID["44444444-4444-4444-4444-444444444444"]
				Expect(found).To(BeTrue())
				Expect(fast.Metadata.Name).To(Equal("sim-fast-volume"))
				Expect(fast.Metadata.Description).To(HaveValue(Equal("Simulated NVMe block storage")))
				Expect(fast.Spec.MinimumSizeGiB).To(HaveValue(Equal(int64(10))))
				Expect(fast.Spec.MaximumSizeGiB).To(HaveValue(Equal(int64(2048))))
				Expect(fast.Spec.Media).To(HaveValue(Equal(regionopenapi.VolumeClassV2MediaNvme)))
				Expect(fast.Spec.Performance).NotTo(BeNil())
				Expect(fast.Spec.Performance.MaxIOPS).To(HaveValue(Equal(25000)))
				Expect(fast.Spec.Performance.MaxThroughputMiBps).To(HaveValue(Equal(500)))
				Expect(fast.Spec.Encrypted).To(BeTrue())
			})
		})

		Describe("Given a visible Region exposes no VolumeClass inventory", func() {
			It("should return a typed non-nil empty list for the selected Region", func() {
				Expect(config.EmptyClassRegionID).NotTo(BeEmpty())

				Eventually(func(g Gomega) {
					regions, err := regionClient.ListRegions(ctx, config.OrgID)
					g.Expect(err).NotTo(HaveOccurred())

					regionIDs := make([]string, 0, len(regions))
					for _, region := range regions {
						g.Expect(region.Metadata).NotTo(BeNil())
						regionIDs = append(regionIDs, region.Metadata.Id)
					}

					g.Expect(regionIDs).To(ContainElement(config.EmptyClassRegionID))
				}).WithTimeout(5 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

				volumeClasses, err := regionClient.ListVolumeClasses(ctx, config.EmptyClassRegionID)

				Expect(err).NotTo(HaveOccurred())
				Expect(volumeClasses).NotTo(BeNil())
				Expect(volumeClasses).To(BeEmpty())
			})
		})
	})
})
