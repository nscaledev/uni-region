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

//nolint:gochecknoglobals,revive,paralleltest,testpackage // global vars and dot imports standard for Ginkgo
package suites

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"
)

const (
	invalidUUID           = "invalid-uuid"
	ubuntuNobleAMD64Image = "https://s3.glo1.nscale.com/os-images/noble-server-cloudimg-amd64.raw"
)

// skipUnlessImageCreated skips the current test if image creation failed in a prior step.
func skipUnlessImageCreated(imageID string) {
	if imageID == "" {
		Skip("skipping: image was not created in a prior step")
	}
}

var _ = Describe("Image Management", Ordered, func() {
	Context("When listing images", func() {
		Describe("Given invalid parameters", func() {
			It("should return an error for an invalid organization ID", func() {
				_, err := client.ListImages(ctx, invalidUUID, config.RegionID)
				Expect(err).To(HaveOccurred())
			})

			It("should return an error for an invalid region ID", func() {
				_, err := client.ListImages(ctx, config.OrgID, invalidUUID)
				// FIXME: API currently returns 500 instead of the expected 400 Bad Request.
				Expect(errors.Is(err, coreclient.ErrServerError)).To(BeTrue())
			})
		})

		Describe("Given a valid organization and region", func() {
			It("should return a non-empty list of images", func() {
				images, err := client.ListImages(ctx, config.OrgID, config.RegionID)
				Expect(err).NotTo(HaveOccurred())
				Expect(images).NotTo(BeEmpty())
				GinkgoWriter.Printf("Found %d images for region %s\n", len(images), config.RegionID)
			})
		})
	})

	Context("When managing a custom image", func() {
		var customImageID string

		AfterAll(func() {
			if customImageID == "" {
				return
			}
			GinkgoWriter.Printf("Cleaning up image %s\n", customImageID)
			if err := regionClient.DeleteImage(ctx, config.OrgID, config.RegionID, customImageID); err != nil {
				GinkgoWriter.Printf("Failed to clean up image %s: %v\n", customImageID, err)
			}
		})

		It("should create a custom image and return its ID", func() {
			data, err := regionClient.CreateImage(ctx, config.OrgID, config.RegionID,
				api.NewImagePayload().
					WithURI(ubuntuNobleAMD64Image).
					WithOSDistro(regionopenapi.OsDistroUbuntu).
					WithOSFamily(regionopenapi.OsFamilyDebian).
					WithOSKernel(regionopenapi.OsKernelLinux).
					WithOSCodename("noble").
					WithOSVersion("24.04").
					WithArchitecture(regionopenapi.ArchitectureX8664).
					WithVirtualization(regionopenapi.ImageVirtualizationVirtualized).
					Build())
			Expect(err).NotTo(HaveOccurred())
			Expect(data.Metadata.Id).NotTo(BeEmpty())

			customImageID = data.Metadata.Id
			GinkgoWriter.Printf("Created image %s\n", customImageID)
		})

		It("should become ready and visible in the image list", func() {
			skipUnlessImageCreated(customImageID)

			api.WaitForImageReady(regionClient, ctx, config, customImageID)
		})

		It("should delete the custom image successfully", func() {
			skipUnlessImageCreated(customImageID)

			err := regionClient.DeleteImage(ctx, config.OrgID, config.RegionID, customImageID)
			Expect(err).NotTo(HaveOccurred())
			GinkgoWriter.Printf("Deleted image %s\n", customImageID)
		})

		It("should return not found when deleting the already-deleted image", func() {
			skipUnlessImageCreated(customImageID)

			err := regionClient.DeleteImage(ctx, config.OrgID, config.RegionID, customImageID)
			Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
		})
	})
})
