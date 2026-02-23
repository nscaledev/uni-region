//go:build integration
// +build integration

/*
Copyright 2025 the Unikorn Authors.
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
	"errors"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
)

var _ = Describe("Region Discovery", func() {
	Context("When listing regions", func() {
		Describe("Given valid organization access", func() {
			It("should return all available regions", func() {
				regions, err := client.ListRegions(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(regions).NotTo(BeEmpty())

				for _, region := range regions {
					Expect(region.Metadata).NotTo(BeNil())
					Expect(region.Spec).NotTo(BeNil())
					Expect(region.Metadata.Id).NotTo(BeEmpty())
					Expect(region.Metadata.Name).NotTo(BeEmpty())
					Expect(region.Spec.Type).To(Or(
						Equal(regionopenapi.RegionTypeOpenstack),
						Equal(regionopenapi.RegionTypeKubernetes),
					))
				}

				GinkgoWriter.Printf("Found %d regions\n", len(regions))
			})
		})

		Describe("Given invalid parameters", func() {
			It("should reject requests with empty organization ID", func() {
				path := client.GetListRegionsPath("")
				_, respBody, err := client.DoRequest(ctx, http.MethodGet, path, nil, http.StatusOK)

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrUnexpectedStatusCode)).To(BeTrue())
				Expect(string(respBody)).To(ContainSubstring("invalid_request"))
				Expect(string(respBody)).To(ContainSubstring("invalid path/query element"))
				GinkgoWriter.Printf("Expected error for empty organization ID: %v\n", err)
			})

			It("should reject requests with invalid organization ID format", func() {
				path := client.GetListRegionsPath("invalid-org-123")
				_, respBody, err := client.DoRequest(ctx, http.MethodGet, path, nil, http.StatusOK)

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrUnexpectedStatusCode)).To(BeTrue())
				Expect(string(respBody)).To(ContainSubstring("forbidden"))
				GinkgoWriter.Printf("Expected error for invalid organization ID: %v\n", err)
			})
		})
	})
})

// NOTE: Region Detail endpoint (/regions/{id}/detail) is not tested because:
// - It's marked as x-hidden: true (admin-only)
// - Returns 404 in test environment (requires elevated permissions)
// - Not part of critical user-facing services
// - Client method exists at api_client.go:102-118 if needed in future

var _ = Describe("Flavor Discovery", func() {
	Context("When listing flavors for a region", func() {
		Describe("Given valid region and organization", func() {
			It("should return all available flavors", func() {
				flavors, err := client.ListFlavors(ctx, config.OrgID, config.RegionID)

				Expect(err).NotTo(HaveOccurred())
				Expect(flavors).NotTo(BeEmpty())

				for _, flavor := range flavors {
					Expect(flavor.Metadata).NotTo(BeNil())
					Expect(flavor.Spec).NotTo(BeNil())
					Expect(flavor.Metadata.Id).NotTo(BeEmpty())
					Expect(flavor.Metadata.Name).NotTo(BeEmpty())
					Expect(flavor.Spec.Cpus).To(BeNumerically(">", 0))
					Expect(flavor.Spec.Memory).To(BeNumerically(">=", 0)) // Memory can be 0 for some flavor types
					Expect(flavor.Spec.Disk).To(BeNumerically(">=", 0)) // Disk can be 0 for some flavor types
				}

				GinkgoWriter.Printf("Found %d flavors for region %s\n", len(flavors), config.RegionID)
			})
		})

		Describe("Given invalid parameters", func() {
			It("should reject requests with invalid region ID for flavors", func() {
				_, err := client.ListFlavors(ctx, config.OrgID, "invalid-region-id")

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
				GinkgoWriter.Printf("Expected error for invalid region ID: %v\n", err)
			})
		})
	})
})

var _ = Describe("Image Discovery", func() {
	Context("When listing images for a region", func() {
		Describe("Given valid region and organization", func() {
			It("should return all available images", func() {
				images, err := client.ListImages(ctx, config.OrgID, config.RegionID)

				Expect(err).NotTo(HaveOccurred())
				Expect(images).NotTo(BeEmpty())

				for _, image := range images {
					Expect(image.Metadata).NotTo(BeNil())
					Expect(image.Spec).NotTo(BeNil())
					Expect(image.Metadata.Id).NotTo(BeEmpty())
					Expect(image.Metadata.Name).NotTo(BeEmpty())
					Expect(image.Spec.Os).NotTo(BeNil())
					Expect(image.Spec.Os.Distro).NotTo(BeEmpty())
				}

				GinkgoWriter.Printf("Found %d images for region %s\n", len(images), config.RegionID)
			})
		})

		Describe("Given invalid parameters", func() {
			It("should reject requests with invalid region ID for images", func() {
				_, err := client.ListImages(ctx, config.OrgID, "invalid-region-id")

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
				//Expect(errors.Is(err, coreclient.ErrServerError)).To(BeTrue())
				GinkgoWriter.Printf("Expected error for invalid region ID: %v\n", err)
			})
		})
	})
})

var _ = Describe("External Network Discovery", func() {
	Context("When listing external networks for a region", func() {
		Describe("Given valid region and organization", func() {
			It("should return 403 when RBAC denies access to external networks", func() {
				_, err := client.ListExternalNetworks(ctx, config.OrgID, config.RegionID)

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrAccessDenied)).To(BeTrue())
				GinkgoWriter.Printf("External networks access denied for region %s as expected\n", config.RegionID)
			})
		})

		Describe("Given invalid parameters", func() {
			It("should reject requests with invalid region ID for external networks", func() {
				_, err := client.ListExternalNetworks(ctx, config.OrgID, "invalid-region-id")

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrAccessDenied)).To(BeTrue())
				GinkgoWriter.Printf("Expected error for invalid region ID: %v\n", err)
			})
		})
	})
})
