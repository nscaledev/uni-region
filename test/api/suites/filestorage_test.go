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

//nolint:revive,testpackage,gci // dot imports and package naming standard for Ginkgo, import grouping
package suites

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/utils/ptr"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
)

var _ = Describe("File Storage Management", func() {
	Context("When listing file storage resources", func() {
		Describe("Given valid project access", func() {
			It("should return file storage resources for the project", func() {
				storageList, err := regionClient.ListFileStorage(ctx, config.OrgID, config.ProjectID, config.RegionID)
				if err != nil && errors.Is(err, coreclient.ErrResourceNotFound) {
					GinkgoWriter.Printf("Project not found or has no filestorage capability (valid state)\n")
					return
				}

				Expect(err).NotTo(HaveOccurred())
				if len(storageList) > 0 {
					// We should validate ALL items in collection, not just first
					for _, storage := range storageList {
						Expect(storage.Metadata).NotTo(BeNil())
						Expect(storage.Metadata.Id).NotTo(BeEmpty())
						Expect(storage.Metadata.Name).NotTo(BeEmpty())

						// Validate spec fields
						Expect(storage.Spec.SizeGiB).To(BeNumerically(">", 0))

						// Validate status fields
						Expect(storage.Status.StorageClassId).NotTo(BeEmpty())
						Expect(storage.Status.RegionId).NotTo(BeEmpty())

						GinkgoWriter.Printf("  Storage: %s (%s) - %dGiB\n",
							storage.Metadata.Name,
							storage.Metadata.Id,
							storage.Spec.SizeGiB)
					}

					GinkgoWriter.Printf("Found %d file storage resources\n", len(storageList))
				} else {
					GinkgoWriter.Printf("No file storage resources found (valid state)\n")
				}
			})
		})

		Describe("Given invalid parameters", func() {
			It("should reject requests with invalid organization ID format", func() {
				invalidOrgID := "not-a-valid-uuid"
				path := regionClient.GetEndpoints().ListFileStorage(invalidOrgID, config.ProjectID, config.RegionID)
				_, respBody, err := regionClient.DoRequest(ctx, http.MethodGet, path, nil, http.StatusOK)

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrUnexpectedStatusCode)).To(BeTrue())
				Expect(string(respBody)).To(Or(ContainSubstring("forbidden"), ContainSubstring("not found")))
				GinkgoWriter.Printf("Expected error for invalid organization ID: %v\n", err)
			})
		})
	})

	Context("When managing file storage lifecycle", Ordered, func() {
		var filestorageID string
		var filestorageName string
		var storageClassID string

		Describe("Given valid storage class and configuration", func() {
			It("should create a file storage resource", func() {
				// Get available storage classes to use for creation
				storageClasses, err := regionClient.ListFileStorageClasses(ctx, config.RegionID)
				Expect(err).NotTo(HaveOccurred(), "Failed to list storage classes")

				if len(storageClasses) == 0 {
					Skip(fmt.Sprintf("No storage classes allocated to region %s", config.RegionID))
				}

				storageClassID = storageClasses[0].Metadata.Id
				GinkgoWriter.Printf("Using storage class: %s (%s)\n",
					storageClasses[0].Metadata.Name,
					storageClassID)

				//nolint:gosec // Using math/rand is sufficient for test resource names
				storageName := fmt.Sprintf("test-storage-%d", rand.IntN(100000))

				// Build type-safe request
				request := regionopenapi.StorageV2CreateRequest{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        storageName,
						Description: ptr.To("Test lifecycle file storage"),
					},
					Spec: struct {
						Attachments    *regionopenapi.StorageAttachmentV2Spec `json:"attachments,omitempty"`
						OrganizationId string                                 `json:"organizationId"`
						ProjectId      string                                 `json:"projectId"`
						RegionId       string                                 `json:"regionId"`
						SizeGiB        int64                                  `json:"sizeGiB"`
						StorageClassId string                                 `json:"storageClassId"`
						StorageType    regionopenapi.StorageTypeV2Spec        `json:"storageType"`
					}{
						OrganizationId: config.OrgID,
						ProjectId:      config.ProjectID,
						RegionId:       config.RegionID,
						SizeGiB:        10,
						StorageClassId: storageClassID,
						StorageType: regionopenapi.StorageTypeV2Spec{
							NFS: &regionopenapi.NFSV2Spec{},
						},
					},
				}

				// Create the storage
				created, err := regionClient.CreateFileStorage(ctx, request)

				Expect(err).NotTo(HaveOccurred())
				Expect(created).NotTo(BeNil())
				Expect(created.Metadata.Id).NotTo(BeEmpty())
				Expect(created.Metadata.Name).To(Equal(request.Metadata.Name))
				Expect(created.Spec.SizeGiB).To(Equal(request.Spec.SizeGiB))

				filestorageID = created.Metadata.Id
				filestorageName = created.Metadata.Name

				GinkgoWriter.Printf("Created file storage: %s (%s)\n",
					created.Metadata.Name,
					filestorageID)
			})

			It("should retrieve the created file storage resource", func() {
				if filestorageID == "" {
					Skip("No filestorage ID available - create test may have been skipped or failed")
				}

				retrieved, err := regionClient.GetFileStorage(ctx, filestorageID)

				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved).NotTo(BeNil())
				Expect(retrieved.Metadata.Id).To(Equal(filestorageID))
				Expect(retrieved.Spec.SizeGiB).To(BeNumerically(">", 0))

				GinkgoWriter.Printf("Retrieved file storage: %s (%s) - %dGiB\n",
					retrieved.Metadata.Name,
					retrieved.Metadata.Id,
					retrieved.Spec.SizeGiB)
			})

			It("should update the file storage resource", func() {
				if filestorageID == "" {
					Skip("No filestorage ID available - create test may have been skipped or failed")
				}

				// Build update request
				update := regionopenapi.StorageV2UpdateRequest{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        filestorageName,
						Description: ptr.To("Updated test file storage"),
					},
					Spec: regionopenapi.StorageV2Spec{
						SizeGiB: 20, // Increase size
						StorageType: regionopenapi.StorageTypeV2Spec{
							NFS: &regionopenapi.NFSV2Spec{},
						},
					},
				}

				updated, err := regionClient.UpdateFileStorage(ctx, filestorageID, update)

				Expect(err).NotTo(HaveOccurred())
				Expect(updated).NotTo(BeNil())
				Expect(updated.Metadata.Id).To(Equal(filestorageID))
				if updated.Metadata.Description != nil {
					Expect(*updated.Metadata.Description).To(Equal("Updated test file storage"))
				}
				Expect(updated.Spec.SizeGiB).To(Equal(int64(20)))

				GinkgoWriter.Printf("Updated file storage: %s (%s) - now %dGiB\n",
					updated.Metadata.Name,
					updated.Metadata.Id,
					updated.Spec.SizeGiB)
			})

			It("should delete the file storage resource", func() {
				if filestorageID == "" {
					Skip("No filestorage ID available - create test may have been skipped or failed")
				}

				err := regionClient.DeleteFileStorage(ctx, filestorageID)

				Expect(err).NotTo(HaveOccurred())

				GinkgoWriter.Printf("Deleted file storage: %s\n", filestorageID)
			})

			It("should not find the deleted file storage resource", func() {
				if filestorageID == "" {
					Skip("No filestorage ID available - create test may have been skipped or failed")
				}

				// Deletion is async - wait for resource to be fully deleted (404)
				Eventually(func() bool {
					_, err := regionClient.GetFileStorage(ctx, filestorageID)
					// Check if we got a 404 error (resource deleted)
					return err != nil && errors.Is(err, coreclient.ErrUnexpectedStatusCode)
				}, "30s", "2s").Should(BeTrue(), "Resource should eventually return 404")

				GinkgoWriter.Printf("Confirmed file storage deleted: %s\n", filestorageID)
			})
		})

		AfterAll(func() {
			// Cleanup: if filestorage still exists, delete it
			if filestorageID != "" {
				GinkgoWriter.Printf("Cleaning up test filestorage: %s\n", filestorageID)
				_ = regionClient.DeleteFileStorage(ctx, filestorageID)
			}
		})
	})
})
