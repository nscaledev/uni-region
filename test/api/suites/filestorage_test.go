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
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreutil "github.com/unikorn-cloud/core/pkg/testing/util"
	idstest "github.com/unikorn-cloud/region/pkg/ids/idstest"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"

	"k8s.io/utils/ptr"
)

const defaultProtectionUpdateStorageSizeGiB = int64(10)

func dailyFileStorageSnapshotPolicies() regionopenapi.StorageSnapshotPolicyListV2Spec {
	return namedDailyFileStorageSnapshotPolicies("daily")
}

func namedDailyFileStorageSnapshotPolicies(name string) regionopenapi.StorageSnapshotPolicyListV2Spec {
	return regionopenapi.StorageSnapshotPolicyListV2Spec{
		{
			Name: name,
			Schedule: regionopenapi.StorageSnapshotScheduleV2Spec{
				Interval:  regionopenapi.StorageSnapshotScheduleIntervalV2Daily,
				TimeOfDay: ptr.To("04:00Z"),
			},
			Retention: regionopenapi.StorageSnapshotRetentionV2Spec{Keep: 7},
		},
	}
}

func hourlyFileStorageSnapshotPolicies() regionopenapi.StorageSnapshotPolicyListV2Spec {
	return regionopenapi.StorageSnapshotPolicyListV2Spec{
		{
			Name: "hourly",
			Schedule: regionopenapi.StorageSnapshotScheduleV2Spec{
				Interval: regionopenapi.StorageSnapshotScheduleIntervalV2Hourly,
			},
			Retention: regionopenapi.StorageSnapshotRetentionV2Spec{Keep: 24},
		},
	}
}

func nfsFileStorageType() regionopenapi.StorageTypeV2Spec {
	return regionopenapi.StorageTypeV2Spec{
		NFS: &regionopenapi.NFSV2Spec{},
	}
}

func requireFileStorageClassID() string {
	storageClasses, err := regionClient.ListFileStorageClasses(ctx, config.RegionID)
	Expect(err).NotTo(HaveOccurred(), "Failed to list storage classes")

	if len(storageClasses) == 0 {
		Skip(fmt.Sprintf("No storage classes allocated to region %s", config.RegionID))
	}

	return storageClasses[0].Metadata.Id
}

func defaultProtectionCreateRequest(storageClassID string, defaultProtectionEnabled *bool, snapshotPolicies *regionopenapi.StorageSnapshotPolicyListV2Spec) regionopenapi.StorageV2CreateRequest {
	storageName := coreutil.GenerateRandomName("test-default-protection")

	return regionopenapi.StorageV2CreateRequest{
		Metadata: coreapi.ResourceWriteMetadata{
			Name:        storageName,
			Description: ptr.To("Test default snapshot protection update semantics"),
		},
		Spec: struct {
			Attachments                      *regionopenapi.StorageAttachmentV2Spec         `json:"attachments,omitempty"`
			DefaultSnapshotProtectionEnabled *bool                                          `json:"defaultSnapshotProtectionEnabled,omitempty"`
			OrganizationId                   string                                         `json:"organizationId"`
			ProjectId                        string                                         `json:"projectId"`
			RegionId                         regionopenapi.RegionId                         `json:"regionId"`
			SizeGiB                          int64                                          `json:"sizeGiB"`
			SnapshotPolicies                 *regionopenapi.StorageSnapshotPolicyListV2Spec `json:"snapshotPolicies,omitempty"`
			StorageClassId                   string                                         `json:"storageClassId"`
			StorageType                      regionopenapi.StorageTypeV2Spec                `json:"storageType"`
		}{
			DefaultSnapshotProtectionEnabled: defaultProtectionEnabled,
			OrganizationId:                   config.OrgID,
			ProjectId:                        config.ProjectID,
			RegionId:                         idstest.MustParseRegionID(config.RegionID),
			SizeGiB:                          defaultProtectionUpdateStorageSizeGiB,
			SnapshotPolicies:                 snapshotPolicies,
			StorageClassId:                   storageClassID,
			StorageType:                      nfsFileStorageType(),
		},
	}
}

func createDefaultProtectionUpdateTestStorage(storageClassID string, defaultProtectionEnabled *bool, snapshotPolicies *regionopenapi.StorageSnapshotPolicyListV2Spec) *regionopenapi.StorageV2Read {
	request := defaultProtectionCreateRequest(storageClassID, defaultProtectionEnabled, snapshotPolicies)

	created, err := regionClient.CreateFileStorage(ctx, request)
	Expect(err).NotTo(HaveOccurred())
	Expect(created).NotTo(BeNil())

	DeferCleanup(func() {
		Expect(regionClient.DeleteFileStorage(ctx, created.Metadata.Id)).To(Succeed())
	})

	return created
}

func defaultProtectionUpdateRequest(name string, defaultProtectionEnabled *bool, snapshotPolicies *regionopenapi.StorageSnapshotPolicyListV2Spec) regionopenapi.StorageV2UpdateRequest {
	return regionopenapi.StorageV2UpdateRequest{
		Metadata: coreapi.ResourceWriteMetadata{
			Name:        name,
			Description: ptr.To("Updated default snapshot protection semantics"),
		},
		Spec: regionopenapi.StorageV2Spec{
			DefaultSnapshotProtectionEnabled: defaultProtectionEnabled,
			SizeGiB:                          defaultProtectionUpdateStorageSizeGiB,
			SnapshotPolicies:                 snapshotPolicies,
			StorageType:                      nfsFileStorageType(),
		},
	}
}

func expectDefaultProtectionUpdateState(storage *regionopenapi.StorageV2Read, defaultProtectionEnabled bool, snapshotPolicies regionopenapi.StorageSnapshotPolicyListV2Spec) {
	Expect(storage).NotTo(BeNil())
	// These spec fields are generated as pointers; reads always populate them, so
	// guard against nil then compare the dereferenced values (comparing a *bool or
	// *slice against a plain bool/slice via Equal always fails on the type mismatch).
	Expect(storage.Spec.DefaultSnapshotProtectionEnabled).NotTo(BeNil())
	Expect(*storage.Spec.DefaultSnapshotProtectionEnabled).To(Equal(defaultProtectionEnabled))
	Expect(storage.Spec.SnapshotPolicies).NotTo(BeNil())
	Expect(*storage.Spec.SnapshotPolicies).To(Equal(snapshotPolicies))
}

// INST-926 tracks Dev environment setup for file storage classes. Until Dev exposes
// a usable class for the configured test region, storage-class-dependent specs skip.
var _ = Describe("File Storage Management", func() {
	Context("When listing file storage resources", func() {
		Describe("Given valid project access", func() {
			var testStorageID string
			var testStorageName string

			It("should return file storage resources for the project", func() {
				storageClasses, err := regionClient.ListFileStorageClasses(ctx, config.RegionID)
				Expect(err).NotTo(HaveOccurred(), "Failed to list storage classes")

				if len(storageClasses) == 0 {
					Skip(fmt.Sprintf("No storage classes allocated to region %s", config.RegionID))
				}

				testStorageName = coreutil.GenerateRandomName("test-list-storage")
				request := regionopenapi.StorageV2CreateRequest{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        testStorageName,
						Description: ptr.To("Test resource for list operation"),
					},
					Spec: struct {
						Attachments                      *regionopenapi.StorageAttachmentV2Spec         `json:"attachments,omitempty"`
						DefaultSnapshotProtectionEnabled *bool                                          `json:"defaultSnapshotProtectionEnabled,omitempty"`
						OrganizationId                   string                                         `json:"organizationId"`
						ProjectId                        string                                         `json:"projectId"`
						RegionId                         regionopenapi.RegionId                         `json:"regionId"`
						SizeGiB                          int64                                          `json:"sizeGiB"`
						SnapshotPolicies                 *regionopenapi.StorageSnapshotPolicyListV2Spec `json:"snapshotPolicies,omitempty"`
						StorageClassId                   string                                         `json:"storageClassId"`
						StorageType                      regionopenapi.StorageTypeV2Spec                `json:"storageType"`
					}{
						OrganizationId: config.OrgID,
						ProjectId:      config.ProjectID,
						RegionId:       idstest.MustParseRegionID(config.RegionID),
						SizeGiB:        10,
						StorageClassId: storageClasses[0].Metadata.Id,
						StorageType: regionopenapi.StorageTypeV2Spec{
							NFS: &regionopenapi.NFSV2Spec{},
						},
					},
				}

				created, err := regionClient.CreateFileStorage(ctx, request)
				Expect(err).NotTo(HaveOccurred())
				Expect(created).NotTo(BeNil())
				testStorageID = created.Metadata.Id

				GinkgoWriter.Printf("Created test storage for list: %s (%s)\n", testStorageName, testStorageID)

				// List GETs are served from the controller-runtime cache, so a
				// just-created resource can briefly be absent from the list.
				Eventually(func(g Gomega) {
					storageList, err := regionClient.ListFileStorage(ctx, config.OrgID, config.ProjectID, config.RegionID)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(len(storageList)).To(BeNumerically(">=", 1), "Should have at least one storage resource")

					found := false
					for _, storage := range storageList {
						// Validate ALL items in collection have required fields
						g.Expect(storage.Metadata).NotTo(BeNil())
						g.Expect(storage.Metadata.Id).NotTo(BeEmpty())
						g.Expect(storage.Metadata.Name).NotTo(BeEmpty())
						g.Expect(storage.Spec.SizeGiB).To(BeNumerically(">", 0))
						g.Expect(storage.Status.StorageClassId).NotTo(BeEmpty())
						g.Expect(storage.Status.RegionId).NotTo(BeEmpty())

						if storage.Metadata.Id == testStorageID {
							found = true
							g.Expect(storage.Metadata.Name).To(Equal(testStorageName))
							g.Expect(storage.Metadata.OrganizationId).To(Equal(config.OrgID))
							g.Expect(storage.Metadata.ProjectId).To(Equal(config.ProjectID))
							GinkgoWriter.Printf("  Found our test storage: %s (%s) - %dGiB\n",
								storage.Metadata.Name,
								storage.Metadata.Id,
								storage.Spec.SizeGiB)
						}
					}

					g.Expect(found).To(BeTrue(), "Created storage should be in the list")
					GinkgoWriter.Printf("Found %d total file storage resources\n", len(storageList))
				}).WithTimeout(5 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())
			})

			AfterEach(func() {
				if testStorageID != "" {
					GinkgoWriter.Printf("Cleaning up test list storage: %s\n", testStorageID)
					Expect(regionClient.DeleteFileStorage(ctx, testStorageID)).To(Succeed())
				}
			})
		})
	})

	Context("When managing file storage lifecycle", Ordered, func() {
		const (
			initialStorageSizeGiB = int64(10)
			updatedStorageSizeGiB = int64(20)
		)

		var filestorageID string
		var filestorageName string
		var storageClassID string
		var filestorageDeleted bool

		Describe("Given valid storage class and configuration", func() {
			It("should create a file storage resource", func() {
				storageClasses, err := regionClient.ListFileStorageClasses(ctx, config.RegionID)
				Expect(err).NotTo(HaveOccurred(), "Failed to list storage classes")

				if len(storageClasses) == 0 {
					Skip(fmt.Sprintf("No storage classes allocated to region %s", config.RegionID))
				}

				storageClassID = storageClasses[0].Metadata.Id
				GinkgoWriter.Printf("Using storage class: %s (%s)\n",
					storageClasses[0].Metadata.Name,
					storageClassID)

				storageName := coreutil.GenerateRandomName("test-storage")

				request := regionopenapi.StorageV2CreateRequest{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        storageName,
						Description: ptr.To("Test lifecycle file storage"),
					},
					Spec: struct {
						Attachments                      *regionopenapi.StorageAttachmentV2Spec         `json:"attachments,omitempty"`
						DefaultSnapshotProtectionEnabled *bool                                          `json:"defaultSnapshotProtectionEnabled,omitempty"`
						OrganizationId                   string                                         `json:"organizationId"`
						ProjectId                        string                                         `json:"projectId"`
						RegionId                         regionopenapi.RegionId                         `json:"regionId"`
						SizeGiB                          int64                                          `json:"sizeGiB"`
						SnapshotPolicies                 *regionopenapi.StorageSnapshotPolicyListV2Spec `json:"snapshotPolicies,omitempty"`
						StorageClassId                   string                                         `json:"storageClassId"`
						StorageType                      regionopenapi.StorageTypeV2Spec                `json:"storageType"`
					}{
						OrganizationId: config.OrgID,
						ProjectId:      config.ProjectID,
						RegionId:       idstest.MustParseRegionID(config.RegionID),
						SizeGiB:        initialStorageSizeGiB,
						StorageClassId: storageClassID,
						StorageType: regionopenapi.StorageTypeV2Spec{
							NFS: &regionopenapi.NFSV2Spec{},
						},
					},
				}

				created, err := regionClient.CreateFileStorage(ctx, request)

				Expect(err).NotTo(HaveOccurred())
				Expect(created).NotTo(BeNil())
				Expect(created.Metadata.Id).NotTo(BeEmpty())
				Expect(created.Metadata.Name).To(Equal(request.Metadata.Name))
				Expect(created.Spec.SizeGiB).To(Equal(request.Spec.SizeGiB))
				expectDefaultProtectionUpdateState(created, true, regionopenapi.StorageSnapshotPolicyListV2Spec{})
				Expect(created.Status.SnapshotPolicies).To(BeEmpty())

				// Validate resource is correctly scoped and wired up
				Expect(created.Metadata.OrganizationId).To(Equal(config.OrgID))
				Expect(created.Metadata.ProjectId).To(Equal(config.ProjectID))
				Expect(created.Status.RegionId).To(Equal(config.RegionID))
				Expect(created.Status.StorageClassId).To(Equal(storageClassID))

				// Validate provisioning status is present (expected to be Unknown at this stage since create is async)
				Expect(created.Metadata.ProvisioningStatus).NotTo(BeNil())

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

				Eventually(func() coreapi.ResourceProvisioningStatus {
					retrieved, err := regionClient.GetFileStorage(ctx, filestorageID)
					if err != nil {
						GinkgoWriter.Printf("Error retrieving filestorage: %v\n", err)
						return ""
					}
					return retrieved.Metadata.ProvisioningStatus
				}).WithTimeout(5*time.Minute).
					WithPolling(10*time.Second).
					Should(Equal(coreapi.ResourceProvisioningStatusProvisioned),
						"File storage should eventually be provisioned")

				// Fetch again for full assertions after provisioning confirmed
				retrieved, err := regionClient.GetFileStorage(ctx, filestorageID)
				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved).NotTo(BeNil())
				Expect(retrieved.Metadata.Id).To(Equal(filestorageID))
				Expect(retrieved.Metadata.OrganizationId).To(Equal(config.OrgID))
				Expect(retrieved.Metadata.ProjectId).To(Equal(config.ProjectID))
				Expect(retrieved.Status.RegionId).To(Equal(config.RegionID))
				Expect(retrieved.Status.StorageClassId).To(Equal(storageClassID))
				Expect(retrieved.Spec.SizeGiB).To(Equal(initialStorageSizeGiB))
				expectDefaultProtectionUpdateState(retrieved, true, regionopenapi.StorageSnapshotPolicyListV2Spec{})
				Expect(retrieved.Status.SnapshotPolicies).To(BeEmpty())
				Expect(retrieved.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))

				GinkgoWriter.Printf("Retrieved file storage: %s (%s) - %dGiB (Status: %s)\n",
					retrieved.Metadata.Name,
					retrieved.Metadata.Id,
					retrieved.Spec.SizeGiB,
					retrieved.Metadata.ProvisioningStatus)
			})

			It("should update the file storage resource", func() {
				if filestorageID == "" {
					Skip("No filestorage ID available - create test may have been skipped or failed")
				}

				update := regionopenapi.StorageV2UpdateRequest{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        filestorageName,
						Description: ptr.To("Updated test file storage"),
					},
					Spec: regionopenapi.StorageV2Spec{
						SizeGiB: updatedStorageSizeGiB, // Increase size
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
				Expect(updated.Spec.SizeGiB).To(Equal(updatedStorageSizeGiB))
				expectDefaultProtectionUpdateState(updated, true, regionopenapi.StorageSnapshotPolicyListV2Spec{})

				GinkgoWriter.Printf("Updated file storage: %s (%s) - now %dGiB\n",
					updated.Metadata.Name,
					updated.Metadata.Id,
					updated.Spec.SizeGiB)
			})

			It("should clear snapshot policies through the parent update", func() {
				if filestorageID == "" {
					Skip("No filestorage ID available - create test may have been skipped or failed")
				}

				snapshotPolicies := regionopenapi.StorageSnapshotPolicyListV2Spec{}
				update := regionopenapi.StorageV2UpdateRequest{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        filestorageName,
						Description: ptr.To("Cleared snapshot policies for test file storage"),
					},
					Spec: regionopenapi.StorageV2Spec{
						SizeGiB:          updatedStorageSizeGiB,
						SnapshotPolicies: &snapshotPolicies,
						StorageType: regionopenapi.StorageTypeV2Spec{
							NFS: &regionopenapi.NFSV2Spec{},
						},
					},
				}

				updated, err := regionClient.UpdateFileStorage(ctx, filestorageID, update)

				Expect(err).NotTo(HaveOccurred())
				Expect(updated).NotTo(BeNil())
				expectDefaultProtectionUpdateState(updated, true, regionopenapi.StorageSnapshotPolicyListV2Spec{})
				Expect(updated.Status.SnapshotPolicies).To(BeEmpty())
			})

			It("should delete the file storage resource", func() {
				if filestorageID == "" {
					Skip("No filestorage ID available - create test may have been skipped or failed")
				}

				err := regionClient.DeleteFileStorage(ctx, filestorageID)

				Expect(err).NotTo(HaveOccurred())

				GinkgoWriter.Printf("Deleted file storage: %s\n", filestorageID)
				filestorageDeleted = true
			})
		})

		AfterAll(func() {
			if filestorageID != "" && !filestorageDeleted {
				GinkgoWriter.Printf("Cleaning up test filestorage: %s\n", filestorageID)
				Expect(regionClient.DeleteFileStorage(ctx, filestorageID)).To(Succeed())
			}
		})
	})

	Context("When updating default snapshot protection", func() {
		Describe("Given a File Storage resource", func() {
			It("changes default snapshot protection and replaces user-managed snapshot policies together", func() {
				storageClassID := requireFileStorageClassID()
				currentPolicies := dailyFileStorageSnapshotPolicies()
				replacementPolicies := hourlyFileStorageSnapshotPolicies()
				created := createDefaultProtectionUpdateTestStorage(storageClassID, ptr.To(false), &currentPolicies)

				update := defaultProtectionUpdateRequest(created.Metadata.Name, ptr.To(true), &replacementPolicies)
				updated, err := regionClient.UpdateFileStorage(ctx, created.Metadata.Id, update)
				Expect(err).NotTo(HaveOccurred())
				expectDefaultProtectionUpdateState(updated, true, replacementPolicies)

				retrieved, err := regionClient.GetFileStorage(ctx, created.Metadata.Id)
				Expect(err).NotTo(HaveOccurred())
				expectDefaultProtectionUpdateState(retrieved, true, replacementPolicies)
			})
		})
	})

	Context("When managing file storage attachments", Ordered, func() {
		const storageSizeGiB = int64(10)

		var filestorageID string
		var filestorageName string
		var storageClassID string
		var filestorageDeleteRequested bool
		var networkID string
		var networkName string

		Describe("Given a network and file storage resource", func() {
			It("should create a network for attachment", func() {
				networkName = api.UniqueName("attach-network")
				networkRequest := regionopenapi.NetworkV2CreateRequest{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        networkName,
						Description: ptr.To("Test network for storage attachment"),
					},
					Spec: regionopenapi.NetworkV2CreateSpec{
						OrganizationId: config.OrgID,
						ProjectId:      config.ProjectID,
						RegionId:       idstest.MustParseRegionID(config.RegionID),
						Prefix:         "10.0.1.0/24",
						DnsNameservers: []string{"8.8.8.8", "8.8.4.4"},
					},
				}

				network, err := regionClient.CreateNetwork(ctx, networkRequest)
				Expect(err).NotTo(HaveOccurred())
				Expect(network).NotTo(BeNil())
				Expect(network.Metadata.Id).NotTo(BeEmpty())

				networkID = network.Metadata.Id
				GinkgoWriter.Printf("Created network for attachment: %s (%s)\n", networkName, networkID)

				Eventually(func() coreapi.ResourceProvisioningStatus {
					networks, err := regionClient.ListNetworks(ctx, config.OrgID, config.ProjectID, config.RegionID)
					if err != nil {
						return ""
					}
					for _, n := range networks {
						if n.Metadata.Id == networkID {
							return n.Metadata.ProvisioningStatus
						}
					}
					return ""
				}).WithTimeout(5*time.Minute).
					WithPolling(10*time.Second).
					Should(Equal(coreapi.ResourceProvisioningStatusProvisioned),
						"Network should eventually be provisioned")

				GinkgoWriter.Printf("Network provisioned: %s\n", networkID)
			})

			It("should create a file storage resource without attachments", func() {
				// Get available storage classes
				storageClasses, err := regionClient.ListFileStorageClasses(ctx, config.RegionID)
				Expect(err).NotTo(HaveOccurred(), "Failed to list storage classes")

				if len(storageClasses) == 0 {
					Skip(fmt.Sprintf("No storage classes allocated to region %s", config.RegionID))
				}

				storageClassID = storageClasses[0].Metadata.Id
				filestorageName = coreutil.GenerateRandomName("test-attach-storage")

				request := regionopenapi.StorageV2CreateRequest{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        filestorageName,
						Description: ptr.To("Test file storage for attachment lifecycle"),
					},
					Spec: struct {
						Attachments                      *regionopenapi.StorageAttachmentV2Spec         `json:"attachments,omitempty"`
						DefaultSnapshotProtectionEnabled *bool                                          `json:"defaultSnapshotProtectionEnabled,omitempty"`
						OrganizationId                   string                                         `json:"organizationId"`
						ProjectId                        string                                         `json:"projectId"`
						RegionId                         regionopenapi.RegionId                         `json:"regionId"`
						SizeGiB                          int64                                          `json:"sizeGiB"`
						SnapshotPolicies                 *regionopenapi.StorageSnapshotPolicyListV2Spec `json:"snapshotPolicies,omitempty"`
						StorageClassId                   string                                         `json:"storageClassId"`
						StorageType                      regionopenapi.StorageTypeV2Spec                `json:"storageType"`
					}{
						OrganizationId: config.OrgID,
						ProjectId:      config.ProjectID,
						RegionId:       idstest.MustParseRegionID(config.RegionID),
						SizeGiB:        storageSizeGiB,
						StorageClassId: storageClassID,
						StorageType: regionopenapi.StorageTypeV2Spec{
							NFS: &regionopenapi.NFSV2Spec{},
						},
					},
				}

				created, err := regionClient.CreateFileStorage(ctx, request)
				Expect(err).NotTo(HaveOccurred())
				Expect(created).NotTo(BeNil())
				Expect(created.Status.Attachments).To(BeNil(), "Should have no attachments initially")

				filestorageID = created.Metadata.Id
				GinkgoWriter.Printf("Created file storage for attachment test: %s (%s)\n", filestorageName, filestorageID)

				Eventually(func() coreapi.ResourceProvisioningStatus {
					retrieved, err := regionClient.GetFileStorage(ctx, filestorageID)
					if err != nil {
						return ""
					}
					return retrieved.Metadata.ProvisioningStatus
				}).WithTimeout(5*time.Minute).
					WithPolling(10*time.Second).
					Should(Equal(coreapi.ResourceProvisioningStatusProvisioned),
						"File storage should be provisioned before attachment")
			})

			It("should update file storage to add network attachment", func() {
				if filestorageID == "" || networkID == "" {
					Skip("No filestorage or network ID available")
				}

				update := regionopenapi.StorageV2UpdateRequest{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        filestorageName,
						Description: ptr.To("Test file storage with network attachment"),
					},
					Spec: regionopenapi.StorageV2Spec{
						SizeGiB: storageSizeGiB,
						Attachments: &regionopenapi.StorageAttachmentV2Spec{
							NetworkIds: []string{networkID},
						},
						StorageType: regionopenapi.StorageTypeV2Spec{
							NFS: &regionopenapi.NFSV2Spec{},
						},
					},
				}

				updated, err := regionClient.UpdateFileStorage(ctx, filestorageID, update)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated).NotTo(BeNil())
				Expect(updated.Spec.Attachments).NotTo(BeNil(), "Spec should have attachments")
				Expect(updated.Spec.Attachments.NetworkIds).To(ContainElement(networkID))

				GinkgoWriter.Printf("Updated file storage with network attachment: %s\n", networkID)
			})

			It("should verify attachment is available on status with mount info", func() {
				if filestorageID == "" || networkID == "" {
					Skip("No filestorage or network ID available")
				}

				// Attachment is complete when mountSource is present
				// Note: attachment.provisioningStatus may remain "unknown"
				Eventually(func() string {
					retrieved, err := regionClient.GetFileStorage(ctx, filestorageID)
					if err != nil {
						GinkgoWriter.Printf("Error retrieving filestorage: %v\n", err)
						return ""
					}

					if retrieved.Status.Attachments == nil || len(*retrieved.Status.Attachments) == 0 {
						GinkgoWriter.Printf("No attachments in status yet\n")
						return ""
					}

					for _, attachment := range *retrieved.Status.Attachments {
						if attachment.NetworkId == networkID &&
							attachment.MountSource != nil &&
							*attachment.MountSource != "" {
							return *attachment.MountSource
						}
					}

					return ""
				}).WithTimeout(10*time.Minute).
					WithPolling(15*time.Second).
					ShouldNot(BeEmpty(), "Attachment should have mount source populated")

				// Fetch again for full assertions after mount source confirmed
				retrieved, err := regionClient.GetFileStorage(ctx, filestorageID)
				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned),
					"Storage should be provisioned")

				Expect(retrieved.Status.Attachments).NotTo(BeNil())
				Expect(*retrieved.Status.Attachments).To(HaveLen(1), "Should have exactly one attachment")

				attachment := (*retrieved.Status.Attachments)[0]
				Expect(attachment.NetworkId).To(Equal(networkID))
				Expect(attachment.MountSource).NotTo(BeNil(), "MountSource should be present")
				Expect(*attachment.MountSource).NotTo(BeEmpty(), "MountSource should not be empty")
				// Note: attachment.ProvisioningStatus may be "unknown" - this is acceptable and tracked separately

				GinkgoWriter.Printf("Attachment verified:\n")
				GinkgoWriter.Printf("  Network ID: %s\n", attachment.NetworkId)
				GinkgoWriter.Printf("  Mount Source: %s\n", *attachment.MountSource)
				GinkgoWriter.Printf("  Attachment Status: %s (may be 'unknown' - acceptable)\n", attachment.ProvisioningStatus)
				GinkgoWriter.Printf("  Storage Status: %s\n", retrieved.Metadata.ProvisioningStatus)
			})

			It("should remove network attachment from file storage", func() {
				if filestorageID == "" {
					Skip("No filestorage ID available")
				}

				update := regionopenapi.StorageV2UpdateRequest{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        filestorageName,
						Description: ptr.To("Test file storage with attachment removed"),
					},
					Spec: regionopenapi.StorageV2Spec{
						SizeGiB: storageSizeGiB,
						Attachments: &regionopenapi.StorageAttachmentV2Spec{
							NetworkIds: []string{}, // Empty array to remove attachment
						},
						StorageType: regionopenapi.StorageTypeV2Spec{
							NFS: &regionopenapi.NFSV2Spec{},
						},
					},
				}

				updated, err := regionClient.UpdateFileStorage(ctx, filestorageID, update)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated).NotTo(BeNil())
				Expect(updated.Spec.Attachments).NotTo(BeNil())
				Expect(updated.Spec.Attachments.NetworkIds).To(BeEmpty(), "NetworkIds should be empty after removal")

				GinkgoWriter.Printf("Removed network attachment from file storage: %s\n", filestorageID)

				Eventually(func() int {
					retrieved, err := regionClient.GetFileStorage(ctx, filestorageID)
					if err != nil {
						return -1
					}
					if retrieved.Status.Attachments == nil {
						return 0
					}
					return len(*retrieved.Status.Attachments)
				}).WithTimeout(2*time.Minute).
					WithPolling(5*time.Second).
					Should(Equal(0), "Attachment should be removed from status")

				GinkgoWriter.Printf("Confirmed attachment removed from status\n")
			})

			It("should delete the file storage resource after detachment", func() {
				if filestorageID == "" {
					Skip("No filestorage ID available")
				}

				err := regionClient.DeleteFileStorage(ctx, filestorageID)
				Expect(err).NotTo(HaveOccurred())
				filestorageDeleteRequested = true

				GinkgoWriter.Printf("Deleted file storage: %s\n", filestorageID)

				api.WaitForFileStorageGone(regionClient, ctx, filestorageID)

				GinkgoWriter.Printf("Confirmed file storage deleted: %s\n", filestorageID)
				filestorageID = "" // suppress AfterAll cleanup; storage has been confirmed deleted
			})

			It("should delete the network resource", func() {
				if networkID == "" {
					Skip("No network ID available")
				}

				err := regionClient.DeleteNetwork(ctx, networkID)
				Expect(err).NotTo(HaveOccurred())

				GinkgoWriter.Printf("Deleted network: %s\n", networkID)

				Eventually(func() int {
					networks, err := regionClient.ListNetworks(ctx, config.OrgID, config.ProjectID, config.RegionID)
					if err != nil {
						return -1
					}
					count := 0
					for _, n := range networks {
						if n.Metadata.Id == networkID {
							count++
						}
					}
					return count
				}).WithTimeout(2*time.Minute).
					WithPolling(5*time.Second).
					Should(Equal(0), "Network should be deleted")

				GinkgoWriter.Printf("Confirmed network deleted: %s\n", networkID)
				networkID = "" // suppress cleanup — already deleted
			})
		})

		AfterAll(func() {
			// Delete storage first to detach from network
			if filestorageID != "" {
				if !filestorageDeleteRequested {
					GinkgoWriter.Printf("Cleaning up test filestorage: %s\n", filestorageID)
					Expect(regionClient.DeleteFileStorage(ctx, filestorageID)).To(Succeed())
					filestorageDeleteRequested = true
				}

				GinkgoWriter.Printf("Waiting for storage cleanup: %s\n", filestorageID)
				api.WaitForFileStorageGone(regionClient, ctx, filestorageID)
			}

			if networkID != "" {
				GinkgoWriter.Printf("Cleaning up test network: %s\n", networkID)
				Expect(regionClient.DeleteNetwork(ctx, networkID)).To(Succeed())
			}
		})
	})
})
