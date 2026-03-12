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
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"golang.org/x/crypto/ssh"
	"k8s.io/utils/ptr"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	coreutil "github.com/unikorn-cloud/core/pkg/testing/util"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
)

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

				storageList, err := regionClient.ListFileStorage(ctx, config.OrgID, config.ProjectID, config.RegionID)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(storageList)).To(BeNumerically(">=", 1), "Should have at least one storage resource")

				found := false
				for _, storage := range storageList {
					// Validate ALL items in collection have required fields
					Expect(storage.Metadata).NotTo(BeNil())
					Expect(storage.Metadata.Id).NotTo(BeEmpty())
					Expect(storage.Metadata.Name).NotTo(BeEmpty())
					Expect(storage.Spec.SizeGiB).To(BeNumerically(">", 0))
					Expect(storage.Status.StorageClassId).NotTo(BeEmpty())
					Expect(storage.Status.RegionId).NotTo(BeEmpty())

					if storage.Metadata.Id == testStorageID {
						found = true
						Expect(storage.Metadata.Name).To(Equal(testStorageName))
						Expect(storage.Metadata.OrganizationId).To(Equal(config.OrgID))
						Expect(storage.Metadata.ProjectId).To(Equal(config.ProjectID))
						GinkgoWriter.Printf("  Found our test storage: %s (%s) - %dGiB\n",
							storage.Metadata.Name,
							storage.Metadata.Id,
							storage.Spec.SizeGiB)
					}
				}

				Expect(found).To(BeTrue(), "Created storage should be in the list")
				GinkgoWriter.Printf("Found %d total file storage resources\n", len(storageList))
			})

			AfterEach(func() {
				if testStorageID != "" {
					GinkgoWriter.Printf("Cleaning up test list storage: %s\n", testStorageID)
					if err := regionClient.DeleteFileStorage(ctx, testStorageID); err != nil {
						GinkgoWriter.Printf("Warning: Failed to cleanup test storage %s: %v\n", testStorageID, err)
					}
				}
			})
		})

		Describe("Given invalid parameters", func() {
			It("should reject requests with invalid organization ID format", func() {
				Skip("Bug INST-457: File Storage API accepts invalid organizationId and returns data for different organization")
				invalidOrgID := "not-a-valid-uuid"
				path := regionClient.GetEndpoints().ListFileStorage(invalidOrgID, config.ProjectID, config.RegionID)
				_, respBody, err := regionClient.DoRegionRequest(ctx, http.MethodGet, path, nil, http.StatusOK)

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrUnexpectedStatusCode)).To(BeTrue())
				Expect(string(respBody)).To(Or(ContainSubstring("forbidden"), ContainSubstring("not found")))
				GinkgoWriter.Printf("Expected error for invalid organization ID: %v\n", err)
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
				Expect(retrieved.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))

				GinkgoWriter.Printf("Retrieved file storage: %s (%s) - %dGiB (Status: %s)\n",
					retrieved.Metadata.Name,
					retrieved.Metadata.Id,
					retrieved.Spec.SizeGiB,
					retrieved.Metadata.ProvisioningStatus)
			})

			It("should update the file storage resource", func() {
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
				Expect(updated.Metadata.Description).NotTo(BeNil())
				Expect(*updated.Metadata.Description).To(Equal("Updated test file storage"))
				Expect(updated.Spec.SizeGiB).To(Equal(updatedStorageSizeGiB))

				GinkgoWriter.Printf("Updated file storage: %s (%s) - now %dGiB\n",
					updated.Metadata.Name,
					updated.Metadata.Id,
					updated.Spec.SizeGiB)
			})

			It("should delete the file storage resource", func() {
				err := regionClient.DeleteFileStorage(ctx, filestorageID)

				Expect(err).NotTo(HaveOccurred())

				GinkgoWriter.Printf("Deleted file storage: %s\n", filestorageID)
			})

			It("should not find the deleted file storage resource", func() {
				Eventually(func() error {
					_, err := regionClient.GetFileStorage(ctx, filestorageID)
					return err
				}).WithTimeout(30*time.Second).
					WithPolling(2*time.Second).
					Should(And(HaveOccurred(), MatchError(coreclient.ErrUnexpectedStatusCode)),
						"Resource should eventually return 404")

				GinkgoWriter.Printf("Confirmed file storage deleted: %s\n", filestorageID)
			})
		})

		AfterAll(func() {
			if filestorageID != "" {
				GinkgoWriter.Printf("Cleaning up test filestorage: %s\n", filestorageID)
				if err := regionClient.DeleteFileStorage(ctx, filestorageID); err != nil {
					GinkgoWriter.Printf("Warning: Failed to cleanup filestorage %s: %v\n", filestorageID, err)
				}
			}
		})
	})

	Context("When verifying NFS storage mount source format on attachment", Ordered, func() {
		const storageSizeGiB = int64(10)

		var filestorageID string
		var storageClassID string
		var networkID string

		Describe("Given an NFS storage class and network", func() {
			It("should find a storage class with NFS protocol support", func() {
				storageClasses, err := regionClient.ListFileStorageClasses(ctx, config.RegionID)
				Expect(err).NotTo(HaveOccurred())

				if len(storageClasses) == 0 {
					Skip(fmt.Sprintf("No storage classes allocated to region %s", config.RegionID))
				}

				// Select the highest parallelism class (best performance, typical of VAST)
				best := storageClasses[0]
				for _, sc := range storageClasses[1:] {
					if sc.Spec.Parallelism > best.Spec.Parallelism {
						best = sc
					}
				}

				storageClassID = best.Metadata.Id
				GinkgoWriter.Printf("Selected storage class: %s (parallelism=%d, protocols=%v)\n",
					best.Metadata.Name, best.Spec.Parallelism, best.Spec.Protocols)
			})

			It("should use or create a network for VAST storage attachment", func() {
				if config.NetworkID != "" {
					networkID = config.NetworkID
					GinkgoWriter.Printf("Using pre-existing network for VAST: %s\n", networkID)
					return
				}

				network, err := regionClient.CreateNetwork(ctx, regionopenapi.NetworkV2CreateRequest{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        coreutil.GenerateRandomName("test-vast-network"),
						Description: ptr.To("Test network for VAST storage attachment"),
					},
					Spec: regionopenapi.NetworkV2CreateSpec{
						OrganizationId: config.OrgID,
						ProjectId:      config.ProjectID,
						RegionId:       config.RegionID,
						Prefix:         "10.0.1.0/24",
						DnsNameservers: regionopenapi.Ipv4AddressList{"8.8.8.8", "8.8.4.4"},
					},
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(network).NotTo(BeNil())
				networkID = network.Metadata.Id
				GinkgoWriter.Printf("Created network for VAST: %s (%s)\n", network.Metadata.Name, networkID)

				Eventually(func() coreapi.ResourceProvisioningStatus {
					n, err := regionClient.GetNetwork(ctx, networkID)
					if err != nil {
						return ""
					}
					if n.Metadata.ProvisioningStatus == coreapi.ResourceProvisioningStatusError {
						Fail(fmt.Sprintf("Network %s entered error state - check network controller logs for region %s", networkID, config.RegionID))
					}
					return n.Metadata.ProvisioningStatus
				}).WithTimeout(5*time.Minute).
					WithPolling(10*time.Second).
					Should(Equal(coreapi.ResourceProvisioningStatusProvisioned),
						"Network should be provisioned before attaching storage")
			})

			It("should create VAST-backed storage with network attachment", func() {
				created, err := regionClient.CreateFileStorage(ctx, regionopenapi.StorageV2CreateRequest{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        coreutil.GenerateRandomName("test-vast-storage"),
						Description: ptr.To("VAST NFS storage on NKS"),
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
						SizeGiB:        storageSizeGiB,
						StorageClassId: storageClassID,
						Attachments: &regionopenapi.StorageAttachmentV2Spec{
							NetworkIds: []string{networkID},
						},
						StorageType: regionopenapi.StorageTypeV2Spec{NFS: &regionopenapi.NFSV2Spec{}},
					},
				})
				Expect(err).NotTo(HaveOccurred())
				filestorageID = created.Metadata.Id
				GinkgoWriter.Printf("Created VAST storage: %s\n", filestorageID)
			})

			It("should expose a mount source in <host>:<path> format", func() {
				var mountSource string
				Eventually(func() string {
					retrieved, err := regionClient.GetFileStorage(ctx, filestorageID)
					if err != nil {
						return ""
					}
					if retrieved.Status.Attachments == nil || len(*retrieved.Status.Attachments) == 0 {
						return ""
					}
					for _, att := range *retrieved.Status.Attachments {
						if att.NetworkId == networkID && att.MountSource != nil && *att.MountSource != "" {
							mountSource = *att.MountSource
							return mountSource
						}
					}
					return ""
				}).WithTimeout(10*time.Minute).
					WithPolling(15*time.Second).
					ShouldNot(BeEmpty(), "NFS storage must expose a mount source")

				// NFS mount sources are in "host:/path" format, e.g. "10.0.0.16:/mnt/nfs"
				parts := strings.SplitN(mountSource, ":", 2)
				Expect(parts).To(HaveLen(2), "Mount source must be host:path format, got: %s", mountSource)
				Expect(parts[0]).NotTo(BeEmpty(), "Mount host must not be empty")
				Expect(parts[1]).To(HavePrefix("/"), "Mount path must be absolute, got: %s", parts[1])

				GinkgoWriter.Printf("NFS mount source validated: host=%s path=%s\n", parts[0], parts[1])
			})

			It("should delete VAST storage", func() {
				err := regionClient.DeleteFileStorage(ctx, filestorageID)
				Expect(err).NotTo(HaveOccurred())
				GinkgoWriter.Printf("Deleted VAST storage: %s\n", filestorageID)
			})
		})

		AfterAll(func() {
			if filestorageID != "" {
				if err := regionClient.DeleteFileStorage(ctx, filestorageID); err != nil {
					GinkgoWriter.Printf("Warning: Failed to cleanup VAST storage %s: %v\n", filestorageID, err)
				}
			}
			if networkID != "" && config.NetworkID == "" {
				if err := regionClient.DeleteNetwork(ctx, networkID); err != nil {
					GinkgoWriter.Printf("Warning: Failed to cleanup VAST network %s: %v\n", networkID, err)
				}
			}
		})
	})

	Context("When verifying storage via SSH on a provisioned server", Ordered, func() {
		const storageSizeGiB = int64(10)

		var filestorageID string
		var networkID string
		var serverID string
		var mountSource string

		Describe("Given a server on the same network as file storage", func() {
			BeforeAll(func() {
				if config.FlavorID == "" || config.ImageID == "" {
					Skip("TEST_FLAVOR_ID and TEST_IMAGE_ID must be set to run SSH storage verification tests")
				}
			})

			It("should create a network for server and storage", func() {
				network, err := regionClient.CreateNetwork(ctx, regionopenapi.NetworkV2CreateRequest{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        coreutil.GenerateRandomName("test-ssh-network"),
						Description: ptr.To("Test network for SSH storage verification"),
					},
					Spec: regionopenapi.NetworkV2CreateSpec{
						OrganizationId: config.OrgID,
						ProjectId:      config.ProjectID,
						RegionId:       config.RegionID,
						Prefix:         "10.0.1.0/24",
						DnsNameservers: regionopenapi.Ipv4AddressList{"8.8.8.8", "8.8.4.4"},
					},
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(network).NotTo(BeNil())
				networkID = network.Metadata.Id
				GinkgoWriter.Printf("Created network for SSH test: %s (%s)\n", network.Metadata.Name, networkID)

				Eventually(func() coreapi.ResourceProvisioningStatus {
					n, err := regionClient.GetNetwork(ctx, networkID)
					if err != nil {
						return ""
					}
					if n.Metadata.ProvisioningStatus == coreapi.ResourceProvisioningStatusError {
						Fail(fmt.Sprintf("Network %s entered error state - check network controller logs for region %s", networkID, config.RegionID))
					}
					return n.Metadata.ProvisioningStatus
				}).WithTimeout(5*time.Minute).
					WithPolling(10*time.Second).
					Should(Equal(coreapi.ResourceProvisioningStatusProvisioned),
						"Network should be provisioned before creating servers")
			})

			It("should create file storage with network attachment", func() {
				storageClasses, err := regionClient.ListFileStorageClasses(ctx, config.RegionID)
				Expect(err).NotTo(HaveOccurred())

				if len(storageClasses) == 0 {
					Skip(fmt.Sprintf("No storage classes allocated to region %s", config.RegionID))
				}

				created, err := regionClient.CreateFileStorage(ctx, regionopenapi.StorageV2CreateRequest{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        coreutil.GenerateRandomName("test-ssh-storage"),
						Description: ptr.To("Storage for SSH verification"),
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
						SizeGiB:        storageSizeGiB,
						StorageClassId: storageClasses[0].Metadata.Id,
						Attachments: &regionopenapi.StorageAttachmentV2Spec{
							NetworkIds: []string{networkID},
						},
						StorageType: regionopenapi.StorageTypeV2Spec{NFS: &regionopenapi.NFSV2Spec{}},
					},
				})
				Expect(err).NotTo(HaveOccurred())
				filestorageID = created.Metadata.Id

				Eventually(func() string {
					retrieved, err := regionClient.GetFileStorage(ctx, filestorageID)
					if err != nil {
						return ""
					}
					if retrieved.Status.Attachments == nil || len(*retrieved.Status.Attachments) == 0 {
						return ""
					}
					for _, att := range *retrieved.Status.Attachments {
						if att.NetworkId == networkID && att.MountSource != nil && *att.MountSource != "" {
							return *att.MountSource
						}
					}
					return ""
				}).WithTimeout(10*time.Minute).
					WithPolling(15*time.Second).
					ShouldNot(BeEmpty(), "Storage must have mount source before server creation")

				retrieved, err := regionClient.GetFileStorage(ctx, filestorageID)
				Expect(err).NotTo(HaveOccurred())
				for _, att := range *retrieved.Status.Attachments {
					if att.NetworkId == networkID && att.MountSource != nil {
						mountSource = *att.MountSource
						break
					}
				}
				GinkgoWriter.Printf("Storage provisioned with mount source: %s\n", mountSource)
			})

			It("should provision a server with cloud-init to mount the NFS storage", func() {
				mountScript := fmt.Sprintf(`#!/bin/bash
apt-get update -qq && apt-get install -y -qq nfs-common
mkdir -p /mnt/vast
mount -t nfs %s /mnt/vast
echo "storage-ok" > /mnt/vast/marker.txt
sync
`, mountSource)
				userData := []byte(mountScript)

				server, err := regionClient.CreateServer(ctx, regionopenapi.ServerV2CreateRequest{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        coreutil.GenerateRandomName("test-ssh-server"),
						Description: ptr.To("Server for SSH storage verification"),
					},
					Spec: regionopenapi.ServerV2CreateSpec{
						FlavorId:  config.FlavorID,
						ImageId:   config.ImageID,
						NetworkId: networkID,
						Networking: &regionopenapi.ServerV2Networking{
							PublicIP: ptr.To(true),
						},
						UserData: &userData,
					},
				})
				Expect(err).NotTo(HaveOccurred())
				serverID = server.Metadata.Id
				GinkgoWriter.Printf("Created server: %s\n", serverID)
			})

			It("should wait for the server to be Running with a public IP", func() {
				Eventually(func() regionopenapi.InstanceLifecyclePhase {
					server, err := regionClient.GetServer(ctx, serverID)
					if err != nil || server.Status.PowerState == nil {
						return ""
					}
					GinkgoWriter.Printf("Server power state: %s\n", *server.Status.PowerState)
					return *server.Status.PowerState
				}).WithTimeout(15 * time.Minute).
					WithPolling(15 * time.Second).
					Should(Equal(regionopenapi.InstanceLifecyclePhaseRunning))

				server, err := regionClient.GetServer(ctx, serverID)
				Expect(err).NotTo(HaveOccurred())
				Expect(server.Status.PublicIP).NotTo(BeNil(), "Server must have a public IP for SSH access")
				GinkgoWriter.Printf("Server running at: %s\n", *server.Status.PublicIP)
			})

			It("should SSH into the server and verify the NFS mount", func() {
				sshKey, err := regionClient.GetServerSSHKey(ctx, serverID)
				Expect(err).NotTo(HaveOccurred())
				Expect(sshKey.PrivateKey).NotTo(BeEmpty())

				server, err := regionClient.GetServer(ctx, serverID)
				Expect(err).NotTo(HaveOccurred())

				signer, err := ssh.ParsePrivateKey([]byte(sshKey.PrivateKey))
				Expect(err).NotTo(HaveOccurred())

				sshUser := config.SSHUser
				if sshUser == "" {
					sshUser = "ubuntu"
				}

				sshCfg := &ssh.ClientConfig{
					User: sshUser,
					Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
					//nolint:gosec // G106: InsecureIgnoreHostKey acceptable for ephemeral test VMs
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Timeout:         30 * time.Second,
				}

				var sshClient *ssh.Client
				Eventually(func() error {
					c, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", *server.Status.PublicIP), sshCfg)
					if err != nil {
						GinkgoWriter.Printf("Waiting for SSH: %v\n", err)
						return err
					}
					sshClient = c
					return nil
				}).WithTimeout(5 * time.Minute).
					WithPolling(15 * time.Second).
					Should(Succeed())

				defer sshClient.Close() //nolint:errcheck

				// Wait for cloud-init to complete before checking the mount and marker.
				// SSH becomes available before cloud-init finishes, so without this
				// the NFS mount and marker file may not be present yet.
				GinkgoWriter.Printf("Waiting for cloud-init to complete...\n")
				cloudInitOut := sshRun(sshClient, "cloud-init status --wait")
				GinkgoWriter.Printf("cloud-init status: %s\n", strings.TrimSpace(cloudInitOut))

				// Verify the NFS storage is mounted
				mountOut := sshRun(sshClient, "mount | grep nfs")
				Expect(mountOut).NotTo(BeEmpty(), "NFS should appear in mount list")
				GinkgoWriter.Printf("NFS mount entry: %s\n", mountOut)

				// Verify the marker written by cloud-init is present
				markerOut := sshRun(sshClient, "cat /mnt/vast/marker.txt")
				Expect(strings.TrimSpace(markerOut)).To(Equal("storage-ok"))
				GinkgoWriter.Printf("Storage marker verified on server\n")
			})

			It("should delete the test server", func() {
				Expect(regionClient.DeleteServer(ctx, serverID)).To(Succeed())
				GinkgoWriter.Printf("Deleted SSH test server: %s\n", serverID)
			})

			It("should delete the test storage", func() {
				Expect(regionClient.DeleteFileStorage(ctx, filestorageID)).To(Succeed())
				GinkgoWriter.Printf("Deleted SSH test storage: %s\n", filestorageID)
			})

			It("should delete the test network", func() {
				Expect(regionClient.DeleteNetwork(ctx, networkID)).To(Succeed())
				GinkgoWriter.Printf("Deleted SSH test network: %s\n", networkID)
			})
		})

		AfterAll(func() {
			if serverID != "" {
				if err := regionClient.DeleteServer(ctx, serverID); err != nil {
					GinkgoWriter.Printf("Warning: Failed to cleanup server %s: %v\n", serverID, err)
				}
			}
			if filestorageID != "" {
				if err := regionClient.DeleteFileStorage(ctx, filestorageID); err != nil {
					GinkgoWriter.Printf("Warning: Failed to cleanup storage %s: %v\n", filestorageID, err)
				}
			}
			if networkID != "" {
				if err := regionClient.DeleteNetwork(ctx, networkID); err != nil {
					GinkgoWriter.Printf("Warning: Failed to cleanup network %s: %v\n", networkID, err)
				}
			}
		})
	})

	Context("When managing file storage attachments", Ordered, func() {
		const storageSizeGiB = int64(10)

		var filestorageID string
		var filestorageName string
		var storageClassID string
		var networkID string

		Describe("Given a network and file storage resource", func() {
			It("should create a network for attachment", func() {
				network, err := regionClient.CreateNetwork(ctx, regionopenapi.NetworkV2CreateRequest{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        coreutil.GenerateRandomName("test-attach-network"),
						Description: ptr.To("Test network for file storage attachment lifecycle"),
					},
					Spec: regionopenapi.NetworkV2CreateSpec{
						OrganizationId: config.OrgID,
						ProjectId:      config.ProjectID,
						RegionId:       config.RegionID,
						Prefix:         "10.0.1.0/24",
						DnsNameservers: regionopenapi.Ipv4AddressList{"8.8.8.8", "8.8.4.4"},
					},
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(network).NotTo(BeNil())
				networkID = network.Metadata.Id
				GinkgoWriter.Printf("Created network for attachment: %s (%s)\n", network.Metadata.Name, networkID)

				Eventually(func() coreapi.ResourceProvisioningStatus {
					n, err := regionClient.GetNetwork(ctx, networkID)
					if err != nil {
						return ""
					}
					if n.Metadata.ProvisioningStatus == coreapi.ResourceProvisioningStatusError {
						Fail(fmt.Sprintf("Network %s entered error state - check network controller logs for region %s", networkID, config.RegionID))
					}
					return n.Metadata.ProvisioningStatus
				}).WithTimeout(5*time.Minute).
					WithPolling(10*time.Second).
					Should(Equal(coreapi.ResourceProvisioningStatusProvisioned),
						"Network should be provisioned before attaching storage")
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
				// Attachment is complete when mountSource is present
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

				GinkgoWriter.Printf("Attachment verified:\n")
				GinkgoWriter.Printf("  Network ID: %s\n", attachment.NetworkId)
				GinkgoWriter.Printf("  Mount Source: %s\n", *attachment.MountSource)
				GinkgoWriter.Printf("  Attachment Status: %s\n", attachment.ProvisioningStatus)
				GinkgoWriter.Printf("  Storage Status: %s\n", retrieved.Metadata.ProvisioningStatus)
			})

			It("should remove network attachment from file storage", func() {
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
				err := regionClient.DeleteFileStorage(ctx, filestorageID)
				Expect(err).NotTo(HaveOccurred())

				GinkgoWriter.Printf("Deleted file storage: %s\n", filestorageID)

				Eventually(func() error {
					_, err := regionClient.GetFileStorage(ctx, filestorageID)
					return err
				}).WithTimeout(2*time.Minute).
					WithPolling(5*time.Second).
					Should(And(HaveOccurred(), MatchError(coreclient.ErrUnexpectedStatusCode)),
						"Storage should be deleted")

				GinkgoWriter.Printf("Confirmed file storage deleted: %s\n", filestorageID)
			})

			It("should delete the network resource", func() {
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
			})
		})

		AfterAll(func() {
			// Delete storage first to detach from network
			if filestorageID != "" {
				GinkgoWriter.Printf("Cleaning up test filestorage: %s\n", filestorageID)
				if err := regionClient.DeleteFileStorage(ctx, filestorageID); err != nil {
					GinkgoWriter.Printf("Warning: Failed to cleanup filestorage %s: %v\n", filestorageID, err)
				}
			}

			if networkID != "" {
				GinkgoWriter.Printf("Waiting for storage detachment before network cleanup...\n")
				Eventually(func() error {
					_, err := regionClient.GetFileStorage(ctx, filestorageID)
					return err
				}).WithTimeout(2*time.Minute).
					WithPolling(5*time.Second).
					Should(And(HaveOccurred(), MatchError(coreclient.ErrUnexpectedStatusCode)),
						"Storage should be deleted before network cleanup")

				GinkgoWriter.Printf("Cleaning up test network: %s\n", networkID)
				if err := regionClient.DeleteNetwork(ctx, networkID); err != nil {
					GinkgoWriter.Printf("Warning: Failed to cleanup network %s: %v\n", networkID, err)
				}
			}
		})
	})
})

// sshRun executes a command on an SSH client and returns the combined output.
// Non-zero exit codes are logged but not returned — callers assert on the output content.
func sshRun(client *ssh.Client, cmd string) string {
	sess, err := client.NewSession()
	if err != nil {
		GinkgoWriter.Printf("Failed to create SSH session: %v\n", err)
		return ""
	}
	defer sess.Close() //nolint:errcheck

	out, err := sess.CombinedOutput(cmd)
	if err != nil {
		GinkgoWriter.Printf("Command %q exited with error: %v\n", cmd, err)
	}
	return string(out)
}
