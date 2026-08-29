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

//nolint:revive,testpackage // dot imports and package naming standard for Ginkgo
package suites

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/unikorn-cloud/core/pkg/openapi"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coretestutil "github.com/unikorn-cloud/core/pkg/testing/util"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"
)

var _ = Describe("Network deprovisioning", func() {
	When("file storage was previously attached and then deleted", func() {
		It("should allow the network to be deleted without hanging", func() {
			var storageClassNFS *regionapi.StorageClassV2Read
			By("retrieving NFS storage class", func() {
				storageClassNFS = mustGetStorageClassNFS()
				GinkgoWriter.Printf("Using storage class '%s' with ID '%s'\n", storageClassNFS.Metadata.Name, storageClassNFS.Metadata.Id)
			})

			var network *regionapi.NetworkV2Read
			By("creating a network", func() {
				network = mustCreateNetworkWithCleanup()
				GinkgoWriter.Printf("Created network '%s' with ID '%s', which will be removed at the end of the test\n", network.Metadata.Name, network.Metadata.Id)
			})

			By("waiting for the network to be ready", func() {
				network = mustWaitForNetworkReady(network.Metadata.Id)
				GinkgoWriter.Printf("Network '%s' is now ready\n", network.Metadata.Id)
			})

			var fileStorage *regionapi.StorageV2Read
			By("creating a file storage and attaching it to the network", func() {
				fileStorage = mustCreateFileStorageWithCleanup(network.Metadata.Id, storageClassNFS.Metadata.Id)
				GinkgoWriter.Printf("Created file storage '%s' with ID '%s', which will be removed at the end of the test\n", fileStorage.Metadata.Name, fileStorage.Metadata.Id)
			})

			By("waiting for the file storage to be ready", func() {
				fileStorage = mustWaitForFileStorageReady(fileStorage.Metadata.Id)
				GinkgoWriter.Printf("File storage '%s' is now ready\n", fileStorage.Metadata.Id)
			})

			By("deleting the file storage", func() {
				mustDeleteFileStorage(fileStorage.Metadata.Id)
				GinkgoWriter.Printf("Requested deletion of file storage '%s'\n", fileStorage.Metadata.Id)
			})

			By("waiting for the file storage to be deleted", func() {
				mustWaitForFileStorageDeleted(fileStorage.Metadata.Id)
				GinkgoWriter.Printf("File storage '%s' has now been deleted\n", fileStorage.Metadata.Id)
			})

			By("deleting the network", func() {
				mustDeleteNetwork(network.Metadata.Id)
				GinkgoWriter.Printf("Requested deletion of network '%s'\n", network.Metadata.Id)
			})

			By("waiting for the network to be deleted", func() {
				mustWaitForNetworkDeleted(network.Metadata.Id)
				GinkgoWriter.Printf("Network '%s' has now been deleted\n", network.Metadata.Id)
			})
		})
	})
})

func doRequest(request *http.Request) *http.Response {
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.AuthToken))

	response, err := http.DefaultClient.Do(request)
	Expect(err).NotTo(HaveOccurred())

	return response
}

func parseJSONPointer[T any](reader io.Reader) *T {
	var data T
	Expect(json.NewDecoder(reader).Decode(&data)).To(Succeed())
	return &data
}

func parseJSONValue[T any](reader io.Reader) T {
	var data T
	Expect(json.NewDecoder(reader).Decode(&data)).To(Succeed())
	return data
}

func listStorageClasses() *http.Response {
	params := &regionapi.GetApiV2FilestorageclassesParams{
		RegionID: &regionapi.RegionIDQueryParameter{
			config.RegionID,
		},
	}

	request, err := regionapi.NewGetApiV2FilestorageclassesRequest(config.BaseURL, params)
	Expect(err).NotTo(HaveOccurred())

	return doRequest(request)
}

func mustGetStorageClassNFS() *regionapi.StorageClassV2Read {
	response := listStorageClasses()
	defer response.Body.Close()

	Expect(response.StatusCode).To(Equal(http.StatusOK))

	storageClasses := parseJSONValue[[]regionapi.StorageClassV2Read](response.Body)

	for _, storageClass := range storageClasses {
		for _, protocol := range storageClass.Spec.Protocols {
			if protocol == regionapi.StorageClassProtocolTypeNfsv3 || protocol == regionapi.StorageClassProtocolTypeNfsv4 {
				return &storageClass
			}
		}
	}

	Fail("no NFS storage class found")

	return nil
}

func createNetwork() *http.Response {
	params := regionapi.NetworkV2Create{
		Metadata: openapi.ResourceWriteMetadata{
			Name: coretestutil.GenerateTestID(),
		},
		Spec: regionapi.NetworkV2CreateSpec{
			DnsNameservers: []string{
				"8.8.8.8",
				"8.8.4.4",
			},
			OrganizationId: config.OrgID,
			Prefix:         "192.168.0.0/24",
			ProjectId:      config.ProjectID,
			RegionId:       config.RegionID,
		},
	}

	request, err := regionapi.NewPostApiV2NetworksRequest(config.BaseURL, params)
	Expect(err).NotTo(HaveOccurred())

	return doRequest(request)
}

func getNetwork(networkID string) *http.Response {
	request, err := regionapi.NewGetApiV2NetworksNetworkIDRequest(config.BaseURL, networkID)
	Expect(err).NotTo(HaveOccurred())

	return doRequest(request)
}

func deleteNetwork(networkID string) *http.Response {
	request, err := regionapi.NewDeleteApiV2NetworksNetworkIDRequest(config.BaseURL, networkID)
	Expect(err).NotTo(HaveOccurred())

	return doRequest(request)
}

func mustCreateNetworkWithCleanup() *regionapi.NetworkV2Read {
	response := createNetwork()
	defer response.Body.Close()

	Expect(response.StatusCode).To(Equal(http.StatusCreated))

	network := parseJSONPointer[regionapi.NetworkV2Read](response.Body)

	DeferCleanup(func() {
		networkID := network.Metadata.Id

		networkDeleteResponse := deleteNetwork(networkID)
		defer networkDeleteResponse.Body.Close()

		Expect(networkDeleteResponse.StatusCode).To(Equal(http.StatusAccepted), "failed to delete network '%s'", networkID)
	})

	return network
}

func mustWaitForNetworkReady(networkID string) *regionapi.NetworkV2Read {
	var provisioned *regionapi.NetworkV2Read

	Eventually(func() error {
		response := getNetwork(networkID)
		defer response.Body.Close()

		if response.StatusCode == http.StatusNotFound {
			return fmt.Errorf("network '%s' not found", networkID)
		}

		if response.StatusCode != http.StatusOK {
			return StopTrying("failed to get network").
				Attach("network_id", networkID).
				Attach("status_code", response.StatusCode)
		}

		network := parseJSONPointer[regionapi.NetworkV2Read](response.Body)

		if status := network.Metadata.ProvisioningStatus; status != coreapi.ResourceProvisioningStatusProvisioned {
			return fmt.Errorf("network '%s' is in provisioning status '%s' and not yet provisioned", networkID, status)
		}

		provisioned = network

		return nil
	}).
		WithTimeout(30*time.Minute).
		WithPolling(15*time.Second).
		Should(Succeed(), "network '%s' did not become ready within the timeout", networkID)

	return provisioned
}

func mustDeleteNetwork(networkID string) {
	response := deleteNetwork(networkID)
	defer response.Body.Close()

	Expect(response.StatusCode).To(Equal(http.StatusAccepted), "failed to delete network '%s'", networkID)
}

func mustWaitForNetworkDeleted(networkID string) {
	Eventually(func() error {
		response := getNetwork(networkID)
		defer response.Body.Close()

		if response.StatusCode == http.StatusNotFound {
			return nil
		}

		if response.StatusCode != http.StatusOK {
			return StopTrying("failed to get network").
				Attach("network_id", networkID).
				Attach("status_code", response.StatusCode)
		}

		return fmt.Errorf("network '%s' is still present and not yet deleted", networkID)
	}).
		WithTimeout(10*time.Minute).
		WithPolling(15*time.Second).
		Should(Succeed(), "network '%s' did not get deleted within the timeout", networkID)
}

func createFileStorage(networkID, storageClassID string) *http.Response {
	params := regionapi.StorageV2Create{
		Metadata: openapi.ResourceWriteMetadata{
			Name: coretestutil.GenerateTestID(),
		},
		Spec: struct {
			Attachments    *regionapi.StorageAttachmentV2Spec `json:"attachments,omitempty"`
			OrganizationId string                             `json:"organizationId"`
			ProjectId      string                             `json:"projectId"`
			RegionId       string                             `json:"regionId"`
			SizeGiB        int64                              `json:"sizeGiB"`
			StorageClassId string                             `json:"storageClassId"`
			StorageType    regionapi.StorageTypeV2Spec        `json:"storageType"`
		}{
			Attachments: &regionapi.StorageAttachmentV2Spec{
				NetworkIds: []string{networkID},
			},
			OrganizationId: config.OrgID,
			ProjectId:      config.ProjectID,
			RegionId:       config.RegionID,
			SizeGiB:        20,
			StorageClassId: storageClassID,
			StorageType: regionapi.StorageTypeV2Spec{
				NFS: &regionapi.NFSV2Spec{
					RootSquash: true,
				},
			},
		},
	}

	request, err := regionapi.NewPostApiV2FilestorageRequest(config.BaseURL, params)
	Expect(err).NotTo(HaveOccurred())

	return doRequest(request)
}

func getFileStorage(fileStorageID string) *http.Response {
	request, err := regionapi.NewGetApiV2FilestorageFilestorageIDRequest(config.BaseURL, fileStorageID)
	Expect(err).NotTo(HaveOccurred())

	return doRequest(request)
}

func deleteFileStorage(fileStorageID string) *http.Response {
	request, err := regionapi.NewDeleteApiV2FilestorageFilestorageIDRequest(config.BaseURL, fileStorageID)
	Expect(err).NotTo(HaveOccurred())

	return doRequest(request)
}

func mustCreateFileStorageWithCleanup(networkID, storageClassID string) *regionapi.StorageV2Read {
	response := createFileStorage(networkID, storageClassID)
	defer response.Body.Close()

	Expect(response.StatusCode).To(Equal(http.StatusCreated))

	fileStorage := parseJSONPointer[regionapi.StorageV2Read](response.Body)

	DeferCleanup(func() {
		fileStorageID := fileStorage.Metadata.Id

		storageDeleteResponse := deleteFileStorage(fileStorageID)
		defer storageDeleteResponse.Body.Close()

		Expect(storageDeleteResponse.StatusCode).To(Equal(http.StatusAccepted), "failed to delete file storage '%s'", fileStorageID)
	})

	return fileStorage
}

func mustWaitForFileStorageReady(fileStorageID string) *regionapi.StorageV2Read {
	var provisioned *regionapi.StorageV2Read

	Eventually(func() error {
		response := getFileStorage(fileStorageID)
		defer response.Body.Close()

		if response.StatusCode == http.StatusNotFound {
			return fmt.Errorf("file storage '%s' not found", fileStorageID)
		}

		if response.StatusCode != http.StatusOK {
			return StopTrying("failed to get file storage").
				Attach("file_storage_id", fileStorageID).
				Attach("status_code", response.StatusCode)
		}

		fileStorage := parseJSONPointer[regionapi.StorageV2Read](response.Body)

		if status := fileStorage.Metadata.ProvisioningStatus; status != coreapi.ResourceProvisioningStatusProvisioned {
			return fmt.Errorf("file storage '%s' is in provisioning status '%s' and not yet provisioned", fileStorageID, status)
		}

		provisioned = fileStorage

		return nil
	}).
		WithTimeout(30*time.Minute).
		WithPolling(15*time.Second).
		Should(Succeed(), "file storage '%s' did not become ready within the timeout", fileStorageID)

	return provisioned
}

func mustDeleteFileStorage(fileStorageID string) {
	response := deleteFileStorage(fileStorageID)
	defer response.Body.Close()

	Expect(response.StatusCode).To(Equal(http.StatusAccepted), "failed to delete file storage '%s'", fileStorageID)
}

func mustWaitForFileStorageDeleted(fileStorageID string) {
	Eventually(func() error {
		response := getFileStorage(fileStorageID)
		defer response.Body.Close()

		if response.StatusCode == http.StatusNotFound {
			return nil
		}

		if response.StatusCode != http.StatusOK {
			return StopTrying("failed to get file storage").
				Attach("file_storage_id", fileStorageID).
				Attach("status_code", response.StatusCode)
		}

		return fmt.Errorf("file storage '%s' is still present and not yet deleted", fileStorageID)
	}).
		WithTimeout(10*time.Minute).
		WithPolling(15*time.Second).
		Should(Succeed(), "file storage '%s' did not get deleted within the timeout", fileStorageID)
}
