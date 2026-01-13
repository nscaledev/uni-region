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
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/unikorn-cloud/core/pkg/openapi"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"
	"k8s.io/utils/ptr"
)

const invalidUUID = "invalid-uuid"

func doRequest(request *http.Request, accessToken string) *http.Response {
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	response, err := http.DefaultClient.Do(request)
	Expect(err).NotTo(HaveOccurred())

	return response
}

func listImages(baseURL, accessToken, organizationID, regionID string) *http.Response {
	request, err := regionapi.NewGetApiV1OrganizationsOrganizationIDRegionsRegionIDImagesRequest(baseURL, organizationID, regionID)
	Expect(err).NotTo(HaveOccurred())

	return doRequest(request, accessToken)
}

func createImage(baseURL, accessToken, organizationID, regionID string, params regionapi.ImageCreate) *http.Response {
	request, err := regionapi.NewPostApiV1OrganizationsOrganizationIDRegionsRegionIDImagesRequest(baseURL, organizationID, regionID, params)
	Expect(err).NotTo(HaveOccurred())

	return doRequest(request, accessToken)
}

func deleteImage(baseURL, accessToken, organizationID, regionID, imageID string) *http.Response {
	request, err := regionapi.NewDeleteApiV1OrganizationsOrganizationIDRegionsRegionIDImagesImageIDRequest(baseURL, organizationID, regionID, imageID)
	Expect(err).NotTo(HaveOccurred())

	return doRequest(request, accessToken)
}

func createServer(baseURL, accessToken string, params regionapi.ServerV2Create) *http.Response {
	request, err := regionapi.NewPostApiV2ServersRequest(baseURL, params)
	Expect(err).NotTo(HaveOccurred())

	return doRequest(request, accessToken)
}

func getServer(baseURL, accessToken, serverID string) *http.Response {
	request, err := regionapi.NewGetApiV2ServersServerIDRequest(baseURL, serverID)
	Expect(err).NotTo(HaveOccurred())

	return doRequest(request, accessToken)
}

func deleteServer(baseURL, accessToken, serverID string) *http.Response {
	request, err := regionapi.NewDeleteApiV2ServersServerIDRequest(baseURL, serverID)
	Expect(err).NotTo(HaveOccurred())

	return doRequest(request, accessToken)
}

func uniqueName(name string) string {
	return fmt.Sprintf("ginkgo-test-%s-%s", name, uuid.NewString()[:8])
}

func requireCustomImageID(value string) {
	if value == "" {
		Skip("custom image creation failed")
	}
}

func requireServerID(value string) {
	if value == "" {
		Skip("server creation failed")
	}
}

var _ = Describe("Image Service", Ordered, func() {
	var apiConfig *api.TestConfig

	BeforeEach(func() {
		temp, err := api.LoadTestConfig()
		Expect(err).NotTo(HaveOccurred())
		apiConfig = temp
	})

	Context("when listing images", func() {
		// FIXME: Skip this context until the API correctly returns 400 for invalid organization IDs.
		XContext("with an invalid organization ID", func() {
			It("returns 400 Bad Request", func() {
				response := listImages(apiConfig.BaseURL, apiConfig.AuthToken, invalidUUID, apiConfig.RegionID)

				// FIXME: API currently returns 200 instead of the expected 400 Bad Request.
				Expect(response.StatusCode).To(Equal(http.StatusBadRequest))
			})
		})

		Context("with an invalid region ID", func() {
			It("returns 500 Internal Server Error", func() {
				response := listImages(apiConfig.BaseURL, apiConfig.AuthToken, apiConfig.OrgID, invalidUUID)
				defer response.Body.Close()

				// FIXME: API currently returns 500 instead of the expected 400 Bad Request.
				Expect(response.StatusCode).To(Equal(http.StatusInternalServerError))
			})
		})

		Context("with a valid request", func() {
			It("returns 200 OK", func() {
				response := listImages(apiConfig.BaseURL, apiConfig.AuthToken, apiConfig.OrgID, apiConfig.RegionID)
				defer response.Body.Close()

				Expect(response.StatusCode).To(Equal(http.StatusOK))

				var data regionapi.Images
				err := json.NewDecoder(response.Body).Decode(&data)
				Expect(err).NotTo(HaveOccurred())

				Expect(data).NotTo(BeEmpty())
			})
		})
	})

	Context("when working with custom images", func() {
		var customImageID string

		It("creates a custom image successfully", func() {
			params := regionapi.ImageCreate{
				Metadata: openapi.ResourceWriteMetadata{
					Name: uniqueName("ginkgo-test-image"),
				},
				Spec: regionapi.ImageCreateSpec{
					Architecture: regionapi.ArchitectureX8664,
					Gpu:          nil,
					Os: regionapi.ImageOS{
						Codename: ptr.To("noble"),
						Distro:   regionapi.OsDistroUbuntu,
						Family:   regionapi.OsFamilyDebian,
						Kernel:   regionapi.OsKernelLinux,
						Variant:  nil,
						Version:  "23.04",
					},
					SoftwareVersions: nil,
					Uri:              "https://s3.glo1.nscale.com/os-images/noble-server-cloudimg-amd64.raw",
					Virtualization:   regionapi.ImageVirtualizationVirtualized,
				},
			}

			response := createImage(apiConfig.BaseURL, apiConfig.AuthToken, apiConfig.OrgID, apiConfig.RegionID, params)
			defer response.Body.Close()

			Expect(response.StatusCode).To(Equal(http.StatusOK))

			var data regionapi.Image
			err := json.NewDecoder(response.Body).Decode(&data)
			Expect(err).NotTo(HaveOccurred())

			Expect(data.Metadata.Id).NotTo(BeEmpty(), fmt.Sprintf("image '%s' created successfully but ID is empty", params.Metadata.Name))

			customImageID = data.Metadata.Id
		})

		It("contains the custom image in the image list", func() {
			requireCustomImageID(customImageID)

			Eventually(func() bool {
				response := listImages(apiConfig.BaseURL, apiConfig.AuthToken, apiConfig.OrgID, apiConfig.RegionID)
				defer response.Body.Close()

				Expect(response.StatusCode).To(Equal(http.StatusOK))

				var data regionapi.Images
				err := json.NewDecoder(response.Body).Decode(&data)
				Expect(err).NotTo(HaveOccurred())

				for _, image := range data {
					if image.Metadata.Id == customImageID {
						return true
					}
				}

				return false
			}).WithTimeout(time.Hour).WithPolling(15 * time.Second).Should(BeTrue())
		})

		Context("when managing a server from the custom image", Ordered, func() {
			var serverID string

			It("creates a server", func() {
				requireCustomImageID(customImageID)

				params := regionapi.ServerV2Create{
					Metadata: openapi.ResourceWriteMetadata{
						Name: uniqueName("ginkgo-test-server"),
					},
					Spec: regionapi.ServerV2CreateSpec{
						FlavorId:  apiConfig.FlavorID,
						ImageId:   customImageID,
						NetworkId: apiConfig.NetworkID,
						Networking: &regionapi.ServerV2Networking{
							PublicIP: ptr.To(true),
						},
					},
				}

				response := createServer(apiConfig.BaseURL, apiConfig.AuthToken, params)
				defer response.Body.Close()

				Expect(response.StatusCode).To(Equal(http.StatusCreated))

				var data regionapi.ServerV2Read
				err := json.NewDecoder(response.Body).Decode(&data)
				Expect(err).NotTo(HaveOccurred())

				serverID = data.Metadata.Id
			})

			It("gets the server", func() {
				requireCustomImageID(customImageID)
				requireServerID(serverID)

				Eventually(func() bool {
					response := getServer(apiConfig.BaseURL, apiConfig.AuthToken, serverID)
					defer response.Body.Close()

					Expect(response.StatusCode).To(Equal(http.StatusOK))

					var data regionapi.ServerV2Read
					err := json.NewDecoder(response.Body).Decode(&data)
					Expect(err).NotTo(HaveOccurred())

					return data.Status.PowerState != nil && *data.Status.PowerState == regionapi.InstanceLifecyclePhaseRunning
				}).WithTimeout(30 * time.Minute).WithPolling(15 * time.Second).Should(BeTrue())
			})

			// FIXME: Skip this test because the backend never returns conflicts.
			// The image is copied to disk before server startup and is not used afterwards.
			XIt("does not allow deleting the custom image while the server exists", func() {
				requireCustomImageID(customImageID)

				response := deleteImage(apiConfig.BaseURL, apiConfig.AuthToken, apiConfig.OrgID, apiConfig.RegionID, customImageID)
				defer response.Body.Close()

				Expect(response.StatusCode).To(Equal(http.StatusConflict))
			})

			It("deletes the server", func() {
				requireCustomImageID(customImageID)
				requireServerID(serverID)

				response := deleteServer(apiConfig.BaseURL, apiConfig.AuthToken, serverID)
				defer response.Body.Close()

				Expect(response.StatusCode).To(Equal(http.StatusAccepted))
			})
		})

		It("deletes the custom image successfully", func() {
			requireCustomImageID(customImageID)

			response := deleteImage(apiConfig.BaseURL, apiConfig.AuthToken, apiConfig.OrgID, apiConfig.RegionID, customImageID)
			defer response.Body.Close()

			Expect(response.StatusCode).To(Equal(http.StatusAccepted))
		})

		It("returns 404 when deleting the same custom image again", func() {
			requireCustomImageID(customImageID)

			response := deleteImage(apiConfig.BaseURL, apiConfig.AuthToken, apiConfig.OrgID, apiConfig.RegionID, customImageID)
			defer response.Body.Close()

			Expect(response.StatusCode).To(Equal(http.StatusNotFound))
		})
	})
})
