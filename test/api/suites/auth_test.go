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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/unikorn-cloud/region/test/api"
)

var _ = Describe("Authentication Enforcement", func() {
	Context("When requests are made without a valid auth token", func() {
		var unauthClient *api.APIClient

		BeforeEach(func() {
			unauthConfig := *config
			unauthConfig.AuthToken = ""
			unauthClient = api.NewAPIClientWithConfig(&unauthConfig)
		})

		Describe("Given no Authorization header on the main API", func() {
			It("should return 401 when listing regions", func() {
				path := unauthClient.GetListRegionsPath(config.OrgID)
				resp, _, err := unauthClient.DoRequest(ctx, http.MethodGet, path, nil, 0)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
				GinkgoWriter.Printf("Unauthenticated list regions returned %d as expected\n", resp.StatusCode)
			})
		})

		Describe("Given no Authorization header on the region service API", func() {
			It("should return 401 when listing networks", func() {
				path := unauthClient.GetEndpoints().ListNetworks(config.OrgID, config.ProjectID, config.RegionID)
				resp, _, err := unauthClient.DoRegionRequest(ctx, http.MethodGet, path, nil, 0)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
				GinkgoWriter.Printf("Unauthenticated list networks returned %d as expected\n", resp.StatusCode)
			})
		})
	})
})
