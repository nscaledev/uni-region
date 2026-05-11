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
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	"github.com/unikorn-cloud/region/test/api"
)

// Region ACL enforcement: verify that knowing a restricted region's ID does not
// grant access to it (confused-deputy prevention). A caller whose organization is
// not listed in the region's security.organizations must receive 404 — not 403 —
// so region existence is not leaked.

var _ = Describe("Region ACL Enforcement", func() {
	Context("When the owning organization supplies a private region ID", func() {
		BeforeEach(func() {
			if config.PrivateRegionID == "" {
				Skip("TEST_PRIVATE_REGION_ID not configured")
			}
		})

		Describe("Given a flavor list request", func() {
			It("should return available flavors", func() {
				flavors, err := client.ListFlavors(ctx, config.OrgID, config.PrivateRegionID)
				Expect(err).NotTo(HaveOccurred())
				Expect(flavors).NotTo(BeNil())
				GinkgoWriter.Printf("Owning org retrieved %d flavors from private region %s\n",
					len(flavors), config.PrivateRegionID)
			})
		})

		Describe("Given an image list request", func() {
			It("should succeed", func() {
				_, err := client.ListImages(ctx, config.OrgID, config.PrivateRegionID)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	Context("When a non-owning organization supplies a private region ID directly", func() {
		BeforeEach(func() {
			if secondaryClient == nil {
				Skip("TEST_SECONDARY_ORG_ID and TEST_SECONDARY_AUTH_TOKEN not configured")
			}
			if config.PrivateRegionID == "" {
				Skip("TEST_PRIVATE_REGION_ID not configured")
			}
		})

		Describe("Given a flavor list request for the private region", func() {
			It("should return 404 without leaking region existence", func() {
				_, err := secondaryClient.ListFlavors(ctx, config.SecondaryOrgID, config.PrivateRegionID)
				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
				GinkgoWriter.Printf("Secondary org correctly denied access to private region %s\n",
					config.PrivateRegionID)
			})
		})

		Describe("Given an image list request for the private region", func() {
			It("should return 404 without leaking region existence", func() {
				_, err := secondaryClient.ListImages(ctx, config.SecondaryOrgID, config.PrivateRegionID)
				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
			})
		})

		Describe("Given a network creation request referencing the private region", func() {
			It("should return 404 without leaking region existence", func() {
				if config.SecondaryProjectID == "" {
					Skip("TEST_SECONDARY_PROJECT_ID not configured")
				}

				reqBody, err := json.Marshal(
					api.NewNetworkPayload(config.SecondaryOrgID, config.SecondaryProjectID, config.PrivateRegionID).Build(),
				)
				Expect(err).NotTo(HaveOccurred())

				path := secondaryClient.GetEndpoints().CreateNetwork()
				resp, _, err := secondaryClient.DoRegionRequest(ctx, http.MethodPost, path, bytes.NewReader(reqBody), 0)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusNotFound))

				GinkgoWriter.Printf("Secondary org network create correctly denied for private region %s\n",
					config.PrivateRegionID)
			})
		})
	})
})
