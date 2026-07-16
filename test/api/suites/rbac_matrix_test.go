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
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/unikorn-cloud/region/test/api"
)

// placeholderResourceID is a well-formed but non-existent UUID, used to build
// payloads for requests that must be denied by RBAC before any reference is
// resolved (mirrors images_test.go's nonExistentImageID).
const placeholderResourceID = "00000000-0000-0000-0000-000000000000"

func expectUserRequestForbidden(method, path string, payload any) {
	GinkgoHelper()

	var body io.Reader
	if payload != nil {
		bodyBytes, err := json.Marshal(payload)
		Expect(err).NotTo(HaveOccurred())

		body = bytes.NewReader(bodyBytes)
	}

	resp, _, err := userClient.DoRegionRequest(ctx, method, path, body, http.StatusForbidden)
	Expect(err).NotTo(HaveOccurred(),
		"user %s %s should return 403 Forbidden", method, path)
	Expect(resp).NotTo(BeNil())
	Expect(resp.StatusCode).To(Equal(http.StatusForbidden))
}

// This suite is the automated CI counterpart of the manual shadow-mode
// verification: it drives an admin/user RBAC matrix against region while
// region runs with --authorization-engine-mode=shadow (hack/ci/test-values.yaml).
// In shadow mode every decision below is ALSO evaluated against identity's
// central Cerbos PDP via the remote-authorization seam, and any disagreement
// with the legacy verdict served here is logged as "remote shadow divergence"
// for hack/ci/divergence-gate to fail on. So breadth here is gate coverage,
// not just RBAC coverage — the assertions below describe the LEGACY served
// behavior (shadow always serves legacy); the divergence gate is what
// separately proves the remote path agreed.
var _ = Describe("Region RBAC (shadow)", func() {
	BeforeEach(func() {
		Expect(config.UserToken).NotTo(BeEmpty(),
			"USER_AUTH_TOKEN must be set by integration fixtures")
		Expect(userClient).NotTo(BeNil(),
			"USER_AUTH_TOKEN must create a user API client")
	})

	Context("When authenticated as an administrator", func() {
		Describe("Given a request to list regions", func() {
			It("should return all available regions with complete metadata", func() {
				regions, err := regionClient.ListRegions(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(regions).NotTo(BeEmpty())

				for _, region := range regions {
					Expect(region.Metadata.Id).NotTo(BeEmpty())
					Expect(region.Metadata.Name).NotTo(BeEmpty())
					Expect(region.Spec).NotTo(BeNil())
				}
			})
		})

		Describe("Given a request to list flavors for the region", func() {
			It("should return all available flavors with complete metadata", func() {
				flavors, err := regionClient.ListFlavors(ctx, config.OrgID, config.RegionID)

				Expect(err).NotTo(HaveOccurred())
				Expect(flavors).NotTo(BeEmpty())

				for _, flavor := range flavors {
					Expect(flavor.Metadata.Id).NotTo(BeEmpty())
					Expect(flavor.Spec).NotTo(BeNil())
				}
			})
		})

		Describe("Given a request to list images for the region", func() {
			It("should return all available images with complete metadata", func() {
				images, err := regionClient.ListImages(ctx, config.OrgID, config.RegionID)

				Expect(err).NotTo(HaveOccurred())
				Expect(images).NotTo(BeEmpty())

				for _, image := range images {
					Expect(image.Metadata.Id).NotTo(BeEmpty())
					Expect(image.Spec).NotTo(BeNil())
				}
			})
		})

		Describe("Given a request to list networks in the project", func() {
			It("should be permitted to list networks", func() {
				_, err := regionClient.ListNetworks(ctx, config.OrgID, config.ProjectID, config.RegionID)

				Expect(err).NotTo(HaveOccurred())
			})
		})

		Describe("Given a request to create a network", func() {
			It("should provision the network with correct metadata", func() {
				createReq := api.NewNetworkPayload(config.OrgID, config.ProjectID, config.RegionID).Build()

				network, cleanup := api.MustProvisionNetwork(regionClient, ctx, createReq)
				DeferCleanup(cleanup)

				Expect(network.Metadata.Id).NotTo(BeEmpty())
				Expect(network.Metadata.Name).To(Equal(createReq.Metadata.Name))
				Expect(network.Metadata.OrganizationId).To(Equal(config.OrgID))
				Expect(network.Metadata.ProjectId).To(Equal(config.ProjectID))
				Expect(network.Status.RegionId).To(Equal(config.RegionID))
			})
		})
	})

	Context("When authenticated as a user", func() {
		Describe("Given a request to list networks in their project", func() {
			It("should be permitted to list networks", func() {
				_, err := userClient.ListNetworks(ctx, config.OrgID, config.ProjectID, config.RegionID)

				Expect(err).NotTo(HaveOccurred())
			})
		})

		Describe("Given a request to create a network in their project", func() {
			It("should provision the network with correct metadata", func() {
				createReq := api.NewNetworkPayload(config.OrgID, config.ProjectID, config.RegionID).Build()

				network, cleanup := api.MustProvisionNetwork(userClient, ctx, createReq)
				DeferCleanup(cleanup)

				Expect(network.Metadata.Id).NotTo(BeEmpty())
				Expect(network.Metadata.Name).To(Equal(createReq.Metadata.Name))
				Expect(network.Metadata.OrganizationId).To(Equal(config.OrgID))
				Expect(network.Metadata.ProjectId).To(Equal(config.ProjectID))
			})
		})

		// The "user" role grants no region:servers/region:servers:v2 permission
		// at any scope (charts/identity/values.yaml) — server lifecycle is only
		// reachable via a service's own internal (mTLS) system account, e.g.
		// compute-service. So both a read and a write op on this kind must be
		// denied for a direct bearer user, regardless of project membership.

		Describe("Given a request to list servers", func() {
			It("should be denied with a forbidden response", func() {
				path := userClient.GetEndpoints().ListServers(config.OrgID, config.ProjectID, config.RegionID, "")

				expectUserRequestForbidden(http.MethodGet, path, nil)
			})
		})

		Describe("Given a request to create a server", func() {
			It("should be denied with a forbidden response", func() {
				createReq := api.NewServerPayload(placeholderResourceID, placeholderResourceID, placeholderResourceID).Build()

				expectUserRequestForbidden(http.MethodPost, userClient.GetEndpoints().CreateServer(), createReq)
			})
		})
	})
})
