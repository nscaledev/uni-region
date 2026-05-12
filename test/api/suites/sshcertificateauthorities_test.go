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
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"
)

var _ = Describe("SSHCertificateAuthority", func() {
	Context("When managing SSH certificate authorities", Ordered, func() {
		var caID string
		var createReq regionopenapi.SshCertificateAuthorityV2Create

		BeforeAll(func() {
			createReq = api.NewSSHCertificateAuthorityPayload(config.OrgID, config.ProjectID).Build()
			created, err := regionClient.CreateSSHCertificateAuthority(ctx, createReq)
			Expect(err).NotTo(HaveOccurred(), "failed to create ssh certificate authority fixture")
			caID = created.Metadata.Id
			DeferCleanup(func() {
				GinkgoWriter.Printf("Cleaning up ssh certificate authority: %s\n", caID)
				err := regionClient.DeleteSSHCertificateAuthority(ctx, caID)
				if errors.Is(err, coreclient.ErrResourceNotFound) {
					return
				}
				Expect(err).NotTo(HaveOccurred())
			})
			GinkgoWriter.Printf("Created ssh certificate authority: %s (%s)\n", created.Metadata.Name, caID)
		})

		Describe("Given a valid Ed25519 public key", func() {
			It("should create an SSH certificate authority with correct response fields", func() {
				Expect(caID).NotTo(BeEmpty())
				Expect(createReq.Metadata.Name).NotTo(BeEmpty())

				got, err := regionClient.GetSSHCertificateAuthority(ctx, caID)
				Expect(err).NotTo(HaveOccurred())
				Expect(got.Metadata.Id).To(Equal(caID))
				Expect(got.Metadata.Name).To(Equal(createReq.Metadata.Name))
				Expect(got.Metadata.OrganizationId).To(Equal(config.OrgID))
				Expect(got.Metadata.ProjectId).To(Equal(config.ProjectID))
				Expect(got.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
				Expect(got.Spec.PublicKey).To(Equal(createReq.Spec.PublicKey))
			})

			It("should appear in the list filtered by org and project", func() {
				list, err := regionClient.ListSSHCertificateAuthorities(ctx, config.OrgID, config.ProjectID)
				Expect(err).NotTo(HaveOccurred())

				var found *regionopenapi.SshCertificateAuthorityV2Read
				for i := range list {
					if list[i].Metadata.Id == caID {
						found = &list[i]
						break
					}
				}

				Expect(found).NotTo(BeNil(), "created ssh certificate authority %s not found in list", caID)
				Expect(found.Metadata.Name).To(Equal(createReq.Metadata.Name))
				Expect(found.Spec.PublicKey).To(Equal(createReq.Spec.PublicKey))
				GinkgoWriter.Printf("Found ssh certificate authority in list: %s\n", caID)
			})

			It("should delete the SSH certificate authority and confirm it is no longer found", func() {
				Expect(regionClient.DeleteSSHCertificateAuthority(ctx, caID)).To(Succeed())
				GinkgoWriter.Printf("Deleted ssh certificate authority: %s\n", caID)

				_, err := regionClient.GetSSHCertificateAuthority(ctx, caID)
				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue(),
					"deleted ssh certificate authority should return not found")
				GinkgoWriter.Printf("Confirmed ssh certificate authority deleted: %s\n", caID)
			})
		})
	})

	Context("When getting a non-existent SSH certificate authority", func() {
		Describe("Given a non-existent SSH certificate authority ID", func() {
			It("should return not found", func() {
				_, err := regionClient.GetSSHCertificateAuthority(ctx, "00000000-0000-0000-0000-000000000000")
				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
			})
		})
	})

	Context("When creating an SSH certificate authority with an invalid key", func() {
		Describe("Given a malformed public key", func() {
			It("should return 422 Unprocessable Entity", func() {
				req := api.NewSSHCertificateAuthorityPayload(config.OrgID, config.ProjectID).
					WithPublicKey("not-a-valid-ssh-public-key").
					Build()
				_, err := regionClient.CreateSSHCertificateAuthority(ctx, req)
				Expect(errors.Is(err, coreclient.ErrUnexpectedStatusCode)).To(BeTrue())
			})
		})
	})
})
