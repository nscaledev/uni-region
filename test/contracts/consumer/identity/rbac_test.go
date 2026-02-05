//go:build integration

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

package identity_test

import (
	"context"
	"fmt"
	"net"
	"testing"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
	"github.com/pact-foundation/pact-go/v2/consumer"
	"github.com/pact-foundation/pact-go/v2/matchers"
	"github.com/pact-foundation/pact-go/v2/models"

	contract "github.com/unikorn-cloud/core/pkg/testing/contract"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

var testingT *testing.T //nolint:gochecknoglobals

func TestContracts(t *testing.T) { //nolint:paralleltest
	testingT = t

	RegisterFailHandler(Fail)
	RunSpecs(t, "Identity Consumer Contract Suite")
}

func createIdentityClient(config consumer.MockServerConfig) (*identityapi.ClientWithResponses, error) {
	url := fmt.Sprintf("http://%s", net.JoinHostPort(config.Host, fmt.Sprintf("%d", config.Port)))

	return identityapi.NewClientWithResponses(url)
}

var _ = Describe("Identity RBAC Consumer Contracts", func() {
	var (
		pact *consumer.V4HTTPMockProvider
		ctx  context.Context
	)

	BeforeEach(func() {
		var err error
		pact, err = contract.NewV4Pact(contract.PactConfig{
			Consumer: "uni-region",
			Provider: "uni-identity",
			PactDir:  "./pacts",
		})
		Expect(err).NotTo(HaveOccurred())
		ctx = context.Background()
	})

	Describe("RBAC Authorization Checks", func() {
		Context("when checking global scope access", func() {
			It("should return ACL with global permissions", func() {
				organizationID := "test-org-123"

				pact.AddInteraction().
					GivenWithParameter(models.ProviderState{
						Name: "organization exists with global read permission",
						Parameters: map[string]interface{}{
							"organizationID": organizationID,
						},
					}).
					UponReceiving("a request to get organization ACL for global scope").
					WithRequest("GET", fmt.Sprintf("/api/v1/organizations/%s/acl", organizationID)).
					WillRespondWith(200, func(b *consumer.V4ResponseBuilder) {
						b.JSONBody(map[string]interface{}{
							"global": matchers.EachLike(map[string]interface{}{
								"name":       matchers.String("region:regions"),
								"operations": matchers.EachLike(matchers.String("read"), 1),
							}, 1),
						})
					})

				test := func(config consumer.MockServerConfig) error {
					identityClient, err := createIdentityClient(config)
					if err != nil {
						return fmt.Errorf("creating identity client: %w", err)
					}

					resp, err := identityClient.GetApiV1OrganizationsOrganizationIDAclWithResponse(
						ctx,
						organizationID,
					)
					if err != nil {
						return fmt.Errorf("getting ACL: %w", err)
					}

					Expect(resp.StatusCode()).To(Equal(200))
					Expect(resp.JSON200).NotTo(BeNil())
					Expect(resp.JSON200.Global).NotTo(BeNil())

					return nil
				}

				Expect(pact.ExecuteTest(testingT, test)).To(Succeed())
			})

			It("should return ACL without global permissions", func() {
				organizationID := "test-org-456"

				pact.AddInteraction().
					GivenWithParameter(models.ProviderState{
						Name: "organization exists without global permission",
						Parameters: map[string]interface{}{
							"organizationID": organizationID,
						},
					}).
					UponReceiving("a request to get organization ACL with no global scope").
					WithRequest("GET", fmt.Sprintf("/api/v1/organizations/%s/acl", organizationID)).
					WillRespondWith(200, func(b *consumer.V4ResponseBuilder) {
						b.JSONBody(map[string]interface{}{
							"organizations": matchers.EachLike(map[string]interface{}{
								"id":   matchers.String(organizationID),
								"name": matchers.String("Test Organization"),
								"endpoints": matchers.EachLike(map[string]interface{}{
									"name":       matchers.String("region:networks"),
									"operations": matchers.EachLike(matchers.String("read"), 1),
								}, 1),
							}, 1),
						})
					})

				test := func(config consumer.MockServerConfig) error {
					identityClient, err := createIdentityClient(config)
					if err != nil {
						return fmt.Errorf("creating identity client: %w", err)
					}

					resp, err := identityClient.GetApiV1OrganizationsOrganizationIDAclWithResponse(
						ctx,
						organizationID,
					)
					if err != nil {
						return fmt.Errorf("getting ACL: %w", err)
					}

					Expect(resp.StatusCode()).To(Equal(200))
					Expect(resp.JSON200).NotTo(BeNil())
					Expect(resp.JSON200.Global).To(BeNil())
					Expect(resp.JSON200.Organizations).NotTo(BeNil())

					return nil
				}

				Expect(pact.ExecuteTest(testingT, test)).To(Succeed())
			})
		})

		Context("when checking organization scope access", func() {
			It("should return ACL with organization permissions", func() {
				organizationID := "test-org-789"

				pact.AddInteraction().
					GivenWithParameter(models.ProviderState{
						Name: "organization exists with organization scope read permission",
						Parameters: map[string]interface{}{
							"organizationID": organizationID,
						},
					}).
					UponReceiving("a request to get organization ACL for organization scope").
					WithRequest("GET", fmt.Sprintf("/api/v1/organizations/%s/acl", organizationID)).
					WillRespondWith(200, func(b *consumer.V4ResponseBuilder) {
						b.JSONBody(map[string]interface{}{
							"organizations": matchers.EachLike(map[string]interface{}{
								"id":   matchers.String(organizationID),
								"name": matchers.String("Test Organization"),
								"endpoints": matchers.EachLike(map[string]interface{}{
									"name":       matchers.String("region:networks:v2"),
									"operations": matchers.EachLike(matchers.String("read"), 1),
								}, 1),
							}, 1),
						})
					})

				test := func(config consumer.MockServerConfig) error {
					identityClient, err := createIdentityClient(config)
					if err != nil {
						return fmt.Errorf("creating identity client: %w", err)
					}

					resp, err := identityClient.GetApiV1OrganizationsOrganizationIDAclWithResponse(
						ctx,
						organizationID,
					)
					if err != nil {
						return fmt.Errorf("getting ACL: %w", err)
					}

					Expect(resp.StatusCode()).To(Equal(200))
					Expect(resp.JSON200).NotTo(BeNil())
					Expect(resp.JSON200.Organizations).NotTo(BeNil())

					return nil
				}

				Expect(pact.ExecuteTest(testingT, test)).To(Succeed())
			})
		})

		Context("when checking project scope access", func() {
			It("should return ACL with project permissions", func() {
				organizationID := "test-org-101"
				projectID := "test-project-202"

				pact.AddInteraction().
					GivenWithParameter(models.ProviderState{
						Name: "project exists with project scope read permission",
						Parameters: map[string]interface{}{
							"organizationID": organizationID,
							"projectID":      projectID,
						},
					}).
					UponReceiving("a request to get organization ACL for project scope").
					WithRequest("GET", fmt.Sprintf("/api/v1/organizations/%s/acl", organizationID)).
					WillRespondWith(200, func(b *consumer.V4ResponseBuilder) {
						b.JSONBody(map[string]interface{}{
							"projects": matchers.EachLike(map[string]interface{}{
								"id":   matchers.String(projectID),
								"name": matchers.String("Test Project"),
								"endpoints": matchers.EachLike(map[string]interface{}{
									"name":       matchers.String("region:servers:v2"),
									"operations": matchers.EachLike(matchers.String("read"), 1),
								}, 1),
							}, 1),
						})
					})

				test := func(config consumer.MockServerConfig) error {
					identityClient, err := createIdentityClient(config)
					if err != nil {
						return fmt.Errorf("creating identity client: %w", err)
					}

					resp, err := identityClient.GetApiV1OrganizationsOrganizationIDAclWithResponse(
						ctx,
						organizationID,
					)
					if err != nil {
						return fmt.Errorf("getting ACL: %w", err)
					}

					Expect(resp.StatusCode()).To(Equal(200))
					Expect(resp.JSON200).NotTo(BeNil())
					Expect(resp.JSON200.Projects).NotTo(BeNil())

					return nil
				}

				Expect(pact.ExecuteTest(testingT, test)).To(Succeed())
			})
		})

		Context("when organization does not exist", func() {
			It("should return 404 Not Found", func() {
				organizationID := "non-existent-org"

				pact.AddInteraction().
					GivenWithParameter(models.ProviderState{
						Name: "organization does not exist",
						Parameters: map[string]interface{}{
							"organizationID": organizationID,
						},
					}).
					UponReceiving("a request to get ACL for non-existent organization").
					WithRequest("GET", fmt.Sprintf("/api/v1/organizations/%s/acl", organizationID)).
					WillRespondWith(404, func(b *consumer.V4ResponseBuilder) {
						b.JSONBody(map[string]interface{}{
							"message": matchers.String("organization not found"),
						})
					})

				test := func(config consumer.MockServerConfig) error {
					identityClient, err := createIdentityClient(config)
					if err != nil {
						return fmt.Errorf("creating identity client: %w", err)
					}

					resp, err := identityClient.GetApiV1OrganizationsOrganizationIDAclWithResponse(
						ctx,
						organizationID,
					)
					if err != nil {
						return fmt.Errorf("getting ACL: %w", err)
					}

					Expect(resp.StatusCode()).To(Equal(404))

					return nil
				}

				Expect(pact.ExecuteTest(testingT, test)).To(Succeed())
			})
		})
	})
})
