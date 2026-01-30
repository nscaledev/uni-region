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

	coreclient "github.com/unikorn-cloud/core/pkg/openapi"
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

// allocationTestParams holds parameters for create allocation tests.
type allocationTestParams struct {
	organizationID string
	projectID      string
	allocationID   string
	name           string
	kind           string
	allocationKind string
	description    string
}

// setupCreateAllocationInteraction configures the pact interaction for creating an allocation.
func setupCreateAllocationInteraction(pact *consumer.V4HTTPMockProvider, params allocationTestParams) {
	pact.AddInteraction().
		GivenWithParameter(models.ProviderState{
			Name: "project exists",
			Parameters: map[string]interface{}{
				"organizationID": params.organizationID,
				"projectID":      params.projectID,
			},
		}).
		UponReceiving(params.description).
		WithRequest("POST", fmt.Sprintf("/api/v1/organizations/%s/projects/%s/allocations", params.organizationID, params.projectID), func(b *consumer.V4RequestBuilder) {
			b.JSONBody(map[string]interface{}{
				"metadata": map[string]interface{}{
					"name": matchers.String(params.name),
				},
				"spec": map[string]interface{}{
					"id":   matchers.String(params.allocationID),
					"kind": matchers.String(params.kind),
					"allocations": []map[string]interface{}{
						{
							"kind":      matchers.String(params.allocationKind),
							"committed": matchers.Integer(1),
							"reserved":  matchers.Integer(1),
						},
					},
				},
			})
		}).
		WillRespondWith(201, func(b *consumer.V4ResponseBuilder) {
			b.JSONBody(map[string]interface{}{
				"metadata": map[string]interface{}{
					"id":           matchers.UUID(),
					"name":         matchers.String(params.name),
					"creationTime": matchers.Timestamp(),
				},
				"spec": map[string]interface{}{
					"id":   matchers.String(params.allocationID),
					"kind": matchers.String(params.kind),
					"allocations": []map[string]interface{}{
						{
							"kind":      matchers.String(params.allocationKind),
							"committed": matchers.Integer(1),
							"reserved":  matchers.Integer(1),
						},
					},
				},
			})
		})
}

// createAllocationTestFunc returns a test function for creating an allocation.
func createAllocationTestFunc(ctx context.Context, params allocationTestParams) func(consumer.MockServerConfig) error {
	return func(config consumer.MockServerConfig) error {
		identityClient, err := createIdentityClient(config)
		if err != nil {
			return fmt.Errorf("creating identity client: %w", err)
		}

		allocationReq := identityapi.AllocationWrite{
			Metadata: coreclient.ResourceWriteMetadata{
				Name: params.name,
			},
			Spec: identityapi.AllocationSpec{
				Id:   params.allocationID,
				Kind: params.kind,
				Allocations: identityapi.ResourceAllocationList{
					{
						Kind:      params.allocationKind,
						Committed: 1,
						Reserved:  1,
					},
				},
			},
		}

		resp, err := identityClient.PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsWithResponse(
			ctx, params.organizationID, params.projectID, allocationReq)
		if err != nil {
			return fmt.Errorf("creating allocation: %w", err)
		}

		Expect(resp.StatusCode()).To(Equal(201))
		Expect(resp.JSON201).NotTo(BeNil())
		Expect(resp.JSON201.Spec.Id).To(Equal(params.allocationID))

		return nil
	}
}

var _ = Describe("Identity Service Contract", func() {
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

	Describe("ResourceAllocations", func() {
		Context("when creating a network allocation", func() {
			It("creates allocation for network resources", func() {
				params := allocationTestParams{
					organizationID: "c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f",
					projectID:      "d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f8a",
					allocationID:   "e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8a9b",
					name:           "test-network",
					kind:           "network",
					allocationKind: "networks",
					description:    "a request to create network allocation",
				}

				setupCreateAllocationInteraction(pact, params)
				Expect(pact.ExecuteTest(testingT, createAllocationTestFunc(ctx, params))).To(Succeed())
			})
		})

		Context("when creating a file storage allocation", func() {
			It("creates allocation for file storage resources", func() {
				params := allocationTestParams{
					organizationID: "f6a7b8c9-d0e1-4f2a-3b4c-5d6e7f8a9b0c",
					projectID:      "a7b8c9d0-e1f2-4a3b-4c5d-6e7f8a9b0c1d",
					allocationID:   "b8c9d0e1-f2a3-4b4c-5d6e-7f8a9b0c1d2e",
					name:           "test-filestorage",
					kind:           "filestorage",
					allocationKind: "filestorage",
					description:    "a request to create file storage allocation",
				}

				setupCreateAllocationInteraction(pact, params)
				Expect(pact.ExecuteTest(testingT, createAllocationTestFunc(ctx, params))).To(Succeed())
			})
		})

		Context("when updating an allocation", func() {
			It("updates allocation with new resource counts", func() {
				organizationID := "c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f"
				projectID := "d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f8a"
				allocationID := "e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8a9b"

				pact.AddInteraction().
					GivenWithParameter(models.ProviderState{
						Name: "allocation exists",
						Parameters: map[string]interface{}{
							"organizationID": organizationID,
							"projectID":      projectID,
							"allocationID":   allocationID,
						},
					}).
					UponReceiving("a request to update allocation").
					WithRequest("PUT",
						fmt.Sprintf("/api/v1/organizations/%s/projects/%s/allocations/%s",
							organizationID, projectID, allocationID), func(b *consumer.V4RequestBuilder) {
							b.JSONBody(map[string]interface{}{
								"metadata": map[string]interface{}{
									"name": matchers.String("test-filestorage"),
								},
								"spec": map[string]interface{}{
									"id":   matchers.String(allocationID),
									"kind": matchers.String("filestorage"),
									"allocations": []map[string]interface{}{
										{
											"kind":      matchers.String("filestorage"),
											"committed": matchers.Integer(2),
											"reserved":  matchers.Integer(2),
										},
									},
								},
							})
						}).
					WillRespondWith(200, func(b *consumer.V4ResponseBuilder) {
						b.JSONBody(map[string]interface{}{
							"metadata": map[string]interface{}{
								"id":           matchers.UUID(),
								"name":         matchers.String("test-filestorage"),
								"creationTime": matchers.Timestamp(),
							},
							"spec": map[string]interface{}{
								"id":   matchers.String(allocationID),
								"kind": matchers.String("filestorage"),
								"allocations": []map[string]interface{}{
									{
										"kind":      matchers.String("filestorage"),
										"committed": matchers.Integer(2),
										"reserved":  matchers.Integer(2),
									},
								},
							},
						})
					})

				test := func(config consumer.MockServerConfig) error {
					identityClient, err := createIdentityClient(config)
					if err != nil {
						return fmt.Errorf("creating identity client: %w", err)
					}

					allocationReq := identityapi.AllocationWrite{
						Metadata: coreclient.ResourceWriteMetadata{
							Name: "test-filestorage",
						},
						Spec: identityapi.AllocationSpec{
							Id:   allocationID,
							Kind: "filestorage",
							Allocations: identityapi.ResourceAllocationList{
								{
									Kind:      "filestorage",
									Committed: 2,
									Reserved:  2,
								},
							},
						},
					}

					resp, err := identityClient.PutApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDWithResponse(
						ctx, organizationID, projectID, allocationID, allocationReq)
					if err != nil {
						return fmt.Errorf("updating allocation: %w", err)
					}

					Expect(resp.StatusCode()).To(Equal(200))
					Expect(resp.JSON200).NotTo(BeNil())
					Expect(resp.JSON200.Spec.Id).To(Equal(allocationID))

					return nil
				}

				Expect(pact.ExecuteTest(testingT, test)).To(Succeed())
			})
		})

		Context("when deleting an allocation", func() {
			It("removes allocation successfully", func() {
				organizationID := "c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f"
				projectID := "d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f8a"
				allocationID := "e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8a9b"

				pact.AddInteraction().
					GivenWithParameter(models.ProviderState{
						Name: "allocation exists",
						Parameters: map[string]interface{}{
							"organizationID": organizationID,
							"projectID":      projectID,
							"allocationID":   allocationID,
						},
					}).
					UponReceiving("a request to delete allocation").
					WithRequest("DELETE",
						fmt.Sprintf("/api/v1/organizations/%s/projects/%s/allocations/%s",
							organizationID, projectID, allocationID)).
					WillRespondWith(202)

				test := func(config consumer.MockServerConfig) error {
					identityClient, err := createIdentityClient(config)
					if err != nil {
						return fmt.Errorf("creating identity client: %w", err)
					}

					resp, err := identityClient.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDWithResponse(
						ctx, organizationID, projectID, allocationID)
					if err != nil {
						return fmt.Errorf("deleting allocation: %w", err)
					}

					Expect(resp.StatusCode()).To(Equal(202))

					return nil
				}

				Expect(pact.ExecuteTest(testingT, test)).To(Succeed())
			})
		})
	})
})
