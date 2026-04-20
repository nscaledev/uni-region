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
	allocations    identityapi.ResourceAllocationList
	description    string
}

func allocationMatchers(allocations identityapi.ResourceAllocationList) []map[string]interface{} {
	out := make([]map[string]interface{}, len(allocations))

	for i := range allocations {
		out[i] = map[string]interface{}{
			"kind":      matchers.String(allocations[i].Kind),
			"committed": matchers.Integer(allocations[i].Committed),
			"reserved":  matchers.Integer(allocations[i].Reserved),
		}
	}

	return out
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
					"id":          matchers.String(params.allocationID),
					"kind":        matchers.String(params.kind),
					"allocations": allocationMatchers(params.allocations),
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
					"id":          matchers.String(params.allocationID),
					"kind":        matchers.String(params.kind),
					"allocations": allocationMatchers(params.allocations),
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
				Id:          params.allocationID,
				Kind:        params.kind,
				Allocations: params.allocations,
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

func setupUpdateAllocationInteraction(pact *consumer.V4HTTPMockProvider, params allocationTestParams) {
	pact.AddInteraction().
		GivenWithParameter(models.ProviderState{
			Name: "allocation exists",
			Parameters: map[string]interface{}{
				"organizationID": params.organizationID,
				"projectID":      params.projectID,
				"allocationID":   params.allocationID,
			},
		}).
		UponReceiving(params.description).
		WithRequest("PUT",
			fmt.Sprintf("/api/v1/organizations/%s/projects/%s/allocations/%s",
				params.organizationID, params.projectID, params.allocationID), func(b *consumer.V4RequestBuilder) {
				b.JSONBody(map[string]interface{}{
					"metadata": map[string]interface{}{
						"name": matchers.String(params.name),
					},
					"spec": map[string]interface{}{
						"id":          matchers.String(params.allocationID),
						"kind":        matchers.String(params.kind),
						"allocations": allocationMatchers(params.allocations),
					},
				})
			}).
		WillRespondWith(200, func(b *consumer.V4ResponseBuilder) {
			b.JSONBody(map[string]interface{}{
				"metadata": map[string]interface{}{
					"id":           matchers.UUID(),
					"name":         matchers.String(params.name),
					"creationTime": matchers.Timestamp(),
				},
				"spec": map[string]interface{}{
					"id":          matchers.String(params.allocationID),
					"kind":        matchers.String(params.kind),
					"allocations": allocationMatchers(params.allocations),
				},
			})
		})
}

func updateAllocationTestFunc(ctx context.Context, params allocationTestParams) func(consumer.MockServerConfig) error {
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
				Id:          params.allocationID,
				Kind:        params.kind,
				Allocations: params.allocations,
			},
		}

		resp, err := identityClient.PutApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDWithResponse(
			ctx, params.organizationID, params.projectID, params.allocationID, allocationReq)
		if err != nil {
			return fmt.Errorf("updating allocation: %w", err)
		}

		Expect(resp.StatusCode()).To(Equal(200))
		Expect(resp.JSON200).NotTo(BeNil())
		Expect(resp.JSON200.Spec.Id).To(Equal(params.allocationID))

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
					allocations: identityapi.ResourceAllocationList{
						{
							Kind:      "networks",
							Committed: 1,
							Reserved:  1,
						},
					},
					description: "a request to create network allocation",
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
					allocations: identityapi.ResourceAllocationList{
						{
							Kind:      "filestorage",
							Committed: 1,
							Reserved:  1,
						},
					},
					description: "a request to create file storage allocation",
				}

				setupCreateAllocationInteraction(pact, params)
				Expect(pact.ExecuteTest(testingT, createAllocationTestFunc(ctx, params))).To(Succeed())
			})
		})

		Context("when creating a load balancer allocation", func() {
			It("creates allocation for load balancer resources", func() {
				params := allocationTestParams{
					organizationID: "fbc8ca8f-b4b0-4624-9d84-daf6f8472730",
					projectID:      "f9db6680-093d-4530-8948-39ec3a0c03c6",
					allocationID:   "c819e05e-82ec-4ef4-9a3f-86983cfddf78",
					name:           "test-loadbalancer",
					kind:           "loadbalancer",
					allocations: identityapi.ResourceAllocationList{
						{
							Kind:      "loadbalancers",
							Committed: 1,
							Reserved:  1,
						},
					},
					description: "a request to create load balancer allocation",
				}

				setupCreateAllocationInteraction(pact, params)
				Expect(pact.ExecuteTest(testingT, createAllocationTestFunc(ctx, params))).To(Succeed())
			})
		})

		Context("when creating a public load balancer allocation", func() {
			It("creates allocation for load balancer and public IP resources", func() {
				params := allocationTestParams{
					organizationID: "b69950c1-5d4d-443c-b94a-6663fc84210d",
					projectID:      "101c9857-72b1-40db-a3f1-529e55e1937e",
					allocationID:   "be866dfb-aaf3-49fd-b0d7-f833fd46ad93",
					name:           "test-public-loadbalancer",
					kind:           "loadbalancer",
					allocations: identityapi.ResourceAllocationList{
						{
							Kind:      "loadbalancers",
							Committed: 1,
							Reserved:  1,
						},
						{
							Kind:      "publicips",
							Committed: 1,
							Reserved:  1,
						},
					},
					description: "a request to create public load balancer allocation",
				}

				setupCreateAllocationInteraction(pact, params)
				Expect(pact.ExecuteTest(testingT, createAllocationTestFunc(ctx, params))).To(Succeed())
			})
		})

		Context("when updating a file storage allocation", func() {
			It("updates allocation with new resource counts", func() {
				params := allocationTestParams{
					organizationID: "c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f",
					projectID:      "d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f8a",
					allocationID:   "e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8a9b",
					name:           "test-filestorage",
					kind:           "filestorage",
					allocations: identityapi.ResourceAllocationList{
						{
							Kind:      "filestorage",
							Committed: 2,
							Reserved:  2,
						},
					},
					description: "a request to update allocation",
				}

				setupUpdateAllocationInteraction(pact, params)
				Expect(pact.ExecuteTest(testingT, updateAllocationTestFunc(ctx, params))).To(Succeed())
			})
		})

		Context("when updating a load balancer allocation", func() {
			It("updates allocation for load balancer resources", func() {
				params := allocationTestParams{
					organizationID: "03d293f3-b0fd-44af-b75f-4807db5e0e62",
					projectID:      "ffbe5f6a-fbf4-4db8-bf2f-c8daf922f0fc",
					allocationID:   "ed100c81-8f3a-4881-9f47-d9588045637e",
					name:           "test-loadbalancer",
					kind:           "loadbalancer",
					allocations: identityapi.ResourceAllocationList{
						{
							Kind:      "loadbalancers",
							Committed: 1,
							Reserved:  1,
						},
					},
					description: "a request to update load balancer allocation",
				}

				setupUpdateAllocationInteraction(pact, params)
				Expect(pact.ExecuteTest(testingT, updateAllocationTestFunc(ctx, params))).To(Succeed())
			})
		})

		Context("when updating a public load balancer allocation", func() {
			It("updates allocation for load balancer and public IP resources", func() {
				params := allocationTestParams{
					organizationID: "57ff7c16-9a3b-45f0-830c-73f146123353",
					projectID:      "f0bff67e-7cb1-41ff-955d-4766205b26fa",
					allocationID:   "9be0db1f-a967-49f2-aa14-b7638fbc62c4",
					name:           "test-public-loadbalancer",
					kind:           "loadbalancer",
					allocations: identityapi.ResourceAllocationList{
						{
							Kind:      "loadbalancers",
							Committed: 1,
							Reserved:  1,
						},
						{
							Kind:      "publicips",
							Committed: 1,
							Reserved:  1,
						},
					},
					description: "a request to update public load balancer allocation",
				}

				setupUpdateAllocationInteraction(pact, params)
				Expect(pact.ExecuteTest(testingT, updateAllocationTestFunc(ctx, params))).To(Succeed())
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
