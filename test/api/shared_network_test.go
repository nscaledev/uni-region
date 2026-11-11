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

//nolint:revive,testpackage // Ginkgo suite uses dot imports and package-local helper access.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreconfig "github.com/unikorn-cloud/core/pkg/testing/config"
)

var _ = Describe("Shared network resolver", func() {
	const (
		orgID     = "org-1"
		projectID = "project-1"
		regionID  = "11111111-1111-1111-1111-111111111111"
		cidr      = "192.168.214.0/24"
	)

	provisionedNetwork := func(id string) map[string]any {
		return map[string]any{
			"metadata": map[string]any{
				"id":                 id,
				"name":               SharedTestNetworkName,
				"provisioningStatus": "provisioned",
			},
		}
	}

	Context("When the shared network already exists and is provisioned", func() {
		Describe("Given it is returned by the network list", func() {
			It("reuses it without creating another", func() {
				var createCalls int

				endpoints := NewEndpoints()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()

					switch {
					case r.Method == http.MethodGet && r.URL.RequestURI() == endpoints.ListNetworks(orgID, projectID, regionID):
						Expect(json.NewEncoder(w).Encode([]map[string]any{provisionedNetwork("network-existing")})).To(Succeed())
					case r.Method == http.MethodPost && r.URL.RequestURI() == endpoints.CreateNetwork():
						createCalls++
						w.WriteHeader(http.StatusCreated)
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				DeferCleanup(server.Close)

				client := NewAPIClientWithConfig(&TestConfig{
					BaseConfig: coreconfig.BaseConfig{
						BaseURL:        server.URL,
						RequestTimeout: time.Second,
					},
					RegionBaseURL:     server.URL,
					OrgID:             orgID,
					ProjectID:         projectID,
					RegionID:          regionID,
					SharedNetworkCIDR: cidr,
				})

				network := MustResolveSharedNetwork(client, context.Background())

				Expect(createCalls).To(Equal(0))
				Expect(network.Metadata.Id).To(Equal("network-existing"))
			})
		})
	})

	Context("When duplicate shared networks exist from a concurrent cold start", func() {
		Describe("Given the list returns two networks with the shared name", func() {
			It("converges on the oldest and deletes the younger duplicate", func() {
				var deletedYounger bool

				endpoints := NewEndpoints()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()

					switch {
					case r.Method == http.MethodGet && r.URL.RequestURI() == endpoints.ListNetworks(orgID, projectID, regionID):
						Expect(json.NewEncoder(w).Encode([]map[string]any{
							{"metadata": map[string]any{"id": "network-older", "name": SharedTestNetworkName, "provisioningStatus": "provisioned", "creationTime": "2026-10-01T00:00:00Z"}},
							{"metadata": map[string]any{"id": "network-younger", "name": SharedTestNetworkName, "provisioningStatus": "provisioned", "creationTime": "2026-10-10T00:00:00Z"}},
						})).To(Succeed())
					case r.Method == http.MethodDelete && r.URL.RequestURI() == endpoints.DeleteNetwork("network-younger"):
						deletedYounger = true
						w.WriteHeader(http.StatusAccepted)
					case r.Method == http.MethodGet && r.URL.RequestURI() == endpoints.GetNetwork("network-younger"):
						w.WriteHeader(http.StatusNotFound)
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				DeferCleanup(server.Close)

				client := NewAPIClientWithConfig(&TestConfig{
					BaseConfig: coreconfig.BaseConfig{
						BaseURL:        server.URL,
						RequestTimeout: time.Second,
					},
					RegionBaseURL: server.URL,
					OrgID:         orgID,
					ProjectID:     projectID,
					RegionID:      regionID,
				})

				network := MustResolveSharedNetwork(client, context.Background())

				Expect(network.Metadata.Id).To(Equal("network-older"))
				Expect(deletedYounger).To(BeTrue(), "the younger duplicate should be deleted")
			})
		})
	})

	Context("When a duplicate shared network is recently created", func() {
		Describe("Given a younger duplicate a concurrent run may still be using", func() {
			It("converges on the oldest without deleting the recent duplicate", func() {
				var deletedYounger bool

				endpoints := NewEndpoints()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()

					switch {
					case r.Method == http.MethodGet && r.URL.RequestURI() == endpoints.ListNetworks(orgID, projectID, regionID):
						Expect(json.NewEncoder(w).Encode([]map[string]any{
							{"metadata": map[string]any{"id": "network-older", "name": SharedTestNetworkName, "provisioningStatus": "provisioned", "creationTime": "2026-01-01T00:00:00Z"}},
							{"metadata": map[string]any{"id": "network-younger", "name": SharedTestNetworkName, "provisioningStatus": "provisioned", "creationTime": time.Now().UTC().Format(time.RFC3339)}},
						})).To(Succeed())
					case r.Method == http.MethodDelete && r.URL.RequestURI() == endpoints.DeleteNetwork("network-younger"):
						deletedYounger = true
						w.WriteHeader(http.StatusAccepted)
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				DeferCleanup(server.Close)

				client := NewAPIClientWithConfig(&TestConfig{
					BaseConfig:    coreconfig.BaseConfig{BaseURL: server.URL, RequestTimeout: time.Second},
					RegionBaseURL: server.URL,
					OrgID:         orgID,
					ProjectID:     projectID,
					RegionID:      regionID,
				})

				network := MustResolveSharedNetwork(client, context.Background())

				Expect(network.Metadata.Id).To(Equal("network-older"))
				Expect(deletedYounger).To(BeFalse(), "a recently created duplicate must not be deleted")
			})
		})
	})

	Context("When a provisioning network settles with a mismatched CIDR", func() {
		Describe("Given its prefix is only known once provisioned", func() {
			It("fails loudly rather than reusing it after the wait", func() {
				endpoints := NewEndpoints()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()

					switch {
					case r.Method == http.MethodGet && r.URL.RequestURI() == endpoints.ListNetworks(orgID, projectID, regionID):
						Expect(json.NewEncoder(w).Encode([]map[string]any{{
							"metadata": map[string]any{"id": "network-prov", "name": SharedTestNetworkName, "provisioningStatus": "provisioning"},
						}})).To(Succeed())
					case r.Method == http.MethodGet && r.URL.RequestURI() == endpoints.GetNetwork("network-prov"):
						Expect(json.NewEncoder(w).Encode(map[string]any{
							"metadata": map[string]any{"id": "network-prov", "name": SharedTestNetworkName, "provisioningStatus": "provisioned"},
							"status":   map[string]any{"prefix": "10.0.0.0/8"},
						})).To(Succeed())
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				DeferCleanup(server.Close)

				client := NewAPIClientWithConfig(&TestConfig{
					BaseConfig:        coreconfig.BaseConfig{BaseURL: server.URL, RequestTimeout: time.Second},
					RegionBaseURL:     server.URL,
					OrgID:             orgID,
					ProjectID:         projectID,
					RegionID:          regionID,
					SharedNetworkCIDR: cidr,
				})

				failures := InterceptGomegaFailures(func() { MustResolveSharedNetwork(client, context.Background()) })

				Expect(failures).To(ContainElement(SatisfyAll(
					ContainSubstring("exists with CIDR"),
					ContainSubstring("make reset-shared-network"),
				)))
			})
		})
	})

	Context("When creating the shared network exceeds the network quota", func() {
		Describe("Given the create call returns 403 with a quota body", func() {
			It("fails naming the quota and the remedy", func() {
				endpoints := NewEndpoints()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()

					switch {
					case r.Method == http.MethodGet && r.URL.RequestURI() == endpoints.ListNetworks(orgID, projectID, regionID):
						Expect(json.NewEncoder(w).Encode([]map[string]any{})).To(Succeed())
					case r.Method == http.MethodPost && r.URL.RequestURI() == endpoints.CreateNetwork():
						w.WriteHeader(http.StatusForbidden)
						Expect(json.NewEncoder(w).Encode(map[string]any{
							"error":             "forbidden",
							"error_description": "allocation of 6 would exceed quota limit of 5",
						})).To(Succeed())
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				DeferCleanup(server.Close)

				client := NewAPIClientWithConfig(&TestConfig{
					BaseConfig: coreconfig.BaseConfig{
						BaseURL:        server.URL,
						RequestTimeout: time.Second,
					},
					RegionBaseURL:     server.URL,
					OrgID:             orgID,
					ProjectID:         projectID,
					RegionID:          regionID,
					SharedNetworkCIDR: cidr,
				})

				failures := InterceptGomegaFailures(func() {
					MustResolveSharedNetwork(client, context.Background())
				})

				Expect(failures).To(ContainElement(SatisfyAll(
					ContainSubstring("exceed quota limit of 5"),
					ContainSubstring("quota"),
				)))
			})
		})
	})

	Context("When the shared network exists but is in error", func() {
		Describe("Given the list reports it in error state", func() {
			It("fails loudly naming the probable cause and the reset target", func() {
				endpoints := NewEndpoints()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()

					switch {
					case r.Method == http.MethodGet && r.URL.RequestURI() == endpoints.ListNetworks(orgID, projectID, regionID):
						Expect(json.NewEncoder(w).Encode([]map[string]any{{
							"metadata": map[string]any{
								"id":                 "network-broken",
								"name":               SharedTestNetworkName,
								"provisioningStatus": "error",
							},
						}})).To(Succeed())
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				DeferCleanup(server.Close)

				client := NewAPIClientWithConfig(&TestConfig{
					BaseConfig: coreconfig.BaseConfig{
						BaseURL:        server.URL,
						RequestTimeout: time.Second,
					},
					RegionBaseURL:     server.URL,
					OrgID:             orgID,
					ProjectID:         projectID,
					RegionID:          regionID,
					SharedNetworkCIDR: cidr,
				})

				failures := InterceptGomegaFailures(func() {
					MustResolveSharedNetwork(client, context.Background())
				})

				Expect(failures).To(ContainElement(SatisfyAll(
					ContainSubstring("error state"),
					ContainSubstring("VLAN pool exhaustion"),
					ContainSubstring("make reset-shared-network"),
				)))
			})
		})
	})

	Context("When the shared network exists but is still provisioning", func() {
		Describe("Given the list reports it provisioning and it later settles provisioned", func() {
			It("waits for it to provision before returning", func() {
				endpoints := NewEndpoints()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()

					switch {
					case r.Method == http.MethodGet && r.URL.RequestURI() == endpoints.ListNetworks(orgID, projectID, regionID):
						Expect(json.NewEncoder(w).Encode([]map[string]any{{
							"metadata": map[string]any{
								"id":                 "network-existing",
								"name":               SharedTestNetworkName,
								"provisioningStatus": "provisioning",
							},
						}})).To(Succeed())
					case r.Method == http.MethodGet && r.URL.RequestURI() == endpoints.GetNetwork("network-existing"):
						Expect(json.NewEncoder(w).Encode(provisionedNetwork("network-existing"))).To(Succeed())
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				DeferCleanup(server.Close)

				client := NewAPIClientWithConfig(&TestConfig{
					BaseConfig: coreconfig.BaseConfig{
						BaseURL:        server.URL,
						RequestTimeout: time.Second,
					},
					RegionBaseURL:     server.URL,
					OrgID:             orgID,
					ProjectID:         projectID,
					RegionID:          regionID,
					SharedNetworkCIDR: cidr,
				})

				network := MustResolveSharedNetwork(client, context.Background())

				Expect(network.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
			})
		})
	})

	Context("When an existing shared network has a different CIDR", func() {
		Describe("Given the list returns it with a mismatched prefix", func() {
			It("fails loudly rather than reusing it", func() {
				endpoints := NewEndpoints()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()

					switch {
					case r.Method == http.MethodGet && r.URL.RequestURI() == endpoints.ListNetworks(orgID, projectID, regionID):
						Expect(json.NewEncoder(w).Encode([]map[string]any{{
							"metadata": map[string]any{"id": "network-existing", "name": SharedTestNetworkName, "provisioningStatus": "provisioned"},
							"status":   map[string]any{"prefix": "10.0.0.0/8"},
						}})).To(Succeed())
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				DeferCleanup(server.Close)

				client := NewAPIClientWithConfig(&TestConfig{
					BaseConfig:        coreconfig.BaseConfig{BaseURL: server.URL, RequestTimeout: time.Second},
					RegionBaseURL:     server.URL,
					OrgID:             orgID,
					ProjectID:         projectID,
					RegionID:          regionID,
					SharedNetworkCIDR: cidr,
				})

				failures := InterceptGomegaFailures(func() { MustResolveSharedNetwork(client, context.Background()) })

				Expect(failures).To(ContainElement(SatisfyAll(
					ContainSubstring("exists with CIDR"),
					ContainSubstring("make reset-shared-network"),
				)))
			})
		})
	})

	Context("When an existing shared network has an unhandled status", func() {
		Describe("Given the list returns an unexpected provisioning status", func() {
			It("fails loudly rather than treating it as usable", func() {
				endpoints := NewEndpoints()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()

					switch {
					case r.Method == http.MethodGet && r.URL.RequestURI() == endpoints.ListNetworks(orgID, projectID, regionID):
						Expect(json.NewEncoder(w).Encode([]map[string]any{{
							"metadata": map[string]any{"id": "network-existing", "name": SharedTestNetworkName, "provisioningStatus": "unknown"},
						}})).To(Succeed())
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				DeferCleanup(server.Close)

				client := NewAPIClientWithConfig(&TestConfig{
					BaseConfig:        coreconfig.BaseConfig{BaseURL: server.URL, RequestTimeout: time.Second},
					RegionBaseURL:     server.URL,
					OrgID:             orgID,
					ProjectID:         projectID,
					RegionID:          regionID,
					SharedNetworkCIDR: cidr,
				})

				failures := InterceptGomegaFailures(func() { MustResolveSharedNetwork(client, context.Background()) })

				Expect(failures).To(ContainElement(ContainSubstring("unhandled provisioning status")))
			})
		})
	})

	Context("When the created network lands in error", func() {
		Describe("Given create succeeds but provisioning fails", func() {
			It("fails fast with the diagnosis instead of waiting out the timeout", func() {
				endpoints := NewEndpoints()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()

					switch {
					case r.Method == http.MethodGet && r.URL.RequestURI() == endpoints.ListNetworks(orgID, projectID, regionID):
						Expect(json.NewEncoder(w).Encode([]map[string]any{})).To(Succeed())
					case r.Method == http.MethodPost && r.URL.RequestURI() == endpoints.CreateNetwork():
						w.WriteHeader(http.StatusCreated)
						Expect(json.NewEncoder(w).Encode(map[string]any{
							"metadata": map[string]any{"id": "network-new", "name": SharedTestNetworkName, "provisioningStatus": "provisioning"},
						})).To(Succeed())
					case r.Method == http.MethodGet && r.URL.RequestURI() == endpoints.GetNetwork("network-new"):
						Expect(json.NewEncoder(w).Encode(map[string]any{
							"metadata": map[string]any{"id": "network-new", "name": SharedTestNetworkName, "provisioningStatus": "error"},
						})).To(Succeed())
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				DeferCleanup(server.Close)

				client := NewAPIClientWithConfig(&TestConfig{
					BaseConfig: coreconfig.BaseConfig{
						BaseURL:        server.URL,
						RequestTimeout: time.Second,
					},
					RegionBaseURL:     server.URL,
					OrgID:             orgID,
					ProjectID:         projectID,
					RegionID:          regionID,
					SharedNetworkCIDR: cidr,
				})

				done := make(chan []string, 1)
				go func() {
					defer GinkgoRecover()
					done <- InterceptGomegaFailures(func() { MustResolveSharedNetwork(client, context.Background()) })
				}()

				var failures []string
				Eventually(done, 30*time.Second).Should(Receive(&failures), "resolver should fail fast, not wait out the provisioning timeout")
				Expect(failures).To(ContainElement(SatisfyAll(
					ContainSubstring("error state"),
					ContainSubstring("make reset-shared-network"),
				)))
			})
		})
	})

	Context("When the shared network does not yet exist", func() {
		Describe("Given an empty network list in the org", func() {
			It("creates it once with the shared name and configured CIDR", func() {
				var createCalls int
				var createdName, createdPrefix string

				endpoints := NewEndpoints()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()

					switch {
					case r.Method == http.MethodGet && r.URL.RequestURI() == endpoints.ListNetworks(orgID, projectID, regionID):
						Expect(json.NewEncoder(w).Encode([]map[string]any{})).To(Succeed())
					case r.Method == http.MethodPost && r.URL.RequestURI() == endpoints.CreateNetwork():
						createCalls++
						var body map[string]any
						Expect(json.NewDecoder(r.Body).Decode(&body)).To(Succeed())
						createdName, _ = body["metadata"].(map[string]any)["name"].(string)
						createdPrefix, _ = body["spec"].(map[string]any)["prefix"].(string)
						w.WriteHeader(http.StatusCreated)
						Expect(json.NewEncoder(w).Encode(map[string]any{
							"metadata": map[string]any{
								"id":                 "network-1",
								"name":               SharedTestNetworkName,
								"provisioningStatus": "provisioned",
							},
						})).To(Succeed())
					case r.Method == http.MethodGet && r.URL.RequestURI() == endpoints.GetNetwork("network-1"):
						Expect(json.NewEncoder(w).Encode(map[string]any{
							"metadata": map[string]any{
								"id":                 "network-1",
								"name":               SharedTestNetworkName,
								"provisioningStatus": "provisioned",
							},
						})).To(Succeed())
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				DeferCleanup(server.Close)

				client := NewAPIClientWithConfig(&TestConfig{
					BaseConfig: coreconfig.BaseConfig{
						BaseURL:        server.URL,
						RequestTimeout: time.Second,
					},
					RegionBaseURL:     server.URL,
					OrgID:             orgID,
					ProjectID:         projectID,
					RegionID:          regionID,
					SharedNetworkCIDR: cidr,
				})

				network := MustResolveSharedNetwork(client, context.Background())

				Expect(createCalls).To(Equal(1))
				Expect(createdName).To(Equal(SharedTestNetworkName))
				Expect(createdPrefix).To(Equal(cidr))
				Expect(network.Metadata.Id).To(Equal("network-1"))
			})
		})
	})
})
