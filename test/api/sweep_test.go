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
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreconfig "github.com/unikorn-cloud/core/pkg/testing/config"
)

var _ = Describe("Stale test resource sweep", func() {
	Context("When dependent resources block deletion of their network", func() {
		Describe("Given the server, file storage, and network are stale test fixtures", func() {
			It("deletes the dependents before deleting the network", func() {
				const (
					serverID      = "server-1"
					fileStorageID = "filestorage-1"
					networkID     = "network-1"
				)

				var serverDeleted atomic.Bool
				var fileStorageDeleted atomic.Bool
				var networkDeleteCalls atomic.Int32

				created := time.Now().Add(-StaleTestResourceTTL - time.Hour).UTC()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()

					switch {
					case r.Method == http.MethodGet && r.URL.Path == "/api/v2/servers":
						Expect(json.NewEncoder(w).Encode([]map[string]any{{
							"metadata": map[string]any{
								"id":           serverID,
								"name":         "ginkgo-test-server-12345678",
								"creationTime": created,
							},
						}})).To(Succeed())
					case r.Method == http.MethodDelete && r.URL.Path == "/api/v2/servers/"+serverID:
						serverDeleted.Store(true)
						w.WriteHeader(http.StatusAccepted)
					case r.Method == http.MethodGet && r.URL.Path == "/api/v2/servers/"+serverID:
						Expect(serverDeleted.Load()).To(BeTrue())
						w.WriteHeader(http.StatusNotFound)
					case r.Method == http.MethodGet && r.URL.Path == "/api/v2/filestorage":
						Expect(json.NewEncoder(w).Encode([]map[string]any{{
							"metadata": map[string]any{
								"id":           fileStorageID,
								"name":         "ginkgo-test-filestorage-12345678",
								"creationTime": created,
							},
						}})).To(Succeed())
					case r.Method == http.MethodDelete && r.URL.Path == "/api/v2/filestorage/"+fileStorageID:
						Expect(serverDeleted.Load()).To(BeTrue())
						fileStorageDeleted.Store(true)
						w.WriteHeader(http.StatusAccepted)
					case r.Method == http.MethodGet && r.URL.Path == "/api/v2/filestorage/"+fileStorageID:
						Expect(fileStorageDeleted.Load()).To(BeTrue())
						w.WriteHeader(http.StatusNotFound)
					case r.Method == http.MethodGet && r.URL.Path == "/api/v2/networks":
						Expect(json.NewEncoder(w).Encode([]map[string]any{{
							"metadata": map[string]any{
								"id":           networkID,
								"name":         "ginkgo-test-network-12345678",
								"creationTime": created,
							},
						}})).To(Succeed())
					case r.Method == http.MethodDelete && r.URL.Path == "/api/v2/networks/"+networkID:
						networkDeleteCalls.Add(1)
						if !fileStorageDeleted.Load() {
							w.WriteHeader(http.StatusForbidden)
							return
						}
						w.WriteHeader(http.StatusAccepted)
					case r.Method == http.MethodGet && r.URL.Path == "/api/v2/networks/"+networkID:
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
					RegionBaseURL:   server.URL,
					OrgID:           "org-1",
					ProjectID:       "project-1",
					RegionID:        "region-1",
					InternalAPICert: "configured",
					InternalAPIKey:  "configured",
				})
				client.internalRegionHTTPClient = server.Client()

				SweepStaleTestResources(client, context.Background(), client.config)

				Expect(serverDeleted.Load()).To(BeTrue())
				Expect(fileStorageDeleted.Load()).To(BeTrue())
				Expect(networkDeleteCalls.Load()).To(Equal(int32(1)))
			})
		})
	})

	Context("When another sweep deletes a listed resource first", func() {
		Describe("Given the stale resource no longer exists at deletion time", func() {
			It("treats the concurrent deletion as successful", func() {
				const fileStorageID = "filestorage-1"

				var deleteCalls atomic.Int32

				created := time.Now().Add(-StaleTestResourceTTL - time.Hour).UTC()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()

					switch {
					case r.Method == http.MethodGet && r.URL.Path == "/api/v2/filestorage":
						Expect(json.NewEncoder(w).Encode([]map[string]any{{
							"metadata": map[string]any{
								"id":           fileStorageID,
								"name":         "ginkgo-test-filestorage-12345678",
								"creationTime": created,
							},
						}})).To(Succeed())
					case r.Method == http.MethodGet && r.URL.Path == "/api/v2/networks":
						Expect(json.NewEncoder(w).Encode([]map[string]any{})).To(Succeed())
					case r.Method == http.MethodDelete && r.URL.Path == "/api/v2/filestorage/"+fileStorageID:
						deleteCalls.Add(1)
						w.WriteHeader(http.StatusNotFound)
					case r.Method == http.MethodGet && r.URL.Path == "/api/v2/filestorage/"+fileStorageID:
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
					OrgID:         "org-1",
					ProjectID:     "project-1",
					RegionID:      "region-1",
				})

				SweepStaleTestResources(client, context.Background(), client.config)
				Expect(deleteCalls.Load()).To(Equal(int32(1)))
			})
		})
	})

	Context("When a listed resource is not eligible for sweeping", func() {
		Describe("Given it is young or does not have a test-owned name", func() {
			It("does not delete or wait for either resource", func() {
				var deleteCalls atomic.Int32
				var waitCalls atomic.Int32

				deleteResource := func() error {
					deleteCalls.Add(1)
					return nil
				}
				waitForGone := func() {
					waitCalls.Add(1)
				}

				sweepStaleTestResource("network", "network-young", "ginkgo-test-network-12345678",
					time.Now(), nil, deleteResource, waitForGone)
				sweepStaleTestResource("network", "network-foreign", "customer-network",
					time.Now().Add(-StaleTestResourceTTL-time.Hour), nil, deleteResource, waitForGone)

				Expect(deleteCalls.Load()).To(BeZero())
				Expect(waitCalls.Load()).To(BeZero())
			})
		})
	})
})
