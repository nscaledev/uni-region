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

//nolint:revive,paralleltest,testpackage // Ginkgo suite uses dot imports and package-local helper access.
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreconfig "github.com/unikorn-cloud/core/pkg/testing/config"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
)

func TestAPI(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "API Helpers Suite")
}

var _ = Describe("Internal API Client", func() {
	Context("When preparing attributed internal requests", func() {
		Describe("Given local mTLS credentials are configured", func() {
			It("should add a principal without enabling impersonation", func() {
				client := &APIClient{
					config: &TestConfig{
						OrgID:            "org-1",
						ProjectID:        "project-1",
						InternalAPIActor: "ci-admin-sa",
					},
				}
				request := httptest.NewRequest(http.MethodGet, "https://region.example/api/v2/servers", nil)

				Expect(client.addInternalRequestHeaders(request)).To(Succeed())
				Expect(request.Header.Get(principal.ImpersonateHeader)).To(BeEmpty())
				Expect(request.Header.Get("Authorization")).To(BeEmpty())
				Expect(request.Header.Get("Traceparent")).NotTo(BeEmpty())

				data, err := base64.RawURLEncoding.DecodeString(request.Header.Get(principal.Header))
				Expect(err).NotTo(HaveOccurred())

				var got principal.Principal
				Expect(json.Unmarshal(data, &got)).To(Succeed())
				Expect(got.OrganizationID).To(Equal("org-1"))
				Expect(got.OrganizationIDs).To(Equal([]string{"org-1"}))
				Expect(got.ProjectID).To(Equal("project-1"))
				Expect(got.Type).To(Equal(identityopenapi.Service))
				Expect(got.Actor).To(Equal("ci-admin-sa"))
			})
		})
	})
})

var _ = Describe("Network fixture cleanup", func() {
	Context("When deleting a network fixture", func() {
		Describe("Given an empty network ID", func() {
			It("should skip cleanup", func() {
				MustDeleteNetwork(&APIClient{}, context.Background(), "")
			})
		})

		Describe("Given an existing network", func() {
			It("should delete and wait for the network to disappear", func() {
				const networkID = "network-1"

				var deleteCalls atomic.Int32
				var getCalls atomic.Int32

				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					Expect(r.URL.Path).To(Equal("/api/v2/networks/" + networkID))

					switch r.Method {
					case http.MethodDelete:
						deleteCalls.Add(1)
						w.WriteHeader(http.StatusAccepted)
					case http.MethodGet:
						getCalls.Add(1)
						w.WriteHeader(http.StatusNotFound)
					default:
						w.WriteHeader(http.StatusMethodNotAllowed)
					}
				}))
				DeferCleanup(server.Close)

				client := NewAPIClientWithConfig(&TestConfig{
					BaseConfig: coreconfig.BaseConfig{
						BaseURL:        server.URL,
						RequestTimeout: time.Second,
					},
					RegionBaseURL: server.URL,
				})

				MustDeleteNetwork(client, context.Background(), networkID)

				Expect(deleteCalls.Load()).To(Equal(int32(1)))
				Expect(getCalls.Load()).To(Equal(int32(1)))
			})
		})

		Describe("Given an already deleted network", func() {
			It("should treat not found as successful cleanup", func() {
				const networkID = "network-1"

				var deleteCalls atomic.Int32

				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).To(Equal(http.MethodDelete))
					Expect(r.URL.Path).To(Equal("/api/v2/networks/" + networkID))

					deleteCalls.Add(1)
					w.WriteHeader(http.StatusNotFound)
				}))
				DeferCleanup(server.Close)

				client := NewAPIClientWithConfig(&TestConfig{
					BaseConfig: coreconfig.BaseConfig{
						BaseURL:        server.URL,
						RequestTimeout: time.Second,
					},
					RegionBaseURL: server.URL,
				})

				MustDeleteNetwork(client, context.Background(), networkID)

				Expect(deleteCalls.Load()).To(Equal(int32(1)))
			})
		})
	})
})
