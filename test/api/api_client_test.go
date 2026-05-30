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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

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
