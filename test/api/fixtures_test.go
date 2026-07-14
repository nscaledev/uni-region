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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Test resource naming", func() {
	Context("When running in GitHub Actions", func() {
		It("builds a repo/run/attempt/unix timestamp prefix", func() {
			now := time.Unix(1784023200, 0).UTC()
			getenv := func(key string) string {
				values := map[string]string{
					"GITHUB_RUN_ID":      "29234292437",
					"GITHUB_RUN_ATTEMPT": "2",
				}

				return values[key]
			}

			Expect(buildTestResourceRunNamePrefix(now, getenv)).
				To(Equal("auto-uni-region-29234292437-2-1784023200"))
		})
	})

	Context("When running locally", func() {
		It("builds a local/user/unix timestamp prefix", func() {
			now := time.Unix(1784023200, 0).UTC()
			getenv := func(key string) string {
				if key == "USER" {
					return "Test.User"
				}

				return ""
			}

			Expect(buildTestResourceRunNamePrefix(now, getenv)).
				To(Equal("auto-uni-region-local-test-user-1784023200"))
		})
	})

	Context("When generating a resource name", func() {
		It("keeps names within Kubernetes label value length", func() {
			name := uniqueName(
				"auto-uni-region-29234292437-1-1784023200",
				"very-long-resource-kind-name-that-needs-truncation",
				"12345678",
			)

			Expect(name).To(HavePrefix("auto-uni-region-29234292437-1-1784023200-"))
			Expect(name).To(HaveSuffix("-12345678"))
			Expect(len(name)).To(BeNumerically("<=", maxResourceNameLength))
		})
	})

	Context("When checking sweep ownership", func() {
		It("recognises current and legacy test resource prefixes", func() {
			Expect(IsTestResourceName("auto-uni-region-29234292437-1-1784023200-lb-12345678")).To(BeTrue())
			Expect(IsTestResourceName("ginkgo-test-network-12345678")).To(BeTrue())
			Expect(IsTestResourceName("manual-network")).To(BeFalse())
		})
	})
})
