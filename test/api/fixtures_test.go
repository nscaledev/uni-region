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
	"strings"
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

		It("uses an unknown user fallback", func() {
			now := time.Unix(1784023200, 0).UTC()
			getenv := func(string) string {
				return ""
			}

			Expect(buildTestResourceRunNamePrefix(now, getenv)).
				To(Equal("auto-uni-region-local-unknown-1784023200"))
		})
	})

	Context("When generating a resource name", func() {
		It("includes the run prefix and a random suffix", func() {
			name := UniqueName("network")

			Expect(name).To(HavePrefix(TestResourceNamePrefix))
			Expect(name).To(MatchRegexp(`-[a-f0-9]{8}$`))
			Expect(len(name)).To(BeNumerically("<=", maxResourceNameLength))
			Expect(IsTestResourceName(name)).To(BeTrue())
		})

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

		It("falls back when name parts sanitize to empty", func() {
			name := uniqueName("", "!!!", "")

			Expect(name).To(HavePrefix("auto-uni-region-resource-"))
			Expect(name).To(MatchRegexp(`-[a-f0-9]{8}$`))
			Expect(len(name)).To(BeNumerically("<=", maxResourceNameLength))
		})

		It("truncates an oversized run prefix", func() {
			name := uniqueName(strings.Repeat("a", 80), "network", "12345678")

			Expect(name).To(HaveSuffix("-n-12345678"))
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

	Context("When sanitizing name parts", func() {
		It("normalizes unsupported characters and repeated separators", func() {
			Expect(sanitizeNamePart("--Alpha__Beta!!Gamma--")).To(Equal("alpha-beta-gamma"))
			Expect(sanitizeNamePart("!!!")).To(BeEmpty())
		})

		It("truncates safely", func() {
			Expect(truncateNamePart("-abcdef-", 4)).To(Equal("abc"))
			Expect(truncateNamePart("abc", 5)).To(Equal("abc"))
			Expect(truncateNamePart("abc", 0)).To(BeEmpty())
		})
	})
})
