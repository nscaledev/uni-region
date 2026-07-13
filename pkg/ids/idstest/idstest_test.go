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

package idstest_test

import (
	"testing"

	"github.com/unikorn-cloud/region/pkg/ids/idstest"
)

const invalidUUID = "not-a-uuid"

func TestMustParsePanics(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		fn   func(string)
	}{
		{"MustParseRegionID", func(s string) { idstest.MustParseRegionID(s) }},
		{"MustParseIdentityID", func(s string) { idstest.MustParseIdentityID(s) }},
		{"MustParseNetworkID", func(s string) { idstest.MustParseNetworkID(s) }},
		{"MustParseSecurityGroupID", func(s string) { idstest.MustParseSecurityGroupID(s) }},
		{"MustParseLoadBalancerID", func(s string) { idstest.MustParseLoadBalancerID(s) }},
		{"MustParseServerID", func(s string) { idstest.MustParseServerID(s) }},
		{"MustParseSSHCertificateAuthorityID", func(s string) { idstest.MustParseSSHCertificateAuthorityID(s) }},
		{"MustParseFileStorageID", func(s string) { idstest.MustParseFileStorageID(s) }},
		{"MustParseImageID", func(s string) { idstest.MustParseImageID(s) }},
		{"MustParseFlavorID", func(s string) { idstest.MustParseFlavorID(s) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if r := recover(); r == nil {
					t.Fatalf("%s should panic on invalid UUID", tc.name)
				}
			}()

			tc.fn(invalidUUID)
		})
	}
}
