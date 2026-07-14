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

package ids_test

import (
	"fmt"
	"testing"

	"github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"
)

const (
	validUUID   = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	invalidUUID = "not-a-uuid"
)

func TestStringFormats(t *testing.T) {
	t.Parallel()

	// Verify value receiver String() works correctly with fmt verbs for all types.
	// This guards against a regression where pointer-receiver-only String() causes
	// fmt to fall back to raw byte-array formatting.
	cases := []struct {
		name string
		s    string
		v    string
	}{
		{
			"RegionID",
			fmt.Sprintf("%s", idstest.MustParseRegionID(validUUID)), //nolint:staticcheck
			fmt.Sprintf("%v", idstest.MustParseRegionID(validUUID)),
		},
		{
			"IdentityID",
			fmt.Sprintf("%s", idstest.MustParseIdentityID(validUUID)), //nolint:staticcheck
			fmt.Sprintf("%v", idstest.MustParseIdentityID(validUUID)),
		},
		{
			"NetworkID",
			fmt.Sprintf("%s", idstest.MustParseNetworkID(validUUID)), //nolint:staticcheck
			fmt.Sprintf("%v", idstest.MustParseNetworkID(validUUID)),
		},
		{
			"SecurityGroupID",
			fmt.Sprintf("%s", idstest.MustParseSecurityGroupID(validUUID)), //nolint:staticcheck
			fmt.Sprintf("%v", idstest.MustParseSecurityGroupID(validUUID)),
		},
		{
			"LoadBalancerID",
			fmt.Sprintf("%s", idstest.MustParseLoadBalancerID(validUUID)), //nolint:staticcheck
			fmt.Sprintf("%v", idstest.MustParseLoadBalancerID(validUUID)),
		},
		{
			"VolumeID",
			fmt.Sprintf("%s", idstest.MustParseVolumeID(validUUID)), //nolint:staticcheck
			fmt.Sprintf("%v", idstest.MustParseVolumeID(validUUID)),
		},
		{
			"ServerID",
			fmt.Sprintf("%s", idstest.MustParseServerID(validUUID)), //nolint:staticcheck
			fmt.Sprintf("%v", idstest.MustParseServerID(validUUID)),
		},
		{
			"SSHCertificateAuthorityID",
			fmt.Sprintf("%s", idstest.MustParseSSHCertificateAuthorityID(validUUID)), //nolint:staticcheck
			fmt.Sprintf("%v", idstest.MustParseSSHCertificateAuthorityID(validUUID)),
		},
		{
			"FileStorageID",
			fmt.Sprintf("%s", idstest.MustParseFileStorageID(validUUID)), //nolint:staticcheck
			fmt.Sprintf("%v", idstest.MustParseFileStorageID(validUUID)),
		},
		{
			"ImageID",
			fmt.Sprintf("%s", idstest.MustParseImageID(validUUID)), //nolint:staticcheck
			fmt.Sprintf("%v", idstest.MustParseImageID(validUUID)),
		},
		{
			"FlavorID",
			fmt.Sprintf("%s", idstest.MustParseFlavorID(validUUID)), //nolint:staticcheck
			fmt.Sprintf("%v", idstest.MustParseFlavorID(validUUID)),
		},
	}

	for _, tc := range cases {
		if tc.s != validUUID {
			t.Errorf("%s: fmt.Sprintf(%%s) = %q, want %q", tc.name, tc.s, validUUID)
		}

		if tc.v != validUUID {
			t.Errorf("%s: fmt.Sprintf(%%v) = %q, want %q", tc.name, tc.v, validUUID)
		}
	}
}

func TestMarshalText(t *testing.T) {
	t.Parallel()

	type marshaler interface {
		MarshalText() ([]byte, error)
	}

	cases := []struct {
		name  string
		value marshaler
	}{
		{"RegionID", idstest.MustParseRegionID(validUUID)},
		{"IdentityID", idstest.MustParseIdentityID(validUUID)},
		{"NetworkID", idstest.MustParseNetworkID(validUUID)},
		{"SecurityGroupID", idstest.MustParseSecurityGroupID(validUUID)},
		{"LoadBalancerID", idstest.MustParseLoadBalancerID(validUUID)},
		{"VolumeID", idstest.MustParseVolumeID(validUUID)},
		{"ServerID", idstest.MustParseServerID(validUUID)},
		{"SSHCertificateAuthorityID", idstest.MustParseSSHCertificateAuthorityID(validUUID)},
		{"FileStorageID", idstest.MustParseFileStorageID(validUUID)},
		{"ImageID", idstest.MustParseImageID(validUUID)},
		{"FlavorID", idstest.MustParseFlavorID(validUUID)},
	}

	for _, tc := range cases {
		b, err := tc.value.MarshalText()
		if err != nil {
			t.Errorf("%s: MarshalText returned unexpected error: %v", tc.name, err)
			continue
		}

		if string(b) != validUUID {
			t.Errorf("%s: MarshalText = %q, want %q", tc.name, string(b), validUUID)
		}
	}
}

func TestUnmarshalTextAcceptsValid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		target interface {
			UnmarshalText(text []byte) error
			String() string
		}
	}{
		{"RegionID", new(ids.RegionID)},
		{"IdentityID", new(ids.IdentityID)},
		{"NetworkID", new(ids.NetworkID)},
		{"SecurityGroupID", new(ids.SecurityGroupID)},
		{"LoadBalancerID", new(ids.LoadBalancerID)},
		{"VolumeID", new(ids.VolumeID)},
		{"ServerID", new(ids.ServerID)},
		{"SSHCertificateAuthorityID", new(ids.SSHCertificateAuthorityID)},
		{"FileStorageID", new(ids.FileStorageID)},
		{"ImageID", new(ids.ImageID)},
		{"FlavorID", new(ids.FlavorID)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := tc.target.UnmarshalText([]byte(validUUID)); err != nil {
				t.Fatalf("%s.UnmarshalText returned unexpected error: %v", tc.name, err)
			}

			if got := tc.target.String(); got != validUUID {
				t.Fatalf("%s: round-trip mismatch: got %q, want %q", tc.name, got, validUUID)
			}
		})
	}
}

func TestUnmarshalTextRejectsInvalid(t *testing.T) {
	t.Parallel()

	type unmarshalTarget interface {
		UnmarshalText(text []byte) error
	}

	cases := []struct {
		name   string
		target unmarshalTarget
	}{
		{"RegionID", new(ids.RegionID)},
		{"IdentityID", new(ids.IdentityID)},
		{"NetworkID", new(ids.NetworkID)},
		{"SecurityGroupID", new(ids.SecurityGroupID)},
		{"LoadBalancerID", new(ids.LoadBalancerID)},
		{"VolumeID", new(ids.VolumeID)},
		{"ServerID", new(ids.ServerID)},
		{"SSHCertificateAuthorityID", new(ids.SSHCertificateAuthorityID)},
		{"FileStorageID", new(ids.FileStorageID)},
		{"ImageID", new(ids.ImageID)},
		{"FlavorID", new(ids.FlavorID)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := tc.target.UnmarshalText([]byte(invalidUUID)); err == nil {
				t.Fatalf("%s.UnmarshalText should reject non-UUID input", tc.name)
			}
		})
	}
}

func TestParseRoundTrips(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		fn   func(string) (string, error)
	}{
		{"ParseRegionID", func(s string) (string, error) {
			v, err := ids.ParseRegionID(s)
			return v.String(), err
		}},
		{"ParseIdentityID", func(s string) (string, error) {
			v, err := ids.ParseIdentityID(s)
			return v.String(), err
		}},
		{"ParseNetworkID", func(s string) (string, error) {
			v, err := ids.ParseNetworkID(s)
			return v.String(), err
		}},
		{"ParseSecurityGroupID", func(s string) (string, error) {
			v, err := ids.ParseSecurityGroupID(s)
			return v.String(), err
		}},
		{"ParseLoadBalancerID", func(s string) (string, error) {
			v, err := ids.ParseLoadBalancerID(s)
			return v.String(), err
		}},
		{"ParseVolumeID", func(s string) (string, error) {
			v, err := ids.ParseVolumeID(s)
			return v.String(), err
		}},
		{"ParseServerID", func(s string) (string, error) {
			v, err := ids.ParseServerID(s)
			return v.String(), err
		}},
		{"ParseSSHCertificateAuthorityID", func(s string) (string, error) {
			v, err := ids.ParseSSHCertificateAuthorityID(s)
			return v.String(), err
		}},
		{"ParseFileStorageID", func(s string) (string, error) {
			v, err := ids.ParseFileStorageID(s)
			return v.String(), err
		}},
		{"ParseImageID", func(s string) (string, error) {
			v, err := ids.ParseImageID(s)
			return v.String(), err
		}},
		{"ParseFlavorID", func(s string) (string, error) {
			v, err := ids.ParseFlavorID(s)
			return v.String(), err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name+"/valid", func(t *testing.T) {
			t.Parallel()

			got, err := tc.fn(validUUID)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != validUUID {
				t.Fatalf("String() = %q, want %q", got, validUUID)
			}
		})

		t.Run(tc.name+"/invalid", func(t *testing.T) {
			t.Parallel()

			if _, err := tc.fn(invalidUUID); err == nil {
				t.Fatal("expected error for invalid UUID, got nil")
			}
		})
	}
}
