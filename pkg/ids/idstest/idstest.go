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

// Package idstest provides panic-on-error constructors for the typed resource
// identifiers in pkg/ids. They are intended for tests and other contexts where
// the input is a known-good literal; production code must use the error-returning
// ids.Parse* functions so a malformed value fails closed rather than crashing the
// process. Keeping the MustParse* helpers out of pkg/ids stops them being reached
// for on a request path by mistake.
package idstest

import (
	"github.com/google/uuid"

	"github.com/unikorn-cloud/region/pkg/ids"
)

// MustParseRegionID parses s as a UUID into a RegionID, panicking if invalid.
func MustParseRegionID(s string) ids.RegionID { return ids.RegionID(uuid.MustParse(s)) }

// MustParseIdentityID parses s as a UUID into an IdentityID, panicking if invalid.
func MustParseIdentityID(s string) ids.IdentityID { return ids.IdentityID(uuid.MustParse(s)) }

// MustParseNetworkID parses s as a UUID into a NetworkID, panicking if invalid.
func MustParseNetworkID(s string) ids.NetworkID { return ids.NetworkID(uuid.MustParse(s)) }

// MustParseSecurityGroupID parses s as a UUID into a SecurityGroupID, panicking if invalid.
func MustParseSecurityGroupID(s string) ids.SecurityGroupID {
	return ids.SecurityGroupID(uuid.MustParse(s))
}

// MustParseLoadBalancerID parses s as a UUID into a LoadBalancerID, panicking if invalid.
func MustParseLoadBalancerID(s string) ids.LoadBalancerID {
	return ids.LoadBalancerID(uuid.MustParse(s))
}

// MustParseServerID parses s as a UUID into a ServerID, panicking if invalid.
func MustParseServerID(s string) ids.ServerID { return ids.ServerID(uuid.MustParse(s)) }

// MustParseSSHCertificateAuthorityID parses s as a UUID into an SSHCertificateAuthorityID, panicking if invalid.
func MustParseSSHCertificateAuthorityID(s string) ids.SSHCertificateAuthorityID {
	return ids.SSHCertificateAuthorityID(uuid.MustParse(s))
}

// MustParseFileStorageID parses s as a UUID into a FileStorageID, panicking if invalid.
func MustParseFileStorageID(s string) ids.FileStorageID {
	return ids.FileStorageID(uuid.MustParse(s))
}

// MustParseImageID parses s as a UUID into an ImageID, panicking if invalid.
func MustParseImageID(s string) ids.ImageID { return ids.ImageID(uuid.MustParse(s)) }

// MustParseFlavorID parses s as a UUID into a FlavorID, panicking if invalid.
func MustParseFlavorID(s string) ids.FlavorID { return ids.FlavorID(uuid.MustParse(s)) }
