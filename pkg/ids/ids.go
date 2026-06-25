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

package ids

import (
	"github.com/google/uuid"
)

// RegionID is a UUID-backed identifier for regions. It is a distinct
// named type so the compiler prevents accidental interchange with any other ID type.
// UnmarshalText delegates to uuid.UUID, so the oapi-codegen runtime rejects
// non-UUID path parameter values before any handler is reached.
//
// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Format=uuid
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type RegionID uuid.UUID

func (v RegionID) String() string                { return uuid.UUID(v).String() }
func (v RegionID) MarshalText() ([]byte, error)  { return uuid.UUID(v).MarshalText() }
func (v *RegionID) UnmarshalText(b []byte) error { return unmarshalUUID((*uuid.UUID)(v), b) }

// IdentityID is a UUID-backed identifier for cloud identities. It is a distinct
// named type so the compiler prevents accidental interchange with any other ID type.
// UnmarshalText delegates to uuid.UUID, so the oapi-codegen runtime rejects
// non-UUID path parameter values before any handler is reached.
//
// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Format=uuid
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type IdentityID uuid.UUID

func (v IdentityID) String() string                { return uuid.UUID(v).String() }
func (v IdentityID) MarshalText() ([]byte, error)  { return uuid.UUID(v).MarshalText() }
func (v *IdentityID) UnmarshalText(b []byte) error { return unmarshalUUID((*uuid.UUID)(v), b) }

// NetworkID is a UUID-backed identifier for networks. It is a distinct
// named type so the compiler prevents accidental interchange with any other ID type.
// UnmarshalText delegates to uuid.UUID, so the oapi-codegen runtime rejects
// non-UUID path parameter values before any handler is reached.
//
// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Format=uuid
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type NetworkID uuid.UUID

func (v NetworkID) String() string                { return uuid.UUID(v).String() }
func (v NetworkID) MarshalText() ([]byte, error)  { return uuid.UUID(v).MarshalText() }
func (v *NetworkID) UnmarshalText(b []byte) error { return unmarshalUUID((*uuid.UUID)(v), b) }

// SecurityGroupID is a UUID-backed identifier for security groups. It is a distinct
// named type so the compiler prevents accidental interchange with any other ID type.
// UnmarshalText delegates to uuid.UUID, so the oapi-codegen runtime rejects
// non-UUID path parameter values before any handler is reached.
//
// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Format=uuid
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type SecurityGroupID uuid.UUID

func (v SecurityGroupID) String() string                { return uuid.UUID(v).String() }
func (v SecurityGroupID) MarshalText() ([]byte, error)  { return uuid.UUID(v).MarshalText() }
func (v *SecurityGroupID) UnmarshalText(b []byte) error { return unmarshalUUID((*uuid.UUID)(v), b) }

// LoadBalancerID is a UUID-backed identifier for load balancers. It is a distinct
// named type so the compiler prevents accidental interchange with any other ID type.
// UnmarshalText delegates to uuid.UUID, so the oapi-codegen runtime rejects
// non-UUID path parameter values before any handler is reached.
//
// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Format=uuid
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type LoadBalancerID uuid.UUID

func (v LoadBalancerID) String() string                { return uuid.UUID(v).String() }
func (v LoadBalancerID) MarshalText() ([]byte, error)  { return uuid.UUID(v).MarshalText() }
func (v *LoadBalancerID) UnmarshalText(b []byte) error { return unmarshalUUID((*uuid.UUID)(v), b) }

// ServerID is a UUID-backed identifier for servers. It is a distinct
// named type so the compiler prevents accidental interchange with any other ID type.
// UnmarshalText delegates to uuid.UUID, so the oapi-codegen runtime rejects
// non-UUID path parameter values before any handler is reached.
//
// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Format=uuid
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type ServerID uuid.UUID

func (v ServerID) String() string                { return uuid.UUID(v).String() }
func (v ServerID) MarshalText() ([]byte, error)  { return uuid.UUID(v).MarshalText() }
func (v *ServerID) UnmarshalText(b []byte) error { return unmarshalUUID((*uuid.UUID)(v), b) }

// SSHCertificateAuthorityID is a UUID-backed identifier for SSH certificate authorities.
// It is a distinct named type so the compiler prevents accidental interchange with any
// other ID type. UnmarshalText delegates to uuid.UUID, so the oapi-codegen runtime rejects
// non-UUID path parameter values before any handler is reached.
//
// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Format=uuid
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type SSHCertificateAuthorityID uuid.UUID

func (v SSHCertificateAuthorityID) String() string               { return uuid.UUID(v).String() }
func (v SSHCertificateAuthorityID) MarshalText() ([]byte, error) { return uuid.UUID(v).MarshalText() }
func (v *SSHCertificateAuthorityID) UnmarshalText(b []byte) error {
	return unmarshalUUID((*uuid.UUID)(v), b)
}

// FileStorageID is a UUID-backed identifier for file storage. It is a distinct
// named type so the compiler prevents accidental interchange with any other ID type.
// UnmarshalText delegates to uuid.UUID, so the oapi-codegen runtime rejects
// non-UUID path parameter values before any handler is reached.
//
// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Format=uuid
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type FileStorageID uuid.UUID

func (v FileStorageID) String() string                { return uuid.UUID(v).String() }
func (v FileStorageID) MarshalText() ([]byte, error)  { return uuid.UUID(v).MarshalText() }
func (v *FileStorageID) UnmarshalText(b []byte) error { return unmarshalUUID((*uuid.UUID)(v), b) }

// ImageID is a UUID-backed identifier for images. The platform addresses images by
// their provider-assigned UUID; it is a distinct named type so the compiler prevents
// accidental interchange with any other ID type. UnmarshalText delegates to uuid.UUID,
// so the oapi-codegen runtime rejects non-UUID path parameter values before any handler
// is reached.
//
// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Format=uuid
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type ImageID uuid.UUID

func (v ImageID) String() string                { return uuid.UUID(v).String() }
func (v ImageID) MarshalText() ([]byte, error)  { return uuid.UUID(v).MarshalText() }
func (v *ImageID) UnmarshalText(b []byte) error { return unmarshalUUID((*uuid.UUID)(v), b) }

// FlavorID is a UUID-backed identifier for flavors. The platform addresses flavors by
// their provider-assigned UUID; it is a distinct named type so the compiler prevents
// accidental interchange with any other ID type. UnmarshalText delegates to uuid.UUID,
// so the oapi-codegen runtime rejects non-UUID path parameter values before any handler
// is reached.
//
// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Format=uuid
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type FlavorID uuid.UUID

func (v FlavorID) String() string                { return uuid.UUID(v).String() }
func (v FlavorID) MarshalText() ([]byte, error)  { return uuid.UUID(v).MarshalText() }
func (v *FlavorID) UnmarshalText(b []byte) error { return unmarshalUUID((*uuid.UUID)(v), b) }

// unmarshalUUID is the shared implementation for all UnmarshalText methods.
func unmarshalUUID(dst *uuid.UUID, text []byte) error {
	var id uuid.UUID

	if err := id.UnmarshalText(text); err != nil {
		return err
	}

	*dst = id

	return nil
}

// ParseRegionID parses s as a UUID into a RegionID, returning
// an error if s is not a valid UUID.
func ParseRegionID(s string) (RegionID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return RegionID{}, err
	}

	return RegionID(id), nil
}

// ParseIdentityID parses s as a UUID into an IdentityID, returning
// an error if s is not a valid UUID.
func ParseIdentityID(s string) (IdentityID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return IdentityID{}, err
	}

	return IdentityID(id), nil
}

// ParseNetworkID parses s as a UUID into a NetworkID, returning
// an error if s is not a valid UUID.
func ParseNetworkID(s string) (NetworkID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return NetworkID{}, err
	}

	return NetworkID(id), nil
}

// ParseSecurityGroupID parses s as a UUID into a SecurityGroupID, returning
// an error if s is not a valid UUID.
func ParseSecurityGroupID(s string) (SecurityGroupID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return SecurityGroupID{}, err
	}

	return SecurityGroupID(id), nil
}

// ParseLoadBalancerID parses s as a UUID into a LoadBalancerID, returning
// an error if s is not a valid UUID.
func ParseLoadBalancerID(s string) (LoadBalancerID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return LoadBalancerID{}, err
	}

	return LoadBalancerID(id), nil
}

// ParseServerID parses s as a UUID into a ServerID, returning
// an error if s is not a valid UUID.
func ParseServerID(s string) (ServerID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return ServerID{}, err
	}

	return ServerID(id), nil
}

// ParseSSHCertificateAuthorityID parses s as a UUID into an SSHCertificateAuthorityID,
// returning an error if s is not a valid UUID.
func ParseSSHCertificateAuthorityID(s string) (SSHCertificateAuthorityID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return SSHCertificateAuthorityID{}, err
	}

	return SSHCertificateAuthorityID(id), nil
}

// ParseFileStorageID parses s as a UUID into a FileStorageID, returning
// an error if s is not a valid UUID.
func ParseFileStorageID(s string) (FileStorageID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return FileStorageID{}, err
	}

	return FileStorageID(id), nil
}

// ParseImageID parses s as a UUID into an ImageID, returning
// an error if s is not a valid UUID.
func ParseImageID(s string) (ImageID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return ImageID{}, err
	}

	return ImageID(id), nil
}

// ParseFlavorID parses s as a UUID into a FlavorID, returning
// an error if s is not a valid UUID.
func ParseFlavorID(s string) (FlavorID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return FlavorID{}, err
	}

	return FlavorID(id), nil
}
