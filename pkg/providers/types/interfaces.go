/*
Copyright 2024-2025 the Unikorn Authors.

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

package types

import (
	"context"
	"io"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

// Providers are expected to provide a provider agnostic manner.
// They are also expected to provide any caching or memoization required
// to provide high performance and a decent UX.
//
//nolint:interfacebloat
type Provider interface {
	// Region returns the provider's region.
	Region(ctx context.Context) (*unikornv1.Region, error)
	// Flavors list all available flavors.
	Flavors(ctx context.Context) (FlavorList, error)
	// ListImages lists all available images.
	ListImages(ctx context.Context, organizationID string) (ImageList, error)
	// GetImage retrieves a specific image by its ID.
	GetImage(ctx context.Context, organizationID, imageID string, bypassCache bool) (*Image, error)
	// CreateImageForUpload creates a new image resource for upload.
	CreateImageForUpload(ctx context.Context, image *Image) (*Image, error)
	// CreateImageFromServer creates a new image from an existing server.
	CreateImageFromServer(ctx context.Context, serverID string, image *Image) (*Image, error)
	// UploadImage uploads data to an image.
	UploadImage(ctx context.Context, imageID string, reader io.Reader) error
	// FinalizeImage finalizes an image after upload.
	FinalizeImage(ctx context.Context, imageID string) (*Image, error)
	// DeleteImage deletes an image.
	DeleteImage(ctx context.Context, imageID string) error
	// CreateIdentity creates a new identity for cloud infrastructure.
	CreateIdentity(ctx context.Context, identity *unikornv1.Identity) error
	// DeleteIdentity cleans up an identity for cloud infrastructure.
	DeleteIdentity(ctx context.Context, identity *unikornv1.Identity) error
	// CreateNetwork creates a new physical network.
	CreateNetwork(ctx context.Context, identity *unikornv1.Identity, network *unikornv1.Network) error
	// DeleteNetwork deletes a physical network.
	DeleteNetwork(ctx context.Context, identity *unikornv1.Identity, network *unikornv1.Network) error
	// ListExternalNetworks returns a list of external networks if the platform
	// supports such a concept.
	ListExternalNetworks(ctx context.Context) (ExternalNetworks, error)
	// CreateSecurityGroup creates a new security group.
	CreateSecurityGroup(ctx context.Context, identity *unikornv1.Identity, securityGroup *unikornv1.SecurityGroup) error
	// DeleteSecurityGroup deletes a security group.
	DeleteSecurityGroup(ctx context.Context, identity *unikornv1.Identity, securityGroup *unikornv1.SecurityGroup) error
	// CreateServer creates a new server.
	CreateServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error
	// RebootServer soft reboots a server.
	RebootServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, hard bool) error
	// StartServer starts a server.
	StartServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error
	// StopServer stops a server.
	StopServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error
	// DeleteServer deletes a server.
	DeleteServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error
	// UpdateServerState checks a server's state and modifies the resource in place.
	UpdateServerState(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error
	// CreateConsoleSession creates a new console session for a server.
	CreateConsoleSession(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) (string, error)
	// GetConsoleOutput retrieves the console output for a server.
	GetConsoleOutput(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, length *int) (string, error)
}
