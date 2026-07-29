/*
Copyright 2025 the Unikorn Authors.
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

package server

import (
	"context"
	goerrors "errors"
	"fmt"
	"slices"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/apimachinery/pkg/api/resource"
)

// validateVirtualization rejects an image whose virtualization type cannot run
// on the flavor. Unrecognized values fail closed: a value this build does not
// know about is positive evidence of version skew or bad provider metadata,
// and this gate fronts a path that ends in root-disk destruction, so it must
// not pass as universally compatible. An empty value fails open like a missing
// architecture: the provider surfaces images without the virtualization
// property (out-of-band Glance uploads, images predating the label) as "", and
// absence of evidence is not evidence of incompatibility.
func validateVirtualization(imageVirtualization types.ImageVirtualization, flavorBaremetal bool) error {
	switch imageVirtualization {
	case "":
	case types.Baremetal:
		if !flavorBaremetal {
			return errors.HTTPUnprocessableContent("image virtualization is not compatible with the flavor")
		}
	case types.Virtualized:
		if flavorBaremetal {
			return errors.HTTPUnprocessableContent("image virtualization is not compatible with the flavor")
		}
	case types.Any:
	default:
		return errors.HTTPUnprocessableContent("image virtualization type is not recognized")
	}

	return nil
}

func architectureCompatible(imageArchitecture, flavorArchitecture types.Architecture) bool {
	// Deliberately fail open on missing metadata: absence of an architecture is
	// absence of evidence (legitimate for existing images and flavors), unlike an
	// unrecognized virtualization value which is positive evidence of skew.
	if imageArchitecture == "" || flavorArchitecture == "" {
		return true
	}

	return imageArchitecture == flavorArchitecture
}

// serverImage returns the provider's image with the given ID, mapping the
// provider's not-found onto HTTP 404 so a dangling image reference surfaces
// identically on every path that resolves one.
func serverImage(ctx context.Context, provider types.Provider, organizationID identityids.OrganizationID, imageID regionids.ImageID) (*types.Image, error) {
	image, err := provider.GetImage(ctx, organizationID, imageID)
	if err != nil {
		if goerrors.Is(err, coreerrors.ErrResourceNotFound) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: failed to retrieve image from provider", err)
	}

	return image, nil
}

// readyServerImage returns the provider's image with the given ID, rejecting
// with HTTP 422 an image that exists but is not yet usable.
func readyServerImage(ctx context.Context, provider types.Provider, organizationID identityids.OrganizationID, imageID regionids.ImageID) (*types.Image, error) {
	image, err := serverImage(ctx, provider, organizationID, imageID)
	if err != nil {
		return nil, err
	}

	if image.Status != types.ImageStatusReady {
		return nil, errors.HTTPUnprocessableContent("image is not ready for use")
	}

	return image, nil
}

// flavorByID returns the region's flavor with the given ID, or a wrapped
// coreerrors.ErrResourceNotFound when the region no longer offers it. Whether
// a miss is fatal is a per-caller policy decision, so it is reported here, not
// mapped onto an HTTP status.
func flavorByID(ctx context.Context, provider types.Provider, flavorID regionids.FlavorID) (*types.Flavor, error) {
	flavors, err := provider.Flavors(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to retrieve flavors from provider", err)
	}

	index := slices.IndexFunc(flavors, func(flavor types.Flavor) bool {
		return flavor.ID == flavorID.String()
	})
	if index < 0 {
		return nil, fmt.Errorf("%w: flavor %s is not offered by the region", coreerrors.ErrResourceNotFound, flavorID)
	}

	return &flavors[index], nil
}

// validateImageFlavorCompatibility enforces the flavor-dependent image checks:
// CPU architecture, root-disk capacity, and virtualization type.
func validateImageFlavorCompatibility(image *types.Image, flavor *types.Flavor) error {
	if !architectureCompatible(image.Architecture, flavor.Architecture) {
		return errors.HTTPUnprocessableContent("image architecture is not compatible with the flavor")
	}

	if flavor.Disk != nil && flavor.Disk.ScaledValue(resource.Giga) < int64(image.SizeGiB) {
		return errors.HTTPUnprocessableContent("flavor disk is too small for the image")
	}

	return validateVirtualization(image.Virtualization, flavor.Baremetal)
}

// validateServerImageForCreate enforces the create-path image contract: the
// image must exist and be visible to the organization, be Ready, and be
// compatible with the requested flavor. A flavor the region no longer offers
// fails loudly and identifiably with HTTP 422 — a create cannot proceed on
// retired hardware, and an anonymous 404 would read as "server not found".
func validateServerImageForCreate(ctx context.Context, provider types.Provider, organizationID identityids.OrganizationID, imageID regionids.ImageID, flavorID regionids.FlavorID) error {
	image, err := readyServerImage(ctx, provider, organizationID, imageID)
	if err != nil {
		return err
	}

	flavor, err := flavorByID(ctx, provider, flavorID)
	if err != nil {
		if goerrors.Is(err, coreerrors.ErrResourceNotFound) {
			return errors.HTTPUnprocessableContent("flavor is no longer offered by the region").WithError(err)
		}

		return err
	}

	return validateImageFlavorCompatibility(image, flavor)
}

// validateServerImageForUpdate enforces the update-path image contract: the
// image-only checks (existence, readiness) always apply, but a flavor the
// region no longer offers is tolerated. The flavor is immutable and provably
// in use — this exact server is already running on that hardware — so a
// retired flavor must not strand the fleet: an image update (e.g. a
// security-patch rebuild) must still go through. On a miss the
// flavor-dependent compatibility checks (architecture, disk size,
// virtualization) are skipped because the flavor's metadata is unavailable;
// Nova is the remaining backstop for a truly incompatible rebuild, and the
// rebuild state machine parks the server on ERROR if Nova objects.
func validateServerImageForUpdate(ctx context.Context, provider types.Provider, organizationID identityids.OrganizationID, imageID regionids.ImageID, flavorID regionids.FlavorID) error {
	image, err := readyServerImage(ctx, provider, organizationID, imageID)
	if err != nil {
		return err
	}

	flavor, err := flavorByID(ctx, provider, flavorID)
	if err != nil {
		if goerrors.Is(err, coreerrors.ErrResourceNotFound) {
			return nil
		}

		return err
	}

	return validateImageFlavorCompatibility(image, flavor)
}
