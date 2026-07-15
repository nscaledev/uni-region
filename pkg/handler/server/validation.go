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

func virtualizationCompatible(imageVirtualization types.ImageVirtualization, flavorBaremetal bool) bool {
	switch imageVirtualization {
	case types.Baremetal:
		return flavorBaremetal
	case types.Virtualized:
		return !flavorBaremetal
	case types.Any:
		return true
	default:
		return true
	}
}

func architectureCompatible(imageArchitecture, flavorArchitecture types.Architecture) bool {
	if imageArchitecture == "" || flavorArchitecture == "" {
		return true
	}

	return imageArchitecture == flavorArchitecture
}

func validateServerImage(ctx context.Context, provider types.Provider, organizationID identityids.OrganizationID, imageID regionids.ImageID, flavorID regionids.FlavorID) error {
	image, err := provider.GetImage(ctx, organizationID, imageID)
	if err != nil {
		if goerrors.Is(err, coreerrors.ErrResourceNotFound) {
			return errors.HTTPNotFound().WithError(err)
		}

		return fmt.Errorf("%w: failed to retrieve image from provider", err)
	}

	if image.Status != types.ImageStatusReady {
		return errors.HTTPUnprocessableContent("image is not ready for use")
	}

	flavors, err := provider.Flavors(ctx)
	if err != nil {
		return fmt.Errorf("%w: failed to retrieve flavors from provider", err)
	}

	index := slices.IndexFunc(flavors, func(flavor types.Flavor) bool {
		return flavor.ID == flavorID.String()
	})
	if index < 0 {
		return errors.HTTPNotFound()
	}

	flavor := flavors[index]

	if !architectureCompatible(image.Architecture, flavor.Architecture) {
		return errors.HTTPUnprocessableContent("image architecture is not compatible with the flavor")
	}

	if flavor.Disk != nil && flavor.Disk.ScaledValue(resource.Giga) < int64(image.SizeGiB) {
		return errors.HTTPUnprocessableContent("flavor disk is too small for the image")
	}

	if !virtualizationCompatible(image.Virtualization, flavor.Baremetal) {
		return errors.HTTPUnprocessableContent("image virtualization is not compatible with the flavor")
	}

	return nil
}
