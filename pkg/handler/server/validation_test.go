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

//nolint:testpackage
package server

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	providermock "github.com/unikorn-cloud/region/pkg/providers/types/mock"

	"k8s.io/apimachinery/pkg/api/resource"
)

const (
	validationOrganizationID = "11111111-1111-4111-a111-111111111111"
	validationImageID        = "22222222-2222-4222-a222-222222222222"
	validationFlavorID       = "33333333-3333-4333-a333-333333333333"
)

func readyValidationImage() *types.Image {
	return &types.Image{
		ID:             validationImageID,
		Status:         types.ImageStatusReady,
		SizeGiB:        20,
		Virtualization: types.Any,
	}
}

func validationFlavors() types.FlavorList {
	return types.FlavorList{{
		ID:   validationFlavorID,
		Disk: resource.NewScaledQuantity(40, resource.Giga),
	}}
}

func TestValidateServerImage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		image   *types.Image
		flavors types.FlavorList
		wantErr string
	}{
		{name: "valid", image: readyValidationImage(), flavors: validationFlavors()},
		{name: "image not ready", image: &types.Image{Status: types.ImageStatusPending}, flavors: validationFlavors(), wantErr: "image is not ready"},
		{name: "flavor disk too small", image: &types.Image{Status: types.ImageStatusReady, SizeGiB: 80, Virtualization: types.Any}, flavors: validationFlavors(), wantErr: "disk is too small"},
		{name: "virtualization mismatch", image: &types.Image{Status: types.ImageStatusReady, Virtualization: types.Baremetal}, flavors: validationFlavors(), wantErr: "virtualization is not compatible"},
		{name: "architecture mismatch", image: &types.Image{Status: types.ImageStatusReady, Virtualization: types.Any, Architecture: types.Aarch64}, flavors: types.FlavorList{{ID: validationFlavorID, Disk: resource.NewScaledQuantity(40, resource.Giga), Architecture: types.X86_64}}, wantErr: "architecture is not compatible"},
		{name: "unknown flavor architecture", image: &types.Image{Status: types.ImageStatusReady, Virtualization: types.Any, Architecture: types.Aarch64}, flavors: validationFlavors()},
		{name: "unknown image architecture", image: readyValidationImage(), flavors: types.FlavorList{{ID: validationFlavorID, Disk: resource.NewScaledQuantity(40, resource.Giga), Architecture: types.Aarch64}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			provider := providermock.NewMockProvider(ctrl)
			provider.EXPECT().GetImage(gomock.Any(), identityids.MustParseOrganizationID(validationOrganizationID), idstest.MustParseImageID(validationImageID)).Return(test.image, nil)
			provider.EXPECT().Flavors(gomock.Any()).Return(test.flavors, nil).AnyTimes()

			err := validateServerImage(t.Context(), provider, identityids.MustParseOrganizationID(validationOrganizationID), idstest.MustParseImageID(validationImageID), idstest.MustParseFlavorID(validationFlavorID))
			if test.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantErr)
			}
		})
	}
}

func TestValidateServerImageNotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	provider := providermock.NewMockProvider(ctrl)
	organizationID := identityids.MustParseOrganizationID(validationOrganizationID)
	imageID := idstest.MustParseImageID(validationImageID)
	provider.EXPECT().GetImage(gomock.Any(), organizationID, imageID).Return(nil, coreerrors.ErrResourceNotFound)

	err := validateServerImage(t.Context(), provider, organizationID, imageID, regionids.FlavorID{})
	require.Error(t, err)
}
