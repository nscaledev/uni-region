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
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
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

func TestValidateServerImageForCreate(t *testing.T) {
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
		{name: "virtualization not recognized", image: &types.Image{Status: types.ImageStatusReady, Virtualization: types.ImageVirtualization("paravirtualized")}, flavors: validationFlavors(), wantErr: "virtualization type is not recognized"},
		{name: "virtualization absent", image: &types.Image{Status: types.ImageStatusReady}, flavors: validationFlavors()},
		{name: "architecture mismatch", image: &types.Image{Status: types.ImageStatusReady, Virtualization: types.Any, Architecture: types.Aarch64}, flavors: types.FlavorList{{ID: validationFlavorID, Disk: resource.NewScaledQuantity(40, resource.Giga), Architecture: types.X86_64}}, wantErr: "architecture is not compatible"},
		{name: "unknown flavor architecture", image: &types.Image{Status: types.ImageStatusReady, Virtualization: types.Any, Architecture: types.Aarch64}, flavors: validationFlavors()},
		{name: "unknown image architecture", image: readyValidationImage(), flavors: types.FlavorList{{ID: validationFlavorID, Disk: resource.NewScaledQuantity(40, resource.Giga), Architecture: types.Aarch64}}},
		{name: "flavor no longer offered", image: readyValidationImage(), flavors: types.FlavorList{}, wantErr: "no longer offered"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			provider := providermock.NewMockProvider(ctrl)
			provider.EXPECT().GetImage(gomock.Any(), identityids.MustParseOrganizationID(validationOrganizationID), idstest.MustParseImageID(validationImageID)).Return(test.image, nil)
			provider.EXPECT().Flavors(gomock.Any()).Return(test.flavors, nil).AnyTimes()

			err := validateServerImageForCreate(t.Context(), provider, identityids.MustParseOrganizationID(validationOrganizationID), idstest.MustParseImageID(validationImageID), idstest.MustParseFlavorID(validationFlavorID))
			if test.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantErr)
			}
		})
	}
}

func TestValidateServerImageForUpdate(t *testing.T) {
	t.Parallel()

	// An image that would fail every flavor-dependent compatibility check
	// against the fixture flavor, proving those checks are skipped on a miss.
	incompatibleImage := &types.Image{
		ID:             validationImageID,
		Status:         types.ImageStatusReady,
		SizeGiB:        80,
		Virtualization: types.ImageVirtualization("paravirtualized"),
		Architecture:   types.Aarch64,
	}

	tests := []struct {
		name    string
		image   *types.Image
		flavors types.FlavorList
		wantErr string
	}{
		{name: "valid", image: readyValidationImage(), flavors: validationFlavors()},
		{name: "retired flavor skips compatibility checks", image: incompatibleImage, flavors: types.FlavorList{}},
		{name: "retired flavor still requires ready image", image: &types.Image{Status: types.ImageStatusPending}, flavors: types.FlavorList{}, wantErr: "image is not ready"},
		{name: "offered flavor still enforces compatibility", image: incompatibleImage, flavors: types.FlavorList{{ID: validationFlavorID, Disk: resource.NewScaledQuantity(40, resource.Giga), Architecture: types.X86_64}}, wantErr: "architecture is not compatible"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			provider := providermock.NewMockProvider(ctrl)
			provider.EXPECT().GetImage(gomock.Any(), identityids.MustParseOrganizationID(validationOrganizationID), idstest.MustParseImageID(validationImageID)).Return(test.image, nil)
			provider.EXPECT().Flavors(gomock.Any()).Return(test.flavors, nil).AnyTimes()

			err := validateServerImageForUpdate(t.Context(), provider, identityids.MustParseOrganizationID(validationOrganizationID), idstest.MustParseImageID(validationImageID), idstest.MustParseFlavorID(validationFlavorID))
			if test.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.wantErr)
			}
		})
	}
}

// TestValidateServerImageNotFound verifies both policy wrappers map a
// provider image miss onto HTTP 404 through the shared existence helper.
func TestValidateServerImageNotFound(t *testing.T) {
	t.Parallel()

	validators := map[string]func(context.Context, types.Provider, identityids.OrganizationID, regionids.ImageID, regionids.FlavorID) error{
		"create": validateServerImageForCreate,
		"update": validateServerImageForUpdate,
	}

	for name, validate := range validators {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			provider := providermock.NewMockProvider(ctrl)
			organizationID := identityids.MustParseOrganizationID(validationOrganizationID)
			imageID := idstest.MustParseImageID(validationImageID)
			provider.EXPECT().GetImage(gomock.Any(), organizationID, imageID).Return(nil, coreerrors.ErrResourceNotFound)

			err := validate(t.Context(), provider, organizationID, imageID, regionids.FlavorID{})
			require.Error(t, err)
			require.True(t, errors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
		})
	}
}

// newInfrastructureRefTestClient builds a ClientV2 whose provider reports the
// given flavor catalogue, as consumed by validateInfrastructureRefForFlavor.
func newInfrastructureRefTestClient(t *testing.T, flavors types.FlavorList) *ClientV2 {
	t.Helper()

	ctrl := gomock.NewController(t)

	provider := providermock.NewMockProvider(ctrl)
	provider.EXPECT().Flavors(gomock.Any()).Return(flavors, nil).AnyTimes()

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(gomock.Any()).Return(provider, nil).AnyTimes()

	return NewClientV2(common.ClientArgs{Providers: providers})
}

// TestValidateInfrastructureRefForFlavorRejectsRetiredFlavor verifies that a
// flavor absent from the region's catalogue does not silently pass the
// pinned-only gate: on the create path (the only caller) it is the same 422 as
// the image validation's create-path flavor-miss policy.
func TestValidateInfrastructureRefForFlavorRejectsRetiredFlavor(t *testing.T) {
	t.Parallel()

	c := newInfrastructureRefTestClient(t, types.FlavorList{})

	err := c.validateInfrastructureRefForFlavor(t.Context(), "region", idstest.MustParseFlavorID(validationFlavorID), nil)
	require.Error(t, err)
	require.ErrorContains(t, err, "no longer offered")
}

// TestValidateInfrastructureRefForFlavorRequiresRefForPinnedFlavor pins the
// existing behaviour that a pinned-only flavor demands an infrastructureRef.
func TestValidateInfrastructureRefForFlavorRequiresRefForPinnedFlavor(t *testing.T) {
	t.Parallel()

	c := newInfrastructureRefTestClient(t, types.FlavorList{{ID: validationFlavorID, PinnedOnly: true}})

	err := c.validateInfrastructureRefForFlavor(t.Context(), "region", idstest.MustParseFlavorID(validationFlavorID), nil)
	require.Error(t, err)
	require.ErrorContains(t, err, "requires infrastructureRef")
}

// TestValidateInfrastructureRefForFlavorAcceptsUnpinnedFlavor pins the
// existing behaviour that an offered, unpinned flavor needs no ref.
func TestValidateInfrastructureRefForFlavorAcceptsUnpinnedFlavor(t *testing.T) {
	t.Parallel()

	c := newInfrastructureRefTestClient(t, types.FlavorList{{ID: validationFlavorID}})

	err := c.validateInfrastructureRefForFlavor(t.Context(), "region", idstest.MustParseFlavorID(validationFlavorID), nil)
	require.NoError(t, err)
}
