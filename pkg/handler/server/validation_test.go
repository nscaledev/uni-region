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
	"github.com/unikorn-cloud/region/pkg/providers/types"
	providermock "github.com/unikorn-cloud/region/pkg/providers/types/mock"

	"k8s.io/apimachinery/pkg/api/resource"
)

func readyImage() *types.Image {
	return &types.Image{
		ID:             "image-1",
		Status:         types.ImageStatusReady,
		SizeGiB:        20,
		Virtualization: types.Any,
	}
}

func flavorList() types.FlavorList {
	return types.FlavorList{
		{ID: "flavor-1", Disk: resource.NewScaledQuantity(40, resource.Giga), Baremetal: false},
	}
}

func TestValidateServerImage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		image   *types.Image
		flavors types.FlavorList
		imageID string
		flavor  string
		wantErr bool
	}{
		{
			name:    "valid",
			image:   readyImage(),
			flavors: flavorList(),
			imageID: "image-1",
			flavor:  "flavor-1",
			wantErr: false,
		},
		{
			name:    "image not ready",
			image:   &types.Image{ID: "image-1", Status: types.ImageStatusPending, SizeGiB: 20, Virtualization: types.Any},
			flavors: flavorList(),
			imageID: "image-1",
			flavor:  "flavor-1",
			wantErr: true,
		},
		{
			name:    "flavor not found",
			image:   readyImage(),
			flavors: flavorList(),
			imageID: "image-1",
			flavor:  "missing",
			wantErr: true,
		},
		{
			name:    "flavor disk too small",
			image:   &types.Image{ID: "image-1", Status: types.ImageStatusReady, SizeGiB: 80, Virtualization: types.Any},
			flavors: flavorList(),
			imageID: "image-1",
			flavor:  "flavor-1",
			wantErr: true,
		},
		{
			name:    "virtualization incompatible",
			image:   &types.Image{ID: "image-1", Status: types.ImageStatusReady, SizeGiB: 20, Virtualization: types.Baremetal},
			flavors: flavorList(),
			imageID: "image-1",
			flavor:  "flavor-1",
			wantErr: true,
		},
		{
			name:    "architecture mismatch",
			image:   &types.Image{ID: "image-1", Status: types.ImageStatusReady, SizeGiB: 20, Virtualization: types.Any, Architecture: types.Aarch64},
			flavors: types.FlavorList{{ID: "flavor-1", Disk: resource.NewScaledQuantity(40, resource.Giga), Architecture: types.X86_64}},
			imageID: "image-1",
			flavor:  "flavor-1",
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			provider := providermock.NewMockProvider(ctrl)

			provider.EXPECT().GetImage(gomock.Any(), "org-1", test.imageID).Return(test.image, nil)
			provider.EXPECT().Flavors(gomock.Any()).Return(test.flavors, nil).AnyTimes()

			err := validateServerImage(t.Context(), provider, "org-1", test.imageID, test.flavor)

			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateServerImageImageNotFound(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	provider := providermock.NewMockProvider(ctrl)

	provider.EXPECT().GetImage(gomock.Any(), "org-1", "missing").Return(nil, coreerrors.ErrResourceNotFound)

	err := validateServerImage(t.Context(), provider, "org-1", "missing", "flavor-1")

	require.Error(t, err)
}
