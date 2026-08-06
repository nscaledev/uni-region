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

package openstack_test

import (
	"errors"
	"math"
	"strconv"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/volumes"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack/mock"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/apimachinery/pkg/api/resource"
)

var errVolumeObservationProvider = errors.New("cinder unavailable")

func observedCinderVolume(identity *regionv1.Identity, volume *regionv1.Volume, status string, size int) *volumes.Volume {
	return &volumes.Volume{
		ID:     "provider-volume-id",
		Name:   "volume-" + volume.Name,
		Status: status,
		Size:   size,
		Metadata: map[string]string{
			"region:volume_id":         volume.Name,
			"identity:organization_id": organizationID,
			"identity:project_id":      projectID,
			"region:region_id":         regionID,
			"region:network_id":        volume.Spec.NetworkID,
			"region:identity_id":       identity.Name,
		},
	}
}

func TestObserveVolumeReturnsProviderNeutralResult(t *testing.T) {
	t.Parallel()

	identity, volume := identityFixture(), volumeFixture()
	c := gomock.NewController(t)
	blockStorage := mock.NewMockVolumeInterface(c)
	blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(observedCinderVolume(identity, volume, "available", 20), nil)

	got, err := openstack.ObserveVolumeWithClient(t.Context(), blockStorage, identity, volume)
	require.NoError(t, err)
	require.Equal(t, types.VolumeStatusAvailable, got.Status)
}

func TestObserveVolumeMapsCinderStatuses(t *testing.T) {
	t.Parallel()

	cases := map[string]types.VolumeStatus{
		"creating":            types.VolumeStatusCreating,
		"available":           types.VolumeStatusAvailable,
		"reserved":            types.VolumeStatusAttaching,
		"attaching":           types.VolumeStatusAttaching,
		"in-use":              types.VolumeStatusAttached,
		"detaching":           types.VolumeStatusDetaching,
		"deleting":            types.VolumeStatusDeleting,
		"managing":            types.VolumeStatusUpdating,
		"maintenance":         types.VolumeStatusUpdating,
		"restoring-backup":    types.VolumeStatusUpdating,
		"awaiting-transfer":   types.VolumeStatusUpdating,
		"backing-up":          types.VolumeStatusUpdating,
		"downloading":         types.VolumeStatusUpdating,
		"uploading":           types.VolumeStatusUpdating,
		"retyping":            types.VolumeStatusUpdating,
		"extending":           types.VolumeStatusUpdating,
		"error":               types.VolumeStatusError,
		"error_deleting":      types.VolumeStatusError,
		"error_managing":      types.VolumeStatusError,
		"error_restoring":     types.VolumeStatusError,
		"error_backing-up":    types.VolumeStatusError,
		"error_extending":     types.VolumeStatusError,
		"":                    types.VolumeStatusUnknown,
		"future-cinder-state": types.VolumeStatusUnknown,
	}

	for cinderStatus, want := range cases {
		name := cinderStatus
		if name == "" {
			name = "unknown-empty"
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			identity, volume := identityFixture(), volumeFixture()
			c := gomock.NewController(t)
			blockStorage := mock.NewMockVolumeInterface(c)
			blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(observedCinderVolume(identity, volume, cinderStatus, 20), nil)

			got, err := openstack.ObserveVolumeWithClient(t.Context(), blockStorage, identity, volume)
			require.NoError(t, err)
			require.Equal(t, want, got.Status)
		})
	}
}

func TestObserveVolumeReturnsResourceNotFound(t *testing.T) {
	t.Parallel()

	identity, volume := identityFixture(), volumeFixture()
	c := gomock.NewController(t)
	blockStorage := mock.NewMockVolumeInterface(c)
	blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(nil, coreerrors.ErrResourceNotFound)

	got, err := openstack.ObserveVolumeWithClient(t.Context(), blockStorage, identity, volume)
	require.Nil(t, got)
	require.ErrorIs(t, err, coreerrors.ErrResourceNotFound)
}

func TestObserveVolumePreservesProviderError(t *testing.T) {
	t.Parallel()

	identity, volume := identityFixture(), volumeFixture()
	c := gomock.NewController(t)
	blockStorage := mock.NewMockVolumeInterface(c)
	blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(nil, errVolumeObservationProvider)

	got, err := openstack.ObserveVolumeWithClient(t.Context(), blockStorage, identity, volume)
	require.Nil(t, got)
	require.ErrorIs(t, err, errVolumeObservationProvider)
}

func TestObserveVolumeConvertsObservedSize(t *testing.T) {
	t.Parallel()

	identity, volume := identityFixture(), volumeFixture()
	c := gomock.NewController(t)
	blockStorage := mock.NewMockVolumeInterface(c)
	blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(observedCinderVolume(identity, volume, "available", 37), nil)

	got, err := openstack.ObserveVolumeWithClient(t.Context(), blockStorage, identity, volume)
	require.NoError(t, err)
	require.Zero(t, got.Size.Cmp(resource.MustParse("37Gi")))
}

func TestObserveVolumeConvertsMaxRepresentableSize(t *testing.T) {
	t.Parallel()

	if strconv.IntSize < 64 {
		t.Skip("Cinder's int size cannot represent the largest safe GiB value on this architecture")
	}

	maxSizeGiB := int64(math.MaxInt64 >> 30)
	identity, volume := identityFixture(), volumeFixture()
	c := gomock.NewController(t)
	blockStorage := mock.NewMockVolumeInterface(c)
	blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(observedCinderVolume(identity, volume, "available", int(maxSizeGiB)), nil)

	got, err := openstack.ObserveVolumeWithClient(t.Context(), blockStorage, identity, volume)
	require.NoError(t, err)
	require.Zero(t, got.Size.Cmp(resource.MustParse("8589934591Gi")))
}

func TestObserveVolumeRejectsNegativeSize(t *testing.T) {
	t.Parallel()

	identity, volume := identityFixture(), volumeFixture()
	c := gomock.NewController(t)
	blockStorage := mock.NewMockVolumeInterface(c)
	blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(observedCinderVolume(identity, volume, "available", -1), nil)

	got, err := openstack.ObserveVolumeWithClient(t.Context(), blockStorage, identity, volume)
	require.Nil(t, got)
	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}

func TestObserveVolumeRejectsOverflowSize(t *testing.T) {
	t.Parallel()

	if strconv.IntSize < 64 {
		t.Skip("Cinder's int size cannot exceed the largest safe GiB value on this architecture")
	}

	maxSizeGiB := int64(math.MaxInt64 >> 30)
	identity, volume := identityFixture(), volumeFixture()
	c := gomock.NewController(t)
	blockStorage := mock.NewMockVolumeInterface(c)
	blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(observedCinderVolume(identity, volume, "available", int(maxSizeGiB+1)), nil)

	got, err := openstack.ObserveVolumeWithClient(t.Context(), blockStorage, identity, volume)
	require.Nil(t, got)
	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}

func TestObserveVolumeRejectsInvalidMetadata(t *testing.T) {
	t.Parallel()

	keys := map[string]string{
		"volume ID":       "region:volume_id",
		"organization ID": "identity:organization_id",
		"project ID":      "identity:project_id",
		"region ID":       "region:region_id",
		"network ID":      "region:network_id",
		"identity ID":     "region:identity_id",
	}

	for name, key := range keys {
		for _, mutation := range []string{"missing", "conflicting"} {
			t.Run(mutation+" "+name, func(t *testing.T) {
				t.Parallel()

				identity, volume := identityFixture(), volumeFixture()
				cinderVolume := observedCinderVolume(identity, volume, "available", 20)

				if mutation == "missing" {
					delete(cinderVolume.Metadata, key)
				} else {
					cinderVolume.Metadata[key] = "other-resource"
				}

				c := gomock.NewController(t)
				blockStorage := mock.NewMockVolumeInterface(c)
				blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(cinderVolume, nil)

				got, err := openstack.ObserveVolumeWithClient(t.Context(), blockStorage, identity, volume)
				require.Nil(t, got)
				require.ErrorIs(t, err, coreerrors.ErrConsistency)
			})
		}
	}

	t.Run("nil metadata", func(t *testing.T) {
		t.Parallel()

		identity, volume := identityFixture(), volumeFixture()
		cinderVolume := observedCinderVolume(identity, volume, "available", 20)
		cinderVolume.Metadata = nil
		c := gomock.NewController(t)
		blockStorage := mock.NewMockVolumeInterface(c)
		blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(cinderVolume, nil)

		got, err := openstack.ObserveVolumeWithClient(t.Context(), blockStorage, identity, volume)
		require.Nil(t, got)
		require.ErrorIs(t, err, coreerrors.ErrConsistency)
	})
}

func TestObserveVolumeRejectsEmptyExpectedMetadata(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		key   string
		clear func(*regionv1.Identity, *regionv1.Volume)
	}{
		"volume ID": {
			key: "region:volume_id",
			clear: func(_ *regionv1.Identity, volume *regionv1.Volume) {
				volume.Name = ""
			},
		},
		"organization ID": {
			key: "identity:organization_id",
			clear: func(_ *regionv1.Identity, volume *regionv1.Volume) {
				volume.Labels[coreconstants.OrganizationLabel] = ""
			},
		},
		"project ID": {
			key: "identity:project_id",
			clear: func(_ *regionv1.Identity, volume *regionv1.Volume) {
				volume.Labels[coreconstants.ProjectLabel] = ""
			},
		},
		"region ID": {
			key: "region:region_id",
			clear: func(_ *regionv1.Identity, volume *regionv1.Volume) {
				volume.Labels[constants.RegionLabel] = ""
			},
		},
		"network ID": {
			key: "region:network_id",
			clear: func(_ *regionv1.Identity, volume *regionv1.Volume) {
				volume.Spec.NetworkID = ""
			},
		},
		"identity ID": {
			key: "region:identity_id",
			clear: func(identity *regionv1.Identity, _ *regionv1.Volume) {
				identity.Name = ""
			},
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			identity, volume := identityFixture(), volumeFixture()
			testCase.clear(identity, volume)
			cinderVolume := observedCinderVolume(identity, volume, "available", 20)
			cinderVolume.Metadata[testCase.key] = ""
			c := gomock.NewController(t)
			blockStorage := mock.NewMockVolumeInterface(c)
			blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(cinderVolume, nil)

			got, err := openstack.ObserveVolumeWithClient(t.Context(), blockStorage, identity, volume)
			require.Nil(t, got)
			require.ErrorIs(t, err, coreerrors.ErrConsistency)
		})
	}
}

func TestObserveVolumeRejectsNilResult(t *testing.T) {
	t.Parallel()

	identity, volume := identityFixture(), volumeFixture()
	c := gomock.NewController(t)
	blockStorage := mock.NewMockVolumeInterface(c)
	blockStorage.EXPECT().GetVolume(t.Context(), volume).Return(nil, nil)

	got, err := openstack.ObserveVolumeWithClient(t.Context(), blockStorage, identity, volume)
	require.Nil(t, got)
	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}
