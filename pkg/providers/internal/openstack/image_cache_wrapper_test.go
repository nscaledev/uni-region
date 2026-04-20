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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/util/cache"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
	"github.com/unikorn-cloud/region/pkg/providers/types"
)

type fakeImageCacheBase struct {
	snapshot *cache.ListSnapshot[types.Image]
}

func (f *fakeImageCacheBase) Get(index string) (*cache.GetSnapshot[types.Image], error) {
	for _, item := range f.snapshot.Items {
		if item.ID == index {
			return &cache.GetSnapshot[types.Image]{
				Epoch: f.snapshot.Epoch,
				Item:  item,
			}, nil
		}
	}

	return nil, cache.ErrNotFound
}

func (f *fakeImageCacheBase) List() (*cache.ListSnapshot[types.Image], error) {
	return f.snapshot, nil
}

func imageForWrapperTest(id string, created time.Time, status types.ImageStatus) *types.Image {
	return &types.Image{
		ID:      id,
		Name:    id,
		Created: created,
		Status:  status,
		OS: types.ImageOS{
			Kernel:  types.Linux,
			Family:  types.Debian,
			Distro:  types.Ubuntu,
			Version: "24.04",
		},
	}
}

func imageIDs(items []*types.Image) []string {
	result := make([]string, len(items))

	for i := range items {
		result[i] = items[i].ID
	}

	return result
}

func TestImageCacheWrapperInsertIfAbsentBridgesUntilBaseEpochChanges(t *testing.T) {
	t.Parallel()

	now := time.Now()
	baseEpoch := openstack.NewCacheEpoch(now)
	nextEpoch := openstack.NewCacheEpoch(now.Add(time.Second))

	base := &fakeImageCacheBase{
		snapshot: &cache.ListSnapshot[types.Image]{
			Epoch: baseEpoch,
			Items: []*types.Image{
				imageForWrapperTest("base", now, types.ImageStatusReady),
			},
		},
	}

	wrapper := openstack.NewImageCacheWrapper(base)

	inserted := imageForWrapperTest("inserted", now.Add(time.Minute), types.ImageStatusCreating)
	require.NoError(t, wrapper.InsertIfAbsent(inserted))

	bridged, err := wrapper.List()
	require.NoError(t, err)
	require.False(t, bridged.Epoch.Valid(baseEpoch))
	require.Equal(t, []string{"base", "inserted"}, imageIDs(bridged.Items))

	base.snapshot = &cache.ListSnapshot[types.Image]{
		Epoch: nextEpoch,
		Items: []*types.Image{
			imageForWrapperTest("base", now, types.ImageStatusReady),
			imageForWrapperTest("inserted", now.Add(time.Minute), types.ImageStatusReady),
		},
	}

	refreshed, err := wrapper.List()
	require.NoError(t, err)
	require.True(t, refreshed.Epoch.Valid(nextEpoch))
	require.Equal(t, []string{"base", "inserted"}, imageIDs(refreshed.Items))
	require.Equal(t, types.ImageStatusReady, refreshed.Items[1].Status)
}

func TestImageCacheWrapperUpdateBridgesUntilBaseEpochChanges(t *testing.T) {
	t.Parallel()

	now := time.Now()
	baseEpoch := openstack.NewCacheEpoch(now)
	nextEpoch := openstack.NewCacheEpoch(now.Add(time.Second))

	base := &fakeImageCacheBase{
		snapshot: &cache.ListSnapshot[types.Image]{
			Epoch: baseEpoch,
			Items: []*types.Image{
				imageForWrapperTest("image", now, types.ImageStatusReady),
			},
		},
	}

	wrapper := openstack.NewImageCacheWrapper(base)

	deleting := imageForWrapperTest("image", now, openstack.ImageStatusPendingDelete)
	require.NoError(t, wrapper.Update(deleting))

	bridged, err := wrapper.Get("image")
	require.NoError(t, err)
	require.False(t, bridged.Epoch.Valid(baseEpoch))
	require.Equal(t, openstack.ImageStatusPendingDelete, bridged.Item.Status)

	base.snapshot = &cache.ListSnapshot[types.Image]{
		Epoch: nextEpoch,
		Items: []*types.Image{
			imageForWrapperTest("image", now, openstack.ImageStatusPendingDelete),
		},
	}

	refreshed, err := wrapper.Get("image")
	require.NoError(t, err)
	require.True(t, refreshed.Epoch.Valid(nextEpoch))
	require.Equal(t, openstack.ImageStatusPendingDelete, refreshed.Item.Status)
}

func TestImageCacheWrapperInsertIfAbsentDoesNotOverwriteBaseData(t *testing.T) {
	t.Parallel()

	now := time.Now()
	baseEpoch := openstack.NewCacheEpoch(now)

	base := &fakeImageCacheBase{
		snapshot: &cache.ListSnapshot[types.Image]{
			Epoch: baseEpoch,
			Items: []*types.Image{
				imageForWrapperTest("image", now, types.ImageStatusReady),
			},
		},
	}

	wrapper := openstack.NewImageCacheWrapper(base)

	require.NoError(t, wrapper.InsertIfAbsent(imageForWrapperTest("image", now, types.ImageStatusCreating)))

	got, err := wrapper.Get("image")
	require.NoError(t, err)
	require.True(t, got.Epoch.Valid(baseEpoch))
	require.Equal(t, types.ImageStatusReady, got.Item.Status)
}
