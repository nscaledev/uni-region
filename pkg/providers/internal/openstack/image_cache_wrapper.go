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

package openstack

import (
	"maps"
	"reflect"
	"slices"
	"sync"
	"time"
	"unsafe"

	"github.com/unikorn-cloud/core/pkg/util/cache"
	"github.com/unikorn-cloud/region/pkg/providers/types"
)

const (
	// imageStatusPendingDelete is an internal-only bridge status used by the temporary
	// image cache wrapper.
	//
	// We intentionally do not add this as a first-class public provider status in
	// pkg/providers/types for this release.  The wrapper exists purely to bridge a gap
	// between "the write to OpenStack succeeded" and "the next successful full Glance
	// relist completed".  Once the underlying cache grows native insert/update support,
	// this temporary wrapper should be deleted and this internal-only sentinel should
	// disappear with it.
	imageStatusPendingDelete = types.ImageStatus("pending_delete")
)

// imageCacheBase is the narrow portion of RefreshAheadCache that the temporary wrapper
// depends on.
//
// This interface is intentionally shaped as a small adapter boundary rather than
// reaching directly into RefreshAheadCache internals.  The plan is to replace this
// wrapper with native cache Insert/Update operations later.  Keeping the dependency
// narrow makes that future swap much easier.
type imageCacheBase interface {
	Get(index string) (*cache.GetSnapshot[types.Image], error)
	List() (*cache.ListSnapshot[types.Image], error)
}

// imageCacheWrapper is a temporary bridge over RefreshAheadCache.
//
// Constraint summary:
//  1. OpenStack create/snapshot/delete can succeed even when an immediate full image
//     relist fails or times out.
//  2. The Region API contract still requires the cache-backed read path to reflect the
//     successful write immediately.
//  3. We do not want provider.go to grow ad-hoc overlay maps that would be hard to
//     remove once the shared cache gains real Insert/Update support.
//  4. We therefore keep all temporary "bridge until next refresh" behavior in this
//     disposable wrapper file.
//
// Semantics:
//   - InsertIfAbsent: bridge a successful create/snapshot until the next successful base
//     cache epoch is observed.
//   - Update: bridge a successful delete by publishing an updated image view (currently
//     with internal pending_delete status) until the next successful base cache epoch is
//     observed.
//   - Any local bridge state is discarded on the first observed underlying cache epoch
//     change.  This is deliberate.  The wrapper is only covering the gap until the next
//     successful base refresh, not trying to outsmart Glance indefinitely.
//   - Local bridge mutations must also advance the observable epoch seen by callers.
//     The cache package currently uses an opaque, timestamp-backed epoch with no public
//     constructor, so we mint a replacement epoch locally via a tiny isolated helper
//     below.  This is explicitly temporary and should be removed once the shared cache
//     exposes the necessary primitives.
type imageCacheWrapper struct {
	base imageCacheBase

	lock sync.Mutex

	// baseEpochSeen tracks whether we've observed at least one underlying cache epoch.
	baseEpochSeen bool
	// baseEpoch is the most recent underlying cache epoch we have incorporated.
	baseEpoch cache.Epoch
	// effectiveEpoch is the epoch returned to callers for the merged view.  It matches
	// the base epoch when there is no local bridge state, and is advanced locally when
	// a temporary insert/update is applied.
	effectiveEpoch cache.Epoch
	// overlay is the temporary write-through bridge state keyed by image ID.
	overlay map[string]*types.Image
}

func newImageCacheWrapper(base imageCacheBase) *imageCacheWrapper {
	return &imageCacheWrapper{
		base:    base,
		overlay: map[string]*types.Image{},
	}
}

// newCacheEpoch mints a cache.Epoch for the temporary wrapper's effective view.
//
// This is intentionally isolated in one place because it relies on reflect/unsafe to
// populate cache.Epoch's private time field.  That is not something we want spread
// through provider code.  The shared cache package currently exposes Epoch as an opaque
// type with equality-based semantics but no constructor.  The wrapper still needs to
// advance the observable epoch when a local bridge insert/update changes the effective
// image view before the base cache epoch changes.
//
// When the underlying cache grows Insert/Update support, this helper and the whole
// wrapper should be deleted.
func newCacheEpoch(t time.Time) cache.Epoch {
	var epoch cache.Epoch

	value := reflect.ValueOf(&epoch).Elem().FieldByName("epoch")
	reflect.NewAt(value.Type(), unsafe.Pointer(value.UnsafeAddr())).Elem().Set(reflect.ValueOf(t))

	return epoch
}

func cloneProviderImage(image *types.Image) *types.Image {
	if image == nil {
		return nil
	}

	clone := *image
	clone.Tags = maps.Clone(image.Tags)

	if image.OrganizationID != nil {
		organizationID := *image.OrganizationID
		clone.OrganizationID = &organizationID
	}

	if image.Packages != nil {
		packages := maps.Clone(*image.Packages)
		clone.Packages = &packages
	}

	if image.GPU != nil {
		gpu := *image.GPU
		gpu.Models = slices.Clone(image.GPU.Models)
		clone.GPU = &gpu
	}

	if image.OS.Variant != nil {
		variant := *image.OS.Variant
		clone.OS.Variant = &variant
	}

	if image.OS.Codename != nil {
		codename := *image.OS.Codename
		clone.OS.Codename = &codename
	}

	return &clone
}

// reconcileBaseEpochLocked clears all temporary bridge state when the underlying cache
// epoch changes.
//
// This is the intentionally simplified lifecycle we agreed on:
//   - the wrapper only bridges from a successful write to the next successful base refresh
//   - once a new base epoch is observed, the wrapper trusts the refreshed cache as the
//     source of truth again and discards all local bridge entries
//
// Because the base cache epoch is opaque and equality-based, we use Epoch.Valid as the
// change detector rather than trying to inspect timestamps.
func (w *imageCacheWrapper) reconcileBaseEpochLocked(baseEpoch cache.Epoch) {
	if !w.baseEpochSeen || !baseEpoch.Valid(w.baseEpoch) {
		clear(w.overlay)
		w.baseEpochSeen = true
		w.baseEpoch = baseEpoch
		w.effectiveEpoch = baseEpoch
	}
}

func (w *imageCacheWrapper) bumpEffectiveEpochLocked() {
	w.effectiveEpoch = newCacheEpoch(time.Now())
}

func (w *imageCacheWrapper) mergeListLocked(base *cache.ListSnapshot[types.Image]) []*types.Image {
	items := make([]*types.Image, 0, len(base.Items)+len(w.overlay))
	seen := make(map[string]struct{}, len(base.Items)+len(w.overlay))

	for _, item := range base.Items {
		if overlay, ok := w.overlay[item.ID]; ok {
			items = append(items, cloneProviderImage(overlay))
			seen[item.ID] = struct{}{}

			continue
		}

		items = append(items, item)
		seen[item.ID] = struct{}{}
	}

	for imageID, item := range w.overlay {
		if _, ok := seen[imageID]; ok {
			continue
		}

		items = append(items, cloneProviderImage(item))
	}

	return items
}

func (w *imageCacheWrapper) List() (*cache.ListSnapshot[types.Image], error) {
	base, err := w.base.List()
	if err != nil {
		return nil, err
	}

	w.lock.Lock()
	defer w.lock.Unlock()

	w.reconcileBaseEpochLocked(base.Epoch)

	return &cache.ListSnapshot[types.Image]{
		Epoch: w.effectiveEpoch,
		Items: w.mergeListLocked(base),
	}, nil
}

func (w *imageCacheWrapper) Get(imageID string) (*cache.GetSnapshot[types.Image], error) {
	// We intentionally use List here rather than base.Get because the wrapper's cleanup
	// semantics are keyed off observing the underlying cache epoch.  List gives us both
	// the current epoch and the current base contents in one call, keeping the wrapper's
	// behavior deterministic.
	base, err := w.base.List()
	if err != nil {
		return nil, err
	}

	w.lock.Lock()
	defer w.lock.Unlock()

	w.reconcileBaseEpochLocked(base.Epoch)

	if overlay, ok := w.overlay[imageID]; ok {
		return &cache.GetSnapshot[types.Image]{
			Epoch: w.effectiveEpoch,
			Item:  cloneProviderImage(overlay),
		}, nil
	}

	for _, item := range base.Items {
		if item.ID == imageID {
			return &cache.GetSnapshot[types.Image]{
				Epoch: w.effectiveEpoch,
				Item:  item,
			}, nil
		}
	}

	return nil, cache.ErrNotFound
}

func (w *imageCacheWrapper) InsertIfAbsent(image *types.Image) error {
	base, err := w.base.List()
	if err != nil {
		return err
	}

	w.lock.Lock()
	defer w.lock.Unlock()

	w.reconcileBaseEpochLocked(base.Epoch)

	if _, ok := w.overlay[image.ID]; ok {
		return nil
	}

	for _, item := range base.Items {
		if item.ID == image.ID {
			return nil
		}
	}

	w.overlay[image.ID] = cloneProviderImage(image)
	w.bumpEffectiveEpochLocked()

	return nil
}

func (w *imageCacheWrapper) Update(image *types.Image) error {
	base, err := w.base.List()
	if err != nil {
		return err
	}

	w.lock.Lock()
	defer w.lock.Unlock()

	w.reconcileBaseEpochLocked(base.Epoch)
	w.overlay[image.ID] = cloneProviderImage(image)
	w.bumpEffectiveEpochLocked()

	return nil
}
