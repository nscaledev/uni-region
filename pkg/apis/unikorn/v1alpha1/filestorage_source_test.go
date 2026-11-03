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

package v1alpha1_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

const (
	sourceSnapshotID      = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	otherSourceSnapshotID = "6ba7b811-9dad-11d1-80b4-00c04fd430c8"
)

func TestFileStorageSourceSchema(t *testing.T) {
	t.Parallel()

	spec := requireSchemaProperty(t, crdSchema(t, fileStorageCRDFile), "spec")
	require.NotContains(t, spec.Required, "source")

	source := requireSchemaProperty(t, spec, "source")
	require.Equal(t, "object", source.Type)
	require.NotContains(t, source.Required, "snapshot")

	id := requireSchemaProperty(t, source, "snapshot", "id")
	require.Equal(t, "string", id.Type)
	require.Contains(t, requireSchemaProperty(t, source, "snapshot").Required, "id")
}

func TestFileStorageSourceRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		spec regionv1.FileStorageSpec
		want *regionv1.FileStorageSource
	}{
		{
			name: "omitted source starts empty",
			spec: regionv1.FileStorageSpec{StorageClassID: "storage-class"},
		},
		{
			name: "snapshot source",
			spec: regionv1.FileStorageSpec{
				StorageClassID: "storage-class",
				Source: &regionv1.FileStorageSource{
					Snapshot: &regionv1.FileStorageSnapshotSource{ID: sourceSnapshotID},
				},
			},
			want: &regionv1.FileStorageSource{
				Snapshot: &regionv1.FileStorageSnapshotSource{ID: sourceSnapshotID},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			data, err := json.Marshal(tc.spec)
			require.NoError(t, err)

			var raw map[string]any

			require.NoError(t, json.Unmarshal(data, &raw))

			if tc.want == nil {
				require.NotContains(t, raw, "source")
			}

			var roundTripped regionv1.FileStorageSpec

			require.NoError(t, json.Unmarshal(data, &roundTripped))
			require.Equal(t, tc.want, roundTripped.Source)
		})
	}
}

func TestFileStorageSourceDeepCopy(t *testing.T) {
	t.Parallel()

	original := &regionv1.FileStorageSpec{
		Source: &regionv1.FileStorageSource{
			Snapshot: &regionv1.FileStorageSnapshotSource{ID: sourceSnapshotID},
		},
	}

	copied := original.DeepCopy()
	require.Equal(t, original.Source, copied.Source)
	require.NotSame(t, original.Source, copied.Source)
	require.NotSame(t, original.Source.Snapshot, copied.Source.Snapshot)

	copied.Source.Snapshot.ID = otherSourceSnapshotID

	require.Equal(t, sourceSnapshotID, original.Source.Snapshot.ID)
}

func TestFileStorageSourceCreateValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		source map[string]any
		valid  bool
	}{
		{name: "omitted source", valid: true},
		{name: "snapshot source", source: snapshotSource(sourceSnapshotID), valid: true},
		{name: "empty source", source: map[string]any{}},
		{name: "snapshot without id", source: map[string]any{"snapshot": map[string]any{}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			valid := newCRDValidator(t, fileStorageCRDFile).validatesUnstructured(t, fileStorageWithSource(tc.source))
			require.Equal(t, tc.valid, valid)
		})
	}
}

func TestFileStorageSourceIsImmutable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		original map[string]any
		updated  map[string]any
		valid    bool
	}{
		{name: "unchanged snapshot source", original: snapshotSource(sourceSnapshotID), updated: snapshotSource(sourceSnapshotID), valid: true},
		{name: "unchanged omitted source", valid: true},
		{name: "changed snapshot id", original: snapshotSource(sourceSnapshotID), updated: snapshotSource(otherSourceSnapshotID)},
		{name: "source added", updated: snapshotSource(sourceSnapshotID)},
		{name: "source removed", original: snapshotSource(sourceSnapshotID)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			validator := newCRDValidator(t, fileStorageCRDFile)
			valid := validator.validatesUpdateUnstructured(t, fileStorageWithSource(tc.updated), fileStorageWithSource(tc.original))
			require.Equal(t, tc.valid, valid)
		})
	}
}

func snapshotSource(id string) map[string]any {
	return map[string]any{
		"snapshot": map[string]any{"id": id},
	}
}

func fileStorageWithSource(source map[string]any) map[string]any {
	spec := map[string]any{
		"storageClassID": "storage-class",
		"size":           "1Gi",
	}

	if source != nil {
		spec["source"] = source
	}

	return map[string]any{
		"apiVersion": "region.unikorn-cloud.org/v1alpha1",
		"kind":       "FileStorage",
		"metadata": map[string]any{
			"name":      "storage",
			"namespace": "default",
		},
		"spec": spec,
	}
}
