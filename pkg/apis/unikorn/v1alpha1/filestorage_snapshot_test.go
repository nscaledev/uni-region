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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	"k8s.io/utils/ptr"
)

const (
	snapshotFileStorageID  = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	snapshotOrganizationID = "d47ac10b-58cc-4372-a567-0e02b2c3d479"
	snapshotProjectID      = "e47ac10b-58cc-4372-a567-0e02b2c3d479"
)

func TestFileStorageSnapshotSchema(t *testing.T) {
	t.Parallel()

	schema := crdSchema(t, fileStorageSnapshotCRDFile)

	fileStorageID := requireSchemaProperty(t, schema, "spec", "fileStorageID")
	require.Equal(t, "string", fileStorageID.Type)
	require.Equal(t, "uuid", fileStorageID.Format)
	require.Contains(t, requireSchemaProperty(t, schema, "spec").Required, "fileStorageID")
	require.Contains(t, requireSchemaProperty(t, schema, "spec").Required, "name")
	require.Equal(t, "boolean", requireSchemaProperty(t, schema, "spec", "pause").Type)

	timeFields := [][]string{
		{"spec", "expirationTime"},
		{"status", "snapshotTime"},
		{"status", "backendObservedAt"},
	}

	for _, path := range timeFields {
		property := requireSchemaProperty(t, schema, path...)
		require.Equal(t, "string", property.Type)
		require.Equal(t, "date-time", property.Format)
	}

	require.Equal(t, "string", requireSchemaProperty(t, schema, "spec", "protectedPath").Type)
	require.Equal(t, "string", requireSchemaProperty(t, schema, "status", "absoluteProtectedPath").Type)
	require.Equal(t, "array", requireSchemaProperty(t, schema, "status", "conditions").Type)
}

func TestFileStorageSnapshotManagedResourceHelpers(t *testing.T) {
	t.Parallel()

	snapshot := &regionv1.FileStorageSnapshot{}

	require.False(t, snapshot.Paused())

	snapshot.Spec.Pause = true
	require.True(t, snapshot.Paused())
}

func TestFileStorageSnapshotProjectScope(t *testing.T) {
	t.Parallel()

	snapshot := &regionv1.FileStorageSnapshot{}
	snapshot.Labels = map[string]string{
		coreconstants.OrganizationLabel: snapshotOrganizationID,
		coreconstants.ProjectLabel:      snapshotProjectID,
	}

	organizationID, err := snapshot.OrganizationID()
	require.NoError(t, err)
	require.Equal(t, snapshotOrganizationID, organizationID.String())

	organizationID, projectID, err := snapshot.OrganizationAndProjectID()
	require.NoError(t, err)
	require.Equal(t, snapshotOrganizationID, organizationID.String())
	require.Equal(t, snapshotProjectID, projectID.String())

	snapshot.Labels[coreconstants.ProjectLabel] = "not-a-uuid"
	_, _, err = snapshot.OrganizationAndProjectID()
	require.Error(t, err)
}

func TestFileStorageSnapshotProtectedPathValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		protectedPath *string
		valid         bool
	}{
		{name: "omitted path selects the root", valid: true},
		{name: "relative path", protectedPath: ptr.To("applications/data"), valid: true},
		{name: "dots within a component", protectedPath: ptr.To("releases/v1.2"), valid: true},
		{name: "path of exactly 1024 characters", protectedPath: ptr.To(strings.Repeat("a", 1024)), valid: true},
		{name: "empty path", protectedPath: ptr.To("")},
		{name: "absolute path", protectedPath: ptr.To("/applications/data")},
		{name: "trailing slash", protectedPath: ptr.To("applications/data/")},
		{name: "doubled slash", protectedPath: ptr.To("applications//data")},
		{name: "current-directory component", protectedPath: ptr.To("applications/./data")},
		{name: "parent-directory component", protectedPath: ptr.To("applications/../data")},
		{name: "path over 1024 characters", protectedPath: ptr.To(strings.Repeat("a", 1025))},
	}

	validator := newCRDValidator(t, fileStorageSnapshotCRDFile)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.valid, validator.validatesUnstructured(t, fileStorageSnapshot(tc.protectedPath)))
		})
	}
}

func TestFileStorageSnapshotNameValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		snapshotName string
		valid        bool
	}{
		{name: "mixed case and dots", snapshotName: "Daily.Backup_01", valid: true},
		{name: "single dot", snapshotName: "."},
		{name: "double dot", snapshotName: ".."},
		{name: "leading punctuation", snapshotName: "-backup"},
		{name: "trailing punctuation", snapshotName: "backup_"},
		{name: "too long", snapshotName: strings.Repeat("a", 64)},
	}

	validator := newCRDValidator(t, fileStorageSnapshotCRDFile)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			snapshot := fileStorageSnapshot(nil)
			spec, ok := snapshot["spec"].(map[string]any)
			require.True(t, ok)

			spec["name"] = tc.snapshotName

			require.Equal(t, tc.valid, validator.validatesUnstructured(t, snapshot))
		})
	}
}

func TestFileStorageSnapshotIntentIsImmutable(t *testing.T) {
	t.Parallel()

	validator := newCRDValidator(t, fileStorageSnapshotCRDFile)
	original := fileStorageSnapshot(ptr.To("applications/data"))
	updatedTags := fileStorageSnapshot(ptr.To("applications/data"))
	spec, ok := updatedTags["spec"].(map[string]any)
	require.True(t, ok)

	spec["tags"] = []any{
		map[string]any{"name": "retention", "value": "extended"},
	}
	updatedPause := fileStorageSnapshot(ptr.To("applications/data"))
	pauseSpec, ok := updatedPause["spec"].(map[string]any)
	require.True(t, ok)

	pauseSpec["pause"] = true

	require.True(t, validator.validatesUpdateUnstructured(t, fileStorageSnapshot(ptr.To("applications/data")), original))
	require.True(t, validator.validatesUpdateUnstructured(t, updatedTags, original))
	require.True(t, validator.validatesUpdateUnstructured(t, updatedPause, original))

	cases := []struct {
		name   string
		mutate func(*testing.T, map[string]any)
	}{
		{
			name: "Manual Snapshot Name",
			mutate: func(t *testing.T, snapshot map[string]any) {
				t.Helper()

				spec, ok := snapshot["spec"].(map[string]any)
				require.True(t, ok)
				spec["name"] = "other-name"
			},
		},
		{
			name: "file storage identity",
			mutate: func(t *testing.T, snapshot map[string]any) {
				t.Helper()

				spec, ok := snapshot["spec"].(map[string]any)
				require.True(t, ok)
				spec["fileStorageID"] = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
			},
		},
		{
			name: "expiration time",
			mutate: func(t *testing.T, snapshot map[string]any) {
				t.Helper()

				spec, ok := snapshot["spec"].(map[string]any)
				require.True(t, ok)
				spec["expirationTime"] = "2031-01-01T00:00:00Z"
			},
		},
		{
			name: "protected path",
			mutate: func(t *testing.T, snapshot map[string]any) {
				t.Helper()

				spec, ok := snapshot["spec"].(map[string]any)
				require.True(t, ok)
				spec["protectedPath"] = "applications/other"
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			updated := fileStorageSnapshot(ptr.To("applications/data"))
			tc.mutate(t, updated)

			require.False(t, validator.validatesUpdateUnstructured(t, updated, original))
		})
	}
}

func TestFileStorageSnapshotBackendObservedAtIsWriteOnce(t *testing.T) {
	t.Parallel()

	validator := newCRDValidator(t, fileStorageSnapshotCRDFile)
	original := fileStorageSnapshot(nil)
	original["status"] = map[string]any{"backendObservedAt": "2026-09-14T12:00:00Z"}
	firstObservation := fileStorageSnapshot(nil)
	firstObservation["status"] = map[string]any{"backendObservedAt": "2026-09-14T12:00:00Z"}

	require.True(t, validator.validatesUpdateUnstructured(t, firstObservation, fileStorageSnapshot(nil)))
	require.True(t, validator.validatesUpdateUnstructured(t, firstObservation, original))

	for _, backendObservedAt := range []any{nil, "2026-09-14T12:00:01Z"} {
		updated := fileStorageSnapshot(nil)
		if backendObservedAt != nil {
			updated["status"] = map[string]any{"backendObservedAt": backendObservedAt}
		}

		require.False(t, validator.validatesUpdateUnstructured(t, updated, original))
	}
}

func fileStorageSnapshot(protectedPath *string) map[string]any {
	spec := map[string]any{
		"name":           "Daily.Backup",
		"fileStorageID":  snapshotFileStorageID,
		"expirationTime": "2030-01-01T00:00:00Z",
	}

	if protectedPath != nil {
		spec["protectedPath"] = *protectedPath
	}

	return map[string]any{
		"apiVersion": regionv1.Group,
		"kind":       "FileStorageSnapshot",
		"metadata": map[string]any{
			"name":      "a47ac10b-58cc-4372-a567-0e02b2c3d479",
			"namespace": "default",
		},
		"spec": spec,
	}
}
