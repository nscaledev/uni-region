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

	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func TestFileStorageSnapshotPolicyScheduleValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		schedule regionv1.FileStorageSnapshotPolicySchedule
		valid    bool
	}{
		{
			name: "hourly accepts no timing fields",
			schedule: regionv1.FileStorageSnapshotPolicySchedule{
				Interval: regionv1.FileStorageSnapshotPolicyIntervalHourly,
			},
			valid: true,
		},
		{
			name: "hourly rejects timeOfDay",
			schedule: regionv1.FileStorageSnapshotPolicySchedule{
				Interval:  regionv1.FileStorageSnapshotPolicyIntervalHourly,
				TimeOfDay: ptr.To("02:30Z"),
			},
		},
		{
			name: "daily accepts timeOfDay",
			schedule: regionv1.FileStorageSnapshotPolicySchedule{
				Interval:  regionv1.FileStorageSnapshotPolicyIntervalDaily,
				TimeOfDay: ptr.To("02:30Z"),
			},
			valid: true,
		},
		{
			name: "daily rejects missing timeOfDay",
			schedule: regionv1.FileStorageSnapshotPolicySchedule{
				Interval: regionv1.FileStorageSnapshotPolicyIntervalDaily,
			},
		},
		{
			name: "weekly accepts dayOfWeek and timeOfDay",
			schedule: regionv1.FileStorageSnapshotPolicySchedule{
				Interval:  regionv1.FileStorageSnapshotPolicyIntervalWeekly,
				DayOfWeek: ptr.To(regionv1.FileStorageSnapshotPolicyWeekdayMonday),
				TimeOfDay: ptr.To("02:30Z"),
			},
			valid: true,
		},
		{
			name: "weekly rejects dayOfMonth",
			schedule: regionv1.FileStorageSnapshotPolicySchedule{
				Interval:   regionv1.FileStorageSnapshotPolicyIntervalWeekly,
				DayOfWeek:  ptr.To(regionv1.FileStorageSnapshotPolicyWeekdayMonday),
				DayOfMonth: ptr.To(1),
				TimeOfDay:  ptr.To("02:30Z"),
			},
		},
		{
			name: "monthly accepts dayOfMonth and timeOfDay",
			schedule: regionv1.FileStorageSnapshotPolicySchedule{
				Interval:   regionv1.FileStorageSnapshotPolicyIntervalMonthly,
				DayOfMonth: ptr.To(1),
				TimeOfDay:  ptr.To("02:30Z"),
			},
			valid: true,
		},
		{
			name: "monthly rejects dayOfWeek",
			schedule: regionv1.FileStorageSnapshotPolicySchedule{
				Interval:   regionv1.FileStorageSnapshotPolicyIntervalMonthly,
				DayOfWeek:  ptr.To(regionv1.FileStorageSnapshotPolicyWeekdayMonday),
				DayOfMonth: ptr.To(1),
				TimeOfDay:  ptr.To("02:30Z"),
			},
		},
		{
			name: "timeOfDay requires UTC Z suffix",
			schedule: regionv1.FileStorageSnapshotPolicySchedule{
				Interval:  regionv1.FileStorageSnapshotPolicyIntervalDaily,
				TimeOfDay: ptr.To("02:30"),
			},
		},
		{
			name: "monthly rejects ambiguous month-end days",
			schedule: regionv1.FileStorageSnapshotPolicySchedule{
				Interval:   regionv1.FileStorageSnapshotPolicyIntervalMonthly,
				DayOfMonth: ptr.To(29),
				TimeOfDay:  ptr.To("02:30Z"),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			valid := newCRDValidator(t, fileStorageCRDFile).validates(t, fileStorageWithSnapshotPolicySchedule(tc.schedule))
			require.Equal(t, tc.valid, valid)
		})
	}
}

func TestFileStorageSnapshotPolicyProtectedPathValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		protectedPath *string
		valid         bool
	}{
		{
			name:  "omitted protected path",
			valid: true,
		},
		{
			name:          "accepts relative path",
			protectedPath: ptr.To("applications/data"),
			valid:         true,
		},
		{
			name:          "accepts dots within a component",
			protectedPath: ptr.To("releases/v1.2"),
			valid:         true,
		},
		{
			name:          "rejects a path exceeding the maximum length",
			protectedPath: ptr.To(strings.Repeat("a", 1025)),
		},
		{
			name:          "rejects empty path",
			protectedPath: ptr.To(""),
		},
		{
			name:          "rejects absolute path",
			protectedPath: ptr.To("/applications/data"),
		},
		{
			name:          "rejects trailing slash",
			protectedPath: ptr.To("applications/data/"),
		},
		{
			name:          "rejects doubled slash",
			protectedPath: ptr.To("applications//data"),
		},
		{
			name:          "rejects current-directory component",
			protectedPath: ptr.To("applications/./data"),
		},
		{
			name:          "rejects parent-directory component",
			protectedPath: ptr.To("applications/../data"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			valid := newCRDValidator(t, fileStorageCRDFile).validatesUnstructured(t, fileStorageWithSnapshotPolicyProtectedPath(tc.protectedPath))
			require.Equal(t, tc.valid, valid)
		})
	}
}

func fileStorageWithSnapshotPolicySchedule(schedule regionv1.FileStorageSnapshotPolicySchedule) *regionv1.FileStorage {
	return &regionv1.FileStorage{
		TypeMeta: metav1.TypeMeta{
			APIVersion: regionv1.Group,
			Kind:       "FileStorage",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "storage",
			Namespace: "default",
		},
		Spec: regionv1.FileStorageSpec{
			StorageClassID: "storage-class",
			Size:           resource.MustParse("1Gi"),
			SnapshotPolicies: []regionv1.FileStorageSnapshotPolicy{
				{
					Name:     "policy",
					Schedule: schedule,
					Retention: regionv1.FileStorageSnapshotPolicyRetention{
						Keep: 1,
					},
				},
			},
		},
	}
}

func fileStorageWithSnapshotPolicyProtectedPath(protectedPath *string) map[string]any {
	policy := map[string]any{
		"name": "policy",
		"schedule": map[string]any{
			"interval": "hourly",
		},
		"retention": map[string]any{
			"keep": 1,
		},
	}

	if protectedPath != nil {
		policy["protectedPath"] = *protectedPath
	}

	return map[string]any{
		"apiVersion": regionv1.Group,
		"kind":       "FileStorage",
		"metadata": map[string]any{
			"name":      "storage",
			"namespace": "default",
		},
		"spec": map[string]any{
			"storageClassID":   "storage-class",
			"size":             "1Gi",
			"snapshotPolicies": []any{policy},
		},
	}
}
