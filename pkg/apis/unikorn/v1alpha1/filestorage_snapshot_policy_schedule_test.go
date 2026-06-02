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
	"os"
	"path/filepath"
	goruntime "runtime"
	"testing"

	"github.com/stretchr/testify/require"

	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	apixinternal "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	celvalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	apixvalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/yaml"
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

			valid := newFileStorageCRDValidator(t).validates(t, fileStorageWithSnapshotPolicySchedule(tc.schedule))
			require.Equal(t, tc.valid, valid)
		})
	}
}

type fileStorageCRDValidator struct {
	schema     *apixinternal.JSONSchemaProps
	structural *structuralschema.Structural
}

func (v fileStorageCRDValidator) validates(t *testing.T, storage *regionv1.FileStorage) bool {
	t.Helper()

	obj := toUnstructured(t, storage)

	validator, _, err := apixvalidation.NewSchemaValidator(v.schema)
	require.NoError(t, err)

	if validator.Validate(obj).HasErrors() {
		return false
	}

	celValidator := celvalidation.NewValidator(v.structural, true, celconfig.PerCallLimit)
	require.NotNil(t, celValidator)

	celErrors, _ := celValidator.Validate(t.Context(), field.NewPath("root"), v.structural, obj, nil, celconfig.RuntimeCELCostBudget)

	return len(celErrors) == 0
}

func toUnstructured(t *testing.T, storage *regionv1.FileStorage) map[string]any {
	t.Helper()

	out, err := kruntime.DefaultUnstructuredConverter.ToUnstructured(storage)
	require.NoError(t, err)

	return out
}

func newFileStorageCRDValidator(t *testing.T) fileStorageCRDValidator {
	t.Helper()

	schema := fileStorageInternalSchema(t)
	structural, err := structuralschema.NewStructural(schema)
	require.NoError(t, err)

	return fileStorageCRDValidator{
		schema:     schema,
		structural: structural,
	}
}

func fileStorageInternalSchema(t *testing.T) *apixinternal.JSONSchemaProps {
	t.Helper()

	var schema apixinternal.JSONSchemaProps

	require.NoError(t, apixv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(fileStorageCRDSchema(t), &schema, nil))

	return &schema
}

func fileStorageCRDSchema(t *testing.T) *apixv1.JSONSchemaProps {
	t.Helper()

	_, filename, _, ok := goruntime.Caller(0)
	require.True(t, ok)

	path := filepath.Join(filepath.Dir(filename), "..", "..", "..", "..", "charts", "region", "crds", "region.unikorn-cloud.org_filestorages.yaml")
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var crd apixv1.CustomResourceDefinition

	require.NoError(t, yaml.Unmarshal(data, &crd))

	for i := range crd.Spec.Versions {
		version := &crd.Spec.Versions[i]
		if version.Name == regionv1.GroupVersion && version.Schema != nil {
			return version.Schema.OpenAPIV3Schema
		}
	}

	t.Fatalf("file storage CRD does not define schema for %s", regionv1.GroupVersion)

	return nil
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
