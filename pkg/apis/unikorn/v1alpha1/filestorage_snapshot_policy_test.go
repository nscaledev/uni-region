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
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	apixinternal "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	celvalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/listtype"
	apixvalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"sigs.k8s.io/yaml"
)

func TestFileStorageSnapshotPoliciesDeepCopyPreservesIndependentSpecAndStatus(t *testing.T) {
	t.Parallel()

	original := &regionv1.FileStorage{
		Spec: regionv1.FileStorageSpec{
			SnapshotPolicies: []regionv1.FileStorageSnapshotPolicy{
				{
					Name: "hourly",
					Schedule: regionv1.FileStorageSnapshotPolicySchedule{
						Interval: regionv1.FileStorageSnapshotPolicyIntervalHourly,
					},
					Retention: regionv1.FileStorageSnapshotPolicyRetention{
						Keep: 24,
					},
				},
			},
		},
		Status: regionv1.FileStorageStatus{
			SnapshotPolicies: []regionv1.FileStorageSnapshotPolicyStatus{
				{
					Name: "hourly",
					Conditions: []unikornv1core.Condition{
						{
							Type:               unikornv1core.ConditionAvailable,
							Status:             corev1.ConditionTrue,
							LastTransitionTime: metav1.Now(),
							Reason:             unikornv1core.ConditionReasonProvisioned,
							Message:            "snapshot policy is ready",
						},
					},
				},
			},
		},
	}

	copied := original.DeepCopy()

	original.Spec.SnapshotPolicies[0].Name = "mutated"
	original.Spec.SnapshotPolicies[0].Retention.Keep = 1
	original.Status.SnapshotPolicies[0].Name = "mutated"
	original.Status.SnapshotPolicies[0].Conditions[0].Message = "mutated"

	require.Equal(t, "hourly", copied.Spec.SnapshotPolicies[0].Name)
	require.Equal(t, 24, copied.Spec.SnapshotPolicies[0].Retention.Keep)
	require.Equal(t, "hourly", copied.Status.SnapshotPolicies[0].Name)
	require.Equal(t, "snapshot policy is ready", copied.Status.SnapshotPolicies[0].Conditions[0].Message)
}

func TestFileStorageSnapshotPolicyCRDExposesSnapshotPoliciesAsMapLists(t *testing.T) {
	t.Parallel()

	schema := fileStorageCRDSchema(t)

	desiredPolicies := schemaProperty(t, schema.Properties["spec"], "snapshotPolicies")
	require.Equal(t, "array", desiredPolicies.Type)
	require.NotNil(t, desiredPolicies.MaxItems)
	require.EqualValues(t, 4, *desiredPolicies.MaxItems)
	require.NotNil(t, desiredPolicies.XListType)
	require.Equal(t, "map", *desiredPolicies.XListType)
	require.Equal(t, []string{"name"}, desiredPolicies.XListMapKeys)

	observedPolicies := schemaProperty(t, schema.Properties["status"], "snapshotPolicies")
	require.Equal(t, "array", observedPolicies.Type)
	require.Nil(t, observedPolicies.MaxItems)
	require.NotNil(t, observedPolicies.XListType)
	require.Equal(t, "map", *observedPolicies.XListType)
	require.Equal(t, []string{"name"}, observedPolicies.XListMapKeys)
}

func TestFileStorageSnapshotPolicyCRDExposesStatusAsNameAndConditionsOnly(t *testing.T) {
	t.Parallel()

	schema := fileStorageCRDSchema(t)
	observedPolicies := schemaProperty(t, schema.Properties["status"], "snapshotPolicies")
	observedPolicy := observedPolicies.Items.Schema
	require.NotNil(t, observedPolicy)

	require.Equal(t, []string{"name"}, observedPolicy.Required)
	require.Len(t, observedPolicy.Properties, 2)
	require.Contains(t, observedPolicy.Properties, "name")
	require.Contains(t, observedPolicy.Properties, "conditions")

	name := observedPolicy.Properties["name"]
	require.Empty(t, name.Pattern)
	require.Nil(t, name.MaxLength)

	conditions := observedPolicy.Properties["conditions"]
	require.NotNil(t, conditions.XListType)
	require.Equal(t, "map", *conditions.XListType)
	require.Equal(t, []string{"type"}, conditions.XListMapKeys)
}

func TestFileStorageSnapshotPolicyCRDAcceptsNoDesiredPolicies(t *testing.T) {
	t.Parallel()

	require.Empty(t, validateFileStorageCRDObject(t, fileStorageObject()))
	require.Empty(t, validateFileStorageCRDObject(t, fileStorageObjectWithSnapshotPolicies(t, []any{})))
}

func TestFileStorageSnapshotPolicyCRDValidatesDesiredPolicyShape(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		policies []any
		valid    bool
	}{
		{
			name: "one valid hourly policy",
			policies: []any{
				hourlySnapshotPolicy("hourly", 24),
			},
			valid: true,
		},
		{
			name: "duplicate schedules with different names are accepted",
			policies: []any{
				hourlySnapshotPolicy("hourly-short", 1),
				hourlySnapshotPolicy("hourly-long", 24),
			},
			valid: true,
		},
		{
			name: "five policies exceeds the desired policy limit",
			policies: []any{
				hourlySnapshotPolicy("hourly-1", 1),
				hourlySnapshotPolicy("hourly-2", 1),
				hourlySnapshotPolicy("hourly-3", 1),
				hourlySnapshotPolicy("hourly-4", 1),
				hourlySnapshotPolicy("hourly-5", 1),
			},
		},
		{
			name: "duplicate policy names are rejected",
			policies: []any{
				hourlySnapshotPolicy("duplicate", 1),
				hourlySnapshotPolicy("duplicate", 2),
			},
		},
		{
			name: "uppercase policy names are rejected",
			policies: []any{
				snapshotPolicy("Daily", map[string]any{"interval": "hourly"}, 1),
			},
		},
		{
			name: "unsupported intervals are rejected",
			policies: []any{
				snapshotPolicy("unsupported", map[string]any{"interval": "yearly"}, 1),
			},
		},
		{
			name: "unsupported weekdays are rejected",
			policies: []any{
				snapshotPolicy("weekly", map[string]any{"interval": "weekly", "dayOfWeek": "funday", "timeOfDay": "02:30Z"}, 1),
			},
		},
		{
			name: "non-UTC time strings are rejected",
			policies: []any{
				snapshotPolicy("daily", map[string]any{"interval": "daily", "timeOfDay": "02:30"}, 1),
			},
		},
		{
			name: "ambiguous monthly days are rejected",
			policies: []any{
				snapshotPolicy("monthly", map[string]any{"interval": "monthly", "dayOfMonth": int64(29), "timeOfDay": "02:30Z"}, 1),
			},
		},
		{
			name: "zero retention is rejected",
			policies: []any{
				hourlySnapshotPolicy("hourly", 0),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			errors := validateFileStorageCRDObject(t, fileStorageObjectWithSnapshotPolicies(t, tc.policies))

			if tc.valid {
				require.Empty(t, errors)

				return
			}

			require.NotEmpty(t, errors)
		})
	}
}

func TestFileStorageSnapshotPolicyCRDValidatesScheduleMatrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		schedule map[string]any
		valid    bool
	}{
		{
			name:     "hourly forbids timing fields",
			schedule: map[string]any{"interval": "hourly"},
			valid:    true,
		},
		{
			name:     "hourly rejects timeOfDay",
			schedule: map[string]any{"interval": "hourly", "timeOfDay": "02:30Z"},
		},
		{
			name:     "daily requires timeOfDay",
			schedule: map[string]any{"interval": "daily", "timeOfDay": "02:30Z"},
			valid:    true,
		},
		{
			name:     "daily rejects missing timeOfDay",
			schedule: map[string]any{"interval": "daily"},
		},
		{
			name:     "daily rejects weekly fields",
			schedule: map[string]any{"interval": "daily", "dayOfWeek": "monday", "timeOfDay": "02:30Z"},
		},
		{
			name:     "daily rejects monthly fields",
			schedule: map[string]any{"interval": "daily", "dayOfMonth": int64(1), "timeOfDay": "02:30Z"},
		},
		{
			name:     "weekly requires dayOfWeek and timeOfDay",
			schedule: map[string]any{"interval": "weekly", "dayOfWeek": "monday", "timeOfDay": "02:30Z"},
			valid:    true,
		},
		{
			name:     "weekly rejects missing dayOfWeek",
			schedule: map[string]any{"interval": "weekly", "timeOfDay": "02:30Z"},
		},
		{
			name:     "weekly rejects monthly fields",
			schedule: map[string]any{"interval": "weekly", "dayOfMonth": int64(1), "dayOfWeek": "monday", "timeOfDay": "02:30Z"},
		},
		{
			name:     "monthly requires dayOfMonth and timeOfDay",
			schedule: map[string]any{"interval": "monthly", "dayOfMonth": int64(1), "timeOfDay": "02:30Z"},
			valid:    true,
		},
		{
			name:     "monthly rejects missing dayOfMonth",
			schedule: map[string]any{"interval": "monthly", "timeOfDay": "02:30Z"},
		},
		{
			name:     "monthly rejects weekly fields",
			schedule: map[string]any{"interval": "monthly", "dayOfMonth": int64(1), "dayOfWeek": "monday", "timeOfDay": "02:30Z"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			errors := validateFileStorageCRDObject(t, fileStorageObjectWithSnapshotPolicies(t, []any{
				snapshotPolicy("policy", tc.schedule, 1),
			}))

			if tc.valid {
				require.Empty(t, errors)

				return
			}

			require.NotEmpty(t, errors)
			require.Contains(t, strings.Join(errors, "\n"), "schedules")
		})
	}
}

func fileStorageCRDSchema(t *testing.T) *apixv1.JSONSchemaProps {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
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

func internalFileStorageCRDSchema(t *testing.T) *apixinternal.JSONSchemaProps {
	t.Helper()

	var schema apixinternal.JSONSchemaProps

	require.NoError(t, apixv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(fileStorageCRDSchema(t), &schema, nil))

	return &schema
}

func validateFileStorageCRDObject(t *testing.T, obj map[string]any) []string {
	t.Helper()

	schema := internalFileStorageCRDSchema(t)
	validator, _, err := apixvalidation.NewSchemaValidator(schema)
	require.NoError(t, err)

	result := validator.Validate(obj)
	errors := make([]string, 0, len(result.Errors))

	for _, err := range result.Errors {
		errors = append(errors, err.Error())
	}

	structural, err := structuralschema.NewStructural(schema)
	require.NoError(t, err)

	for _, err := range listtype.ValidateListSetsAndMaps(field.NewPath("root"), structural, obj) {
		errors = append(errors, err.Error())
	}

	celValidator := celvalidation.NewValidator(structural, true, 1000000)
	if celValidator == nil {
		return errors
	}

	celErrors, _ := celValidator.Validate(t.Context(), field.NewPath("root"), structural, obj, nil, 1000000)
	for _, err := range celErrors {
		errors = append(errors, err.Error())
	}

	return errors
}

func schemaProperty(t *testing.T, schema apixv1.JSONSchemaProps, name string) apixv1.JSONSchemaProps {
	t.Helper()

	property, ok := schema.Properties[name]
	require.Truef(t, ok, "schema property %q is missing", name)

	return property
}

func fileStorageObject() map[string]any {
	return map[string]any{
		"apiVersion": regionv1.Group,
		"kind":       "FileStorage",
		"metadata": map[string]any{
			"name":      "storage",
			"namespace": "default",
		},
		"spec": map[string]any{
			"storageClassID": "storage-class",
			"size":           "1Gi",
		},
	}
}

func fileStorageObjectWithSnapshotPolicies(t *testing.T, policies []any) map[string]any {
	t.Helper()

	obj := fileStorageObject()
	spec, ok := obj["spec"].(map[string]any)
	require.True(t, ok)

	spec["snapshotPolicies"] = policies

	return obj
}

func hourlySnapshotPolicy(name string, keep int64) map[string]any {
	return snapshotPolicy(name, map[string]any{"interval": "hourly"}, keep)
}

func snapshotPolicy(name string, schedule map[string]any, keep int64) map[string]any {
	return map[string]any{
		"name":      name,
		"schedule":  schedule,
		"retention": map[string]any{"keep": keep},
	}
}
