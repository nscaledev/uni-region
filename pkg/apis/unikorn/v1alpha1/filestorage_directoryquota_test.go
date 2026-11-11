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

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
)

const directoryQuotaFileStorageID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"

// directoryQuota builds a minimal valid quota, then applies the mutations to its spec.
func directoryQuota(t *testing.T, mutations ...func(spec map[string]any)) map[string]any {
	t.Helper()

	spec := map[string]any{
		"fileStorageID":   directoryQuotaFileStorageID,
		"path":            "projects/alpha",
		"directoryLimits": map[string]any{"capacity": "1Ti"},
	}

	for _, mutate := range mutations {
		mutate(spec)
	}

	return map[string]any{
		"apiVersion": regionv1.Group,
		"kind":       "FileStorageDirectoryQuota",
		"metadata": map[string]any{
			"name":      "b47ac10b-58cc-4372-a567-0e02b2c3d479",
			"namespace": "default",
		},
		"spec": spec,
	}
}

func rule(kind string, subject map[string]any, limits map[string]any) map[string]any {
	subject["kind"] = kind

	return map[string]any{"subject": subject, "limits": limits}
}

func TestFileStorageDirectoryQuotaSchema(t *testing.T) {
	t.Parallel()

	schema := crdSchema(t, fileStorageDirectoryQuotaCRDFile)
	spec := requireSchemaProperty(t, schema, "spec")

	require.Contains(t, spec.Required, "fileStorageID")
	require.Contains(t, spec.Required, "path")
	require.Equal(t, "uuid", requireSchemaProperty(t, schema, "spec", "fileStorageID").Format)
	require.Equal(t, "boolean", requireSchemaProperty(t, schema, "spec", "pause").Type)
	require.Equal(t, "array", requireSchemaProperty(t, schema, "spec", "rules").Type)
	require.Equal(t, "atomic", *requireSchemaProperty(t, schema, "spec", "rules").XListType)
	require.Equal(t, int64(20), *requireSchemaProperty(t, schema, "spec", "rules").MaxItems)
	require.Equal(t, "array", requireSchemaProperty(t, schema, "status", "conditions").Type)
	require.Equal(t, "atomic", *requireSchemaProperty(t, schema, "status", "rules").XListType)
	require.Equal(t, "atomic", *requireSchemaProperty(t, schema, "status", "usage", "rules").XListType)
}

func TestFileStorageDirectoryQuotaManagedResourceHelpers(t *testing.T) {
	t.Parallel()

	quota := &regionv1.FileStorageDirectoryQuota{}

	require.False(t, quota.Paused())

	quota.Spec.Pause = true
	require.True(t, quota.Paused())

	_, err := quota.StatusConditionRead(unikornv1core.ConditionAvailable)
	require.Error(t, err)

	quota.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "done")

	condition, err := quota.StatusConditionRead(unikornv1core.ConditionAvailable)
	require.NoError(t, err)
	require.Equal(t, string(unikornv1core.ConditionReasonProvisioned), condition.Reason)

	labels, err := quota.ResourceLabels()
	require.NoError(t, err)
	require.Nil(t, labels)
}

func TestFileStorageDirectoryQuotaProjectScope(t *testing.T) {
	t.Parallel()

	quota := &regionv1.FileStorageDirectoryQuota{}
	quota.Labels = map[string]string{
		coreconstants.OrganizationLabel: snapshotOrganizationID,
		coreconstants.ProjectLabel:      snapshotProjectID,
	}

	organizationID, err := quota.OrganizationID()
	require.NoError(t, err)
	require.Equal(t, snapshotOrganizationID, organizationID.String())

	organizationID, projectID, err := quota.OrganizationAndProjectID()
	require.NoError(t, err)
	require.Equal(t, snapshotOrganizationID, organizationID.String())
	require.Equal(t, snapshotProjectID, projectID.String())

	quota.Labels[coreconstants.ProjectLabel] = "not-a-uuid"
	_, _, err = quota.OrganizationAndProjectID()
	require.Error(t, err)
}

// TestFileStorageDirectoryQuotaLimitsShape covers the shared limits type in each
// of the four places it is used.
func TestFileStorageDirectoryQuotaLimitsShape(t *testing.T) {
	t.Parallel()

	locations := map[string]func(limits map[string]any) func(spec map[string]any){
		"directoryLimits": func(limits map[string]any) func(map[string]any) {
			return func(spec map[string]any) { spec["directoryLimits"] = limits }
		},
		"defaultUserLimits": func(limits map[string]any) func(map[string]any) {
			return func(spec map[string]any) { spec["defaultUserLimits"] = limits }
		},
		"defaultGroupLimits": func(limits map[string]any) func(map[string]any) {
			return func(spec map[string]any) { spec["defaultGroupLimits"] = limits }
		},
		"rules[].limits": func(limits map[string]any) func(map[string]any) {
			return func(spec map[string]any) {
				spec["rules"] = []any{rule("user", map[string]any{"name": "alice"}, limits)}
			}
		},
	}

	shapes := []struct {
		name   string
		limits map[string]any
		valid  bool
	}{
		{name: "capacity only", limits: map[string]any{"capacity": "10Gi"}, valid: true},
		{name: "inodes only", limits: map[string]any{"inodes": int64(1000)}, valid: true},
		{name: "both", limits: map[string]any{"capacity": "10Gi", "inodes": int64(1000)}, valid: true},
		{name: "neither", limits: map[string]any{}},
	}

	validator := newCRDValidator(t, fileStorageDirectoryQuotaCRDFile)

	for location, apply := range locations {
		for _, shape := range shapes {
			t.Run(location+"/"+shape.name, func(t *testing.T) {
				t.Parallel()

				quota := directoryQuota(t, apply(shape.limits))

				require.Equal(t, shape.valid, validator.validatesUnstructured(t, quota))
			})
		}
	}
}

func TestFileStorageDirectoryQuotaSpecRules(t *testing.T) {
	t.Parallel()

	alice := func() map[string]any { return map[string]any{"name": "alice"} }
	limits := func() map[string]any { return map[string]any{"capacity": "1Gi"} }

	cases := []struct {
		name   string
		mutate func(spec map[string]any)
		valid  bool
	}{
		// Rule 6: at least one limit or rule.
		{name: "directory limit only", valid: true},
		{name: "default user limit only", mutate: func(s map[string]any) {
			delete(s, "directoryLimits")
			s["defaultUserLimits"] = limits()
		}, valid: true},
		{name: "default group limit only", mutate: func(s map[string]any) {
			delete(s, "directoryLimits")
			s["defaultGroupLimits"] = limits()
		}, valid: true},
		{name: "rules only", mutate: func(s map[string]any) {
			delete(s, "directoryLimits")
			s["rules"] = []any{rule("user", alice(), limits())}
		}, valid: true},
		{name: "nothing set", mutate: func(s map[string]any) { delete(s, "directoryLimits") }},
		{name: "empty rules only", mutate: func(s map[string]any) {
			delete(s, "directoryLimits")
			s["rules"] = []any{}
		}},

		// Rule 5: subject sets exactly one of name or id.
		{name: "subject by name", mutate: func(s map[string]any) {
			s["rules"] = []any{rule("user", alice(), limits())}
		}, valid: true},
		{name: "subject by id", mutate: func(s map[string]any) {
			s["rules"] = []any{rule("group", map[string]any{"id": int64(1000)}, limits())}
		}, valid: true},
		{name: "subject with neither", mutate: func(s map[string]any) {
			s["rules"] = []any{rule("user", map[string]any{}, limits())}
		}},
		{name: "subject with both", mutate: func(s map[string]any) {
			s["rules"] = []any{rule("user", map[string]any{"name": "alice", "id": int64(1000)}, limits())}
		}},

		// Rule 7: no duplicate subject.
		{name: "same name, different kind", mutate: func(s map[string]any) {
			s["rules"] = []any{rule("user", alice(), limits()), rule("group", alice(), limits())}
		}, valid: true},
		{name: "name and id of the same person are not CEL duplicates", mutate: func(s map[string]any) {
			s["rules"] = []any{rule("user", alice(), limits()), rule("user", map[string]any{"id": int64(1000)}, limits())}
		}, valid: true},
		{name: "duplicate subject", mutate: func(s map[string]any) {
			s["rules"] = []any{rule("user", alice(), limits()), rule("user", alice(), map[string]any{"inodes": int64(5)})}
		}},

		// Rule 8 and path shape.
		{name: "nested path", mutate: func(s map[string]any) { s["path"] = "a/b/c" }, valid: true},
		{name: "dots within a component", mutate: func(s map[string]any) { s["path"] = "releases/v1.2" }, valid: true},
		{name: "path of 1024 characters", mutate: func(s map[string]any) { s["path"] = strings.Repeat("a", 1024) }, valid: true},
		{name: "path over 1024 characters", mutate: func(s map[string]any) { s["path"] = strings.Repeat("a", 1025) }},
		{name: "empty path", mutate: func(s map[string]any) { s["path"] = "" }},
		{name: "root-like absolute path", mutate: func(s map[string]any) { s["path"] = "/" }},
		{name: "absolute path", mutate: func(s map[string]any) { s["path"] = "/a/b" }},
		{name: "trailing slash", mutate: func(s map[string]any) { s["path"] = "a/b/" }},
		{name: "doubled slash", mutate: func(s map[string]any) { s["path"] = "a//b" }},
		{name: "current-directory component", mutate: func(s map[string]any) { s["path"] = "a/./b" }},
		{name: "parent-directory component", mutate: func(s map[string]any) { s["path"] = "a/../b" }},
		{name: "path is required", mutate: func(s map[string]any) { delete(s, "path") }},
		{name: "file storage id is required", mutate: func(s map[string]any) { delete(s, "fileStorageID") }},
	}

	validator := newCRDValidator(t, fileStorageDirectoryQuotaCRDFile)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var mutations []func(map[string]any)
			if tc.mutate != nil {
				mutations = append(mutations, tc.mutate)
			}

			require.Equal(t, tc.valid, validator.validatesUnstructured(t, directoryQuota(t, mutations...)))
		})
	}
}

func TestFileStorageDirectoryQuotaSchemaBounds(t *testing.T) {
	t.Parallel()

	withLimits := func(limits map[string]any) func(map[string]any) {
		return func(s map[string]any) { s["directoryLimits"] = limits }
	}

	withSubject := func(subject map[string]any) func(map[string]any) {
		return func(s map[string]any) {
			s["rules"] = []any{rule("user", subject, map[string]any{"capacity": "1Gi"})}
		}
	}

	manyRules := func(n int) func(map[string]any) {
		return func(s map[string]any) {
			rules := make([]any, 0, n)

			for i := range n {
				rules = append(rules, rule("user", map[string]any{"id": int64(i)}, map[string]any{"capacity": "1Gi"}))
			}

			s["rules"] = rules
		}
	}

	cases := []struct {
		name   string
		mutate func(spec map[string]any)
		valid  bool
	}{
		{name: "20 rules", mutate: manyRules(20), valid: true},
		{name: "21 rules", mutate: manyRules(21)},

		{name: "inodes 1", mutate: withLimits(map[string]any{"inodes": int64(1)}), valid: true},
		{name: "inodes 0", mutate: withLimits(map[string]any{"inodes": int64(0)})},
		{name: "inodes negative", mutate: withLimits(map[string]any{"inodes": int64(-1)})},

		{name: "capacity 1 byte", mutate: withLimits(map[string]any{"capacity": "1"}), valid: true},
		{name: "capacity binary suffix", mutate: withLimits(map[string]any{"capacity": "16Ti"}), valid: true},
		{name: "capacity decimal suffix", mutate: withLimits(map[string]any{"capacity": "100G"}), valid: true},
		{name: "capacity whole-number exponent", mutate: withLimits(map[string]any{"capacity": "1e3"}), valid: true},
		{name: "capacity integer", mutate: withLimits(map[string]any{"capacity": int64(1073741824)}), valid: true},
		{name: "capacity not a quantity", mutate: withLimits(map[string]any{"capacity": "lots"})},

		{name: "unknown kind", mutate: func(s map[string]any) {
			s["rules"] = []any{rule("role", map[string]any{"name": "x"}, map[string]any{"capacity": "1Gi"})}
		}},
		{name: "id 0", mutate: withSubject(map[string]any{"id": int64(0)}), valid: true},
		{name: "id maximum", mutate: withSubject(map[string]any{"id": int64(4294967294)}), valid: true},
		{name: "id over maximum", mutate: withSubject(map[string]any{"id": int64(4294967295)})},
		{name: "id negative", mutate: withSubject(map[string]any{"id": int64(-1)})},
		{name: "name with domain", mutate: withSubject(map[string]any{"name": `CORP\alice`}), valid: true},
		{name: "name of 256 characters", mutate: withSubject(map[string]any{"name": strings.Repeat("a", 256)}), valid: true},
		{name: "name of 257 characters", mutate: withSubject(map[string]any{"name": strings.Repeat("a", 257)})},
		{name: "empty name", mutate: withSubject(map[string]any{"name": ""})},
	}

	validator := newCRDValidator(t, fileStorageDirectoryQuotaCRDFile)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.valid, validator.validatesUnstructured(t, directoryQuota(t, tc.mutate)))
		})
	}
}

func TestFileStorageDirectoryQuotaImmutability(t *testing.T) {
	t.Parallel()

	validator := newCRDValidator(t, fileStorageDirectoryQuotaCRDFile)
	original := directoryQuota(t)

	// Everything but the identity of the quota may change.
	mutable := []struct {
		name   string
		mutate func(spec map[string]any)
	}{
		{name: "same spec", mutate: func(map[string]any) {}},
		{name: "pause", mutate: func(s map[string]any) { s["pause"] = true }},
		{name: "directory limits", mutate: func(s map[string]any) { s["directoryLimits"] = map[string]any{"inodes": int64(5)} }},
		{name: "rules", mutate: func(s map[string]any) {
			s["rules"] = []any{rule("user", map[string]any{"name": "alice"}, map[string]any{"capacity": "1Gi"})}
		}},
		{name: "tags", mutate: func(s map[string]any) {
			s["tags"] = []any{map[string]any{"name": "team", "value": "ml"}}
		}},
	}

	for _, tc := range mutable {
		t.Run("mutable/"+tc.name, func(t *testing.T) {
			t.Parallel()

			updated := directoryQuota(t, tc.mutate)

			require.True(t, validator.validatesUpdateUnstructured(t, updated, original))
		})
	}

	immutable := []struct {
		name   string
		mutate func(spec map[string]any)
	}{
		{name: "path", mutate: func(s map[string]any) { s["path"] = "projects/beta" }},
		{name: "file storage id", mutate: func(s map[string]any) { s["fileStorageID"] = "6ba7b810-9dad-11d1-80b4-00c04fd430c8" }},
	}

	for _, tc := range immutable {
		t.Run("immutable/"+tc.name, func(t *testing.T) {
			t.Parallel()

			updated := directoryQuota(t, tc.mutate)

			require.False(t, validator.validatesUpdateUnstructured(t, updated, original))
		})
	}
}

func TestFileStorageDirectoryQuotaStatusSchema(t *testing.T) {
	t.Parallel()

	validator := newCRDValidator(t, fileStorageDirectoryQuotaCRDFile)

	quota := directoryQuota(t)
	quota["status"] = map[string]any{
		"observedGeneration": int64(2),
		"rules": []any{
			map[string]any{
				"subject":            map[string]any{"kind": "user", "name": "alice"},
				"provisioningStatus": "Provisioned",
			},
			map[string]any{
				"subject":            map[string]any{"kind": "user", "name": "typo"},
				"provisioningStatus": "Errored",
				"message":            "not found",
			},
		},
		"usage": map[string]any{
			"directory": map[string]any{"usedCapacity": "2Gi", "usedInodes": int64(10)},
			"rules": []any{
				map[string]any{
					"subject": map[string]any{"kind": "user", "name": "alice"},
					"usage":   map[string]any{"usedCapacity": "1Gi"},
				},
			},
			"timestamp": "2026-10-30T10:08:46Z",
		},
	}

	require.True(t, validator.validatesUnstructured(t, quota))

	status, ok := quota["status"].(map[string]any)
	require.True(t, ok)

	rules, ok := status["rules"].([]any)
	require.True(t, ok)

	first, ok := rules[0].(map[string]any)
	require.True(t, ok)

	first["provisioningStatus"] = "Broken"

	require.False(t, validator.validatesUnstructured(t, quota))
}
