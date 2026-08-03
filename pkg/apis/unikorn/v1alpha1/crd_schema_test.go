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
	"time"

	"github.com/stretchr/testify/require"

	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	apixinternal "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	celvalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	apixvalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"

	"sigs.k8s.io/yaml"
)

const (
	fileStorageCRDFile = "region.unikorn-cloud.org_filestorages.yaml"
	volumeCRDFile      = "region.unikorn-cloud.org_volumes.yaml"
	serverCRDFile      = "region.unikorn-cloud.org_servers.yaml"
)

type crdValidator struct {
	schema     *apixinternal.JSONSchemaProps
	structural *structuralschema.Structural
}

func (v crdValidator) validates(t *testing.T, resource any) bool {
	t.Helper()

	return v.validatesUnstructured(t, toUnstructured(t, resource))
}

func (v crdValidator) validatesUnstructured(t *testing.T, obj map[string]any) bool {
	t.Helper()

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

func newCRDValidator(t *testing.T, crdFile string) crdValidator {
	t.Helper()

	schema := internalCRDSchema(t, crdFile)
	structural, err := structuralschema.NewStructural(schema)
	require.NoError(t, err)

	return crdValidator{
		schema:     schema,
		structural: structural,
	}
}

func toUnstructured(t *testing.T, resource any) map[string]any {
	t.Helper()

	out, err := kruntime.DefaultUnstructuredConverter.ToUnstructured(resource)
	require.NoError(t, err)

	return out
}

func internalCRDSchema(t *testing.T, crdFile string) *apixinternal.JSONSchemaProps {
	t.Helper()

	var schema apixinternal.JSONSchemaProps

	require.NoError(t, apixv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(crdSchema(t, crdFile), &schema, nil))

	return &schema
}

func crdSchema(t *testing.T, crdFile string) *apixv1.JSONSchemaProps {
	t.Helper()

	_, filename, _, ok := goruntime.Caller(0)
	require.True(t, ok)

	path := filepath.Join(filepath.Dir(filename), "..", "..", "..", "..", "charts", "region", "crds", crdFile)
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

	t.Fatalf("%s does not define schema for %s", crdFile, regionv1.GroupVersion)

	return nil
}

// TestServerObservedSchema pins the monitor-owned subtree: the CRD must accept a
// fully populated observation and reject a mistyped generation.
func TestServerObservedSchema(t *testing.T) {
	t.Parallel()

	validator := newCRDValidator(t, serverCRDFile)

	now := metav1.Now()

	server := func(observed map[string]any) map[string]any {
		return map[string]any{
			"apiVersion": "region.unikorn-cloud.org/v1alpha1",
			"kind":       "Server",
			"metadata":   map[string]any{"name": "test", "namespace": "test"},
			"spec": map[string]any{
				"flavorID": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
				"image":    map[string]any{"id": "3f2504e0-4f89-11d3-9a0c-0305e82c3302"},
			},
			"status": map[string]any{"observed": observed},
		}
	}

	require.True(t, validator.validatesUnstructured(t, server(map[string]any{
		"serverGeneration": int64(7),
		"macAddress":       "e0:9d:73:86:cc:18",
		"launchedAt":       now.Format(time.RFC3339),
		"scheduledAt":      now.Format(time.RFC3339),
		"provisionedAt":    now.Format(time.RFC3339),
	})), "a fully populated observation must validate")

	require.False(t, validator.validatesUnstructured(t, server(map[string]any{
		"serverGeneration": "seven",
	})), "the generation is an integer and a string must be rejected")
}

// TestServerRebuildSchema pins the reconciler-owned rebuild marker. The
// rejection cases carry the weight: an unrecognised subtree is pruned rather
// than refused, so only a required-field failure proves the schema has it.
func TestServerRebuildSchema(t *testing.T) {
	t.Parallel()

	validator := newCRDValidator(t, serverCRDFile)

	server := func(rebuild map[string]any) map[string]any {
		return map[string]any{
			"apiVersion": "region.unikorn-cloud.org/v1alpha1",
			"kind":       "Server",
			"metadata":   map[string]any{"name": "test", "namespace": "test"},
			"spec": map[string]any{
				"flavorID": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
				"image":    map[string]any{"id": "3f2504e0-4f89-11d3-9a0c-0305e82c3302"},
			},
			"status": map[string]any{"rebuild": rebuild},
		}
	}

	require.True(t, validator.validatesUnstructured(t, server(map[string]any{
		"targetImageID":  "6f1a2b3c-0000-4000-8000-000000000001",
		"preArmImageRef": "6f1a2b3c-0000-4000-8000-000000000002",
		"accepted":       true,
		"parked":         false,
	})), "a fully populated rebuild marker must validate")

	require.False(t, validator.validatesUnstructured(t, server(map[string]any{
		"preArmImageRef": "6f1a2b3c-0000-4000-8000-000000000002",
	})), "a marker without a target must be rejected")

	require.False(t, validator.validatesUnstructured(t, server(map[string]any{
		"targetImageID": "6f1a2b3c-0000-4000-8000-000000000001",
	})), "a marker without a pre-arm ref must be rejected")
}
