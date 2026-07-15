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
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"

	"sigs.k8s.io/yaml"
)

const (
	fileStorageCRDFile = "region.unikorn-cloud.org_filestorages.yaml"
	serverCRDFile      = "region.unikorn-cloud.org_servers.yaml"
	volumeCRDFile      = "region.unikorn-cloud.org_volumes.yaml"
)

func requireSchemaProperty(t *testing.T, schema *apixv1.JSONSchemaProps, path ...string) *apixv1.JSONSchemaProps {
	t.Helper()

	current := schema

	for _, name := range path {
		property, ok := current.Properties[name]
		require.Truef(t, ok, "schema property %q is missing", name)

		current = &property
	}

	return current
}

func TestServerRebuildSchema(t *testing.T) {
	t.Parallel()

	schema := crdSchema(t, serverCRDFile)

	rebuildGeneration := requireSchemaProperty(t, schema, "spec", "rebuildGeneration")
	require.Equal(t, "integer", rebuildGeneration.Type)
	require.NotNil(t, rebuildGeneration.Minimum)
	require.Zero(t, *rebuildGeneration.Minimum)

	targetImageID := requireSchemaProperty(t, schema, "status", "rebuild", "targetImageID")
	require.Equal(t, "string", targetImageID.Type)
	require.Equal(t, "uuid", targetImageID.Format)

	for _, name := range []string{"generation", "acceptedAttempts"} {
		property := requireSchemaProperty(t, schema, "status", "rebuild", name)
		require.Equal(t, "integer", property.Type)
		require.NotNil(t, property.Minimum)
		require.Zero(t, *property.Minimum)
	}
}

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
