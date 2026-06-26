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

package openapi_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/legacy"
	"github.com/stretchr/testify/require"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

// TestSchemaAcceptsAllProvisioningStatusValues guards against the embedded OpenAPI
// document and the core type system disagreeing about the provisioningStatus enum.
//
// The document is bundled into schema.go by `make generate`, which resolves core's
// schemas from the remote $ref target — not from the core module pinned in go.mod.
// The response-validation middleware enforces the bundled document, so a value the
// Go types define but the bundled enum lacks panics the serving handler at runtime
// while every other check stays green. This test makes that mismatch a unit
// failure: it fails until `make generate` is re-run against a $ref target that
// knows every value, which is exactly the gate a release must pass.
func TestSchemaAcceptsAllProvisioningStatusValues(t *testing.T) {
	t.Parallel()

	emittable := []coreapi.ResourceProvisioningStatus{
		coreapi.ResourceProvisioningStatusUnknown,
		coreapi.ResourceProvisioningStatusPending,
		coreapi.ResourceProvisioningStatusProvisioning,
		coreapi.ResourceProvisioningStatusProvisioned,
		coreapi.ResourceProvisioningStatusDeprovisioning,
		coreapi.ResourceProvisioningStatusError,
	}

	swagger, err := openapi.GetSwagger()
	require.NoError(t, err)

	found := 0

	for name, schema := range swagger.Components.Schemas {
		if !strings.HasSuffix(name, "resourceProvisioningStatus") || schema.Value == nil {
			continue
		}

		found++

		allowed := make(map[string]bool, len(schema.Value.Enum))

		for _, v := range schema.Value.Enum {
			s, ok := v.(string)
			require.True(t, ok, "non-string enum value %v in schema %s", v, name)

			allowed[s] = true
		}

		for _, status := range emittable {
			require.True(t, allowed[string(status)],
				"value %q is defined by the core type system but rejected by the bundled schema %s; re-run `make generate` once the $ref target includes it, or the response validator will panic when it is served",
				status, name)
		}
	}

	require.NotZero(t, found, "no resourceProvisioningStatus schema found in the embedded document; the bundling layout may have changed and this guard needs updating")
}

func TestStorageDefaultSnapshotProtectionContract(t *testing.T) {
	t.Parallel()

	swagger, err := openapi.GetSwagger()
	require.NoError(t, err)

	storageSpec := componentSchema(t, swagger, "storageV2Spec")
	defaultProtectionProperty := schemaProperty(t, storageSpec, "defaultSnapshotProtectionEnabled")
	require.NotContains(t, storageSpec.Required, "defaultSnapshotProtectionEnabled")
	require.NotNil(t, defaultProtectionProperty.Type)
	require.True(t, defaultProtectionProperty.Type.Includes("boolean"))
	require.False(t, defaultProtectionProperty.PermitsNull())

	requireSchemaPropertyRef(t, componentSchema(t, swagger, "storageV2Read"), "spec", "#/components/schemas/storageV2Spec")
	requireSchemaPropertyRef(t, componentSchema(t, swagger, "storageV2Update"), "spec", "#/components/schemas/storageV2Spec")
	require.Len(t, componentSchema(t, swagger, "storageV2Create").Properties["spec"].Value.AllOf, 2)
	require.Equal(t, "#/components/schemas/storageV2Spec", componentSchema(t, swagger, "storageV2Create").Properties["spec"].Value.AllOf[1].Ref)
}

func TestStorageDefaultSnapshotProtectionRejectsNullInput(t *testing.T) {
	t.Parallel()

	swagger, err := openapi.GetSwagger()
	require.NoError(t, err)

	storageSpec := componentSchema(t, swagger, "storageV2Spec")
	defaultProtectionProperty := schemaProperty(t, storageSpec, "defaultSnapshotProtectionEnabled")

	require.Error(t, defaultProtectionProperty.VisitJSON(nil))
}

func TestStorageV2UpdateRequestRejectsExplicitNulls(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name: "omitted nullable-looking fields is valid",
			body: `{"metadata":{"name":"storage-name"},"spec":{"sizeGiB":10,"storageType":{"NFS":{"rootSquash":true}}}}`,
		},
		{
			name:    "snapshot policies null is invalid",
			body:    `{"metadata":{"name":"storage-name"},"spec":{"sizeGiB":10,"storageType":{"NFS":{"rootSquash":true}},"snapshotPolicies":null}}`,
			wantErr: true,
		},
		{
			name:    "default snapshot protection null is invalid",
			body:    `{"metadata":{"name":"storage-name"},"spec":{"sizeGiB":10,"storageType":{"NFS":{"rootSquash":true}},"defaultSnapshotProtectionEnabled":null}}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateStorageV2UpdateRequest(t, tt.body)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func validateStorageV2UpdateRequest(t *testing.T, body string) error {
	t.Helper()

	swagger, err := openapi.GetSwagger()
	require.NoError(t, err)

	router, err := legacy.NewRouter(swagger)
	require.NoError(t, err)

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v2/filestorage/00000000-0000-0000-0000-000000000000", bytes.NewBufferString(body))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")

	route, pathParams, err := router.FindRoute(request)
	require.NoError(t, err)

	return openapi3filter.ValidateRequest(t.Context(), &openapi3filter.RequestValidationInput{
		Request:    request,
		PathParams: pathParams,
		Route:      route,
		Options: &openapi3filter.Options{
			AuthenticationFunc: openapi3filter.NoopAuthenticationFunc,
		},
	})
}

func componentSchema(t *testing.T, swagger *openapi3.T, name string) *openapi3.Schema {
	t.Helper()

	schemaRef := swagger.Components.Schemas[name]
	require.NotNil(t, schemaRef, "missing component schema %s", name)
	require.NotNil(t, schemaRef.Value, "component schema %s has no value", name)

	return schemaRef.Value
}

func schemaProperty(t *testing.T, schema *openapi3.Schema, name string) *openapi3.Schema {
	t.Helper()

	schemaRef := schema.Properties[name]
	require.NotNil(t, schemaRef, "missing schema property %s", name)
	require.NotNil(t, schemaRef.Value, "schema property %s has no value", name)

	return schemaRef.Value
}

func requireSchemaPropertyRef(t *testing.T, schema *openapi3.Schema, name string, ref string) {
	t.Helper()

	schemaRef := schema.Properties[name]
	require.NotNil(t, schemaRef, "missing schema property %s", name)
	require.Equal(t, ref, schemaRef.Ref)
}
