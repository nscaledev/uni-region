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
	"strings"
	"testing"

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
