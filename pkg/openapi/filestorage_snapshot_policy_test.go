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
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/region/pkg/openapi"
)

func TestFileStorageSnapshotPolicyProtectedPathContract(t *testing.T) {
	t.Parallel()

	swagger, err := openapi.GetSwagger()
	require.NoError(t, err)

	policy := componentSchema(t, swagger, "storageSnapshotPolicyV2Spec")
	protectedPath := schemaProperty(t, policy, "protectedPath")
	require.NotContains(t, policy.Required, "protectedPath")
	require.NotNil(t, protectedPath.Type)
	require.True(t, protectedPath.Type.Includes("string"))
	require.False(t, protectedPath.PermitsNull())
	require.NotNil(t, protectedPath.MaxLength)
	require.EqualValues(t, 1024, *protectedPath.MaxLength)
	require.Equal(t, "^([^/]+/)*[^/]+$", protectedPath.Pattern)
}

func TestFileStorageSnapshotPolicyProtectedPathRequestValidation(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name     string
		fragment string
		wantErr  bool
	}{
		{name: "omitted path protects the root"},
		{name: "valid relative path", fragment: `,"protectedPath":"applications/data"`},
		{name: "dots within a component", fragment: `,"protectedPath":"releases/v1.2"`},
		{name: "null path", fragment: `,"protectedPath":null`, wantErr: true},
		{name: "empty path", fragment: `,"protectedPath":""`, wantErr: true},
		{name: "absolute path", fragment: `,"protectedPath":"/applications/data"`, wantErr: true},
		{name: "trailing slash", fragment: `,"protectedPath":"applications/data/"`, wantErr: true},
		{name: "doubled slash", fragment: `,"protectedPath":"applications//data"`, wantErr: true},
		{name: "path exceeds maximum length", fragment: `,"protectedPath":"` + strings.Repeat("a", 1025) + `"`, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body := fmt.Sprintf(`{"metadata":{"name":"storage-name"},"spec":{"sizeGiB":10,"storageType":{"NFS":{"rootSquash":true}},"snapshotPolicies":[{"name":"daily"%s,"schedule":{"interval":"daily","timeOfDay":"04:00Z"},"retention":{"keep":7}}]}}`, tt.fragment)

			err := validateStorageV2UpdateRequest(t, body)
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
		})
	}
}
