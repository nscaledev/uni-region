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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/region/pkg/openapi"
)

const maxNFSPolicyAtimeUpdateIntervalSeconds int64 = 86_399_999_999_999

func TestFileStorageNFSPolicyContract(t *testing.T) {
	t.Parallel()

	swagger, err := openapi.GetSwagger()
	require.NoError(t, err)

	writeStorageType := componentSchema(t, swagger, "storageTypeV2Spec")
	requireSchemaPropertyRef(t, writeStorageType, "NFS", "#/components/schemas/NFSV2Spec")
	require.NotContains(t, writeStorageType.Required, "NFS")

	writeNFS := componentSchema(t, swagger, "NFSV2Spec")
	require.Contains(t, writeNFS.Required, "rootSquash")
	require.NotContains(t, writeNFS.Required, "posixAcl")
	require.NotContains(t, writeNFS.Required, "atimeUpdateIntervalSeconds")

	posixACL := schemaProperty(t, writeNFS, "posixAcl")
	require.NotNil(t, posixACL.Type)
	require.True(t, posixACL.Type.Includes("boolean"))
	require.True(t, posixACL.PermitsNull())
	require.Equal(t, false, posixACL.Default)

	atime := schemaProperty(t, writeNFS, "atimeUpdateIntervalSeconds")
	require.NotNil(t, atime.Type)
	require.True(t, atime.Type.Includes("integer"))
	require.Equal(t, "int64", atime.Format)
	require.True(t, atime.PermitsNull())
	require.EqualValues(t, 0, atime.Default)
	require.NotNil(t, atime.Min)
	require.InDelta(t, float64(0), *atime.Min, 0)
	require.NotNil(t, atime.Max)
	require.InDelta(t, float64(maxNFSPolicyAtimeUpdateIntervalSeconds), *atime.Max, 0)

	requireSchemaPropertyRef(t, componentSchema(t, swagger, "storageV2Read"), "spec", "#/components/schemas/storageV2Spec")
	requireSchemaPropertyRef(t, componentSchema(t, swagger, "storageV2Update"), "spec", "#/components/schemas/storageV2Spec")
	require.Len(t, componentSchema(t, swagger, "storageV2Create").Properties["spec"].Value.AllOf, 2)
	require.Equal(t, "#/components/schemas/storageV2Spec", componentSchema(t, swagger, "storageV2Create").Properties["spec"].Value.AllOf[1].Ref)
}

func TestFileStorageNFSPolicyGeneratedClientPreservesOmission(t *testing.T) {
	t.Parallel()

	data, err := json.Marshal(openapi.NFSV2Spec{RootSquash: true})
	require.NoError(t, err)
	require.JSONEq(t, `{"rootSquash":true}`, string(data))
}

func TestFileStorageNFSPolicyRequestValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		nfs     string
		wantErr bool
	}{
		{name: "omitted fields", nfs: `"rootSquash":true`},
		{name: "null fields", nfs: `"rootSquash":true,"posixAcl":null,"atimeUpdateIntervalSeconds":null`},
		{name: "explicit false and zero", nfs: `"rootSquash":true,"posixAcl":false,"atimeUpdateIntervalSeconds":0`},
		{name: "upper bound", nfs: `"rootSquash":true,"posixAcl":true,"atimeUpdateIntervalSeconds":86399999999999`},
		{name: "negative atime", nfs: `"rootSquash":true,"posixAcl":true,"atimeUpdateIntervalSeconds":-1`, wantErr: true},
		{name: "atime above upper bound", nfs: `"rootSquash":true,"posixAcl":true,"atimeUpdateIntervalSeconds":86400000000000`, wantErr: true},
		{name: "missing root squash", nfs: `"posixAcl":false,"atimeUpdateIntervalSeconds":0`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body := `{"metadata":{"name":"storage-name"},"spec":{"sizeGiB":10,"storageType":{"NFS":{` + tt.nfs + `}}}}`
			err := validateStorageV2UpdateRequest(t, body)

			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
		})
	}

	require.NoError(t, validateStorageV2UpdateRequest(t, `{"metadata":{"name":"storage-name"},"spec":{"sizeGiB":10,"storageType":{}}}`))
	require.Error(t, validateStorageV2UpdateRequest(t, `{"metadata":{"name":"storage-name"},"spec":{"sizeGiB":10,"storageType":{"NFS":null}}}`))
}
