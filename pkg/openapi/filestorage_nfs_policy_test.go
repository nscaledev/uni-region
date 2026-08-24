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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/region/pkg/openapi"
)

const maxNFSPolicyAtimeUpdateIntervalSeconds int64 = 86_399_999_999_999

func TestFileStorageNFSPolicyContract(t *testing.T) {
	t.Parallel()

	swagger, err := openapi.GetSwagger()
	require.NoError(t, err)

	storageType := componentSchema(t, swagger, "storageTypeV2Spec")
	requireSchemaPropertyRef(t, storageType, "NFS", "#/components/schemas/NFSV2Spec")

	nfs := componentSchema(t, swagger, "NFSV2Spec")
	require.Contains(t, nfs.Required, "rootSquash")

	posixACL := schemaProperty(t, nfs, "posixAcl")
	require.NotContains(t, nfs.Required, "posixAcl")
	require.NotNil(t, posixACL.Type)
	require.True(t, posixACL.Type.Includes("boolean"))
	require.False(t, posixACL.PermitsNull())

	atime := schemaProperty(t, nfs, "atimeUpdateIntervalSeconds")
	require.NotContains(t, nfs.Required, "atimeUpdateIntervalSeconds")
	require.NotNil(t, atime.Type)
	require.True(t, atime.Type.Includes("integer"))
	require.Equal(t, "int64", atime.Format)
	require.False(t, atime.PermitsNull())
	require.NotNil(t, atime.Min)
	require.InDelta(t, float64(0), *atime.Min, 0)
	require.NotNil(t, atime.Max)
	require.InDelta(t, float64(maxNFSPolicyAtimeUpdateIntervalSeconds), *atime.Max, 0)

	requireSchemaPropertyRef(t, componentSchema(t, swagger, "storageV2Read"), "spec", "#/components/schemas/storageV2Spec")
	requireSchemaPropertyRef(t, componentSchema(t, swagger, "storageV2Update"), "spec", "#/components/schemas/storageV2Spec")
	require.Len(t, componentSchema(t, swagger, "storageV2Create").Properties["spec"].Value.AllOf, 2)
	require.Equal(t, "#/components/schemas/storageV2Spec", componentSchema(t, swagger, "storageV2Create").Properties["spec"].Value.AllOf[1].Ref)
}

func TestFileStorageNFSPolicyRequestValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		nfs     string
		wantErr bool
	}{
		{name: "omitted fields", nfs: `"rootSquash":true`},
		{name: "explicit false and zero", nfs: `"rootSquash":true,"posixAcl":false,"atimeUpdateIntervalSeconds":0`},
		{name: "upper bound", nfs: `"rootSquash":true,"atimeUpdateIntervalSeconds":86399999999999`},
		{name: "negative atime", nfs: `"rootSquash":true,"atimeUpdateIntervalSeconds":-1`, wantErr: true},
		{name: "atime above upper bound", nfs: `"rootSquash":true,"atimeUpdateIntervalSeconds":86400000000000`, wantErr: true},
		{name: "null POSIX ACL", nfs: `"rootSquash":true,"posixAcl":null`, wantErr: true},
		{name: "null atime", nfs: `"rootSquash":true,"atimeUpdateIntervalSeconds":null`, wantErr: true},
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
}
