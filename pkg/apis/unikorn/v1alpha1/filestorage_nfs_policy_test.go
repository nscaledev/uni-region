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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	"k8s.io/utils/ptr"
)

const maxAtimeUpdateIntervalSeconds int64 = 86_399_999_999_999

func TestFileStorageNFSPolicySchema(t *testing.T) {
	t.Parallel()

	nfs := requireSchemaProperty(t, crdSchema(t, fileStorageCRDFile), "spec", "nfs")
	posixACL := requireSchemaProperty(t, nfs, "posixAcl")
	require.Equal(t, "boolean", posixACL.Type)
	require.False(t, posixACL.Nullable)
	require.NotContains(t, nfs.Required, "posixAcl")

	atime := requireSchemaProperty(t, nfs, "atimeUpdateIntervalSeconds")
	require.Equal(t, "integer", atime.Type)
	require.Equal(t, "int64", atime.Format)
	require.False(t, atime.Nullable)
	require.NotContains(t, nfs.Required, "atimeUpdateIntervalSeconds")
	require.NotNil(t, atime.Minimum)
	require.InDelta(t, float64(0), *atime.Minimum, 0)
	require.NotNil(t, atime.Maximum)
	require.InDelta(t, float64(maxAtimeUpdateIntervalSeconds), *atime.Maximum, 0)
}

func TestFileStorageNFSPolicyPresenceRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		nfs    regionv1.NFS
		want   string
		assert func(*testing.T, regionv1.NFS)
	}{
		{
			name: "omitted values remain absent",
			want: `{}`,
			assert: func(t *testing.T, got regionv1.NFS) {
				t.Helper()
				require.Nil(t, got.POSIXACL)
				require.Nil(t, got.AtimeUpdateIntervalSeconds)
			},
		},
		{
			name: "explicit false and zero remain present",
			nfs: regionv1.NFS{
				POSIXACL:                   ptr.To(false),
				AtimeUpdateIntervalSeconds: ptr.To(int64(0)),
			},
			want: `{"posixAcl":false,"atimeUpdateIntervalSeconds":0}`,
			assert: func(t *testing.T, got regionv1.NFS) {
				t.Helper()
				require.NotNil(t, got.POSIXACL)
				require.False(t, *got.POSIXACL)
				require.NotNil(t, got.AtimeUpdateIntervalSeconds)
				require.Zero(t, *got.AtimeUpdateIntervalSeconds)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			data, err := json.Marshal(tc.nfs)
			require.NoError(t, err)
			require.JSONEq(t, tc.want, string(data))

			var roundTripped regionv1.NFS

			require.NoError(t, json.Unmarshal(data, &roundTripped))
			tc.assert(t, roundTripped)
		})
	}
}

func TestFileStorageNFSPolicyBoundsValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		nfs   map[string]any
		valid bool
	}{
		{name: "omitted values", nfs: map[string]any{}, valid: true},
		{name: "explicit false and lower bound", nfs: map[string]any{"posixAcl": false, "atimeUpdateIntervalSeconds": int64(0)}, valid: true},
		{name: "upper bound", nfs: map[string]any{"atimeUpdateIntervalSeconds": maxAtimeUpdateIntervalSeconds}, valid: true},
		{name: "below lower bound", nfs: map[string]any{"atimeUpdateIntervalSeconds": int64(-1)}},
		{name: "above upper bound", nfs: map[string]any{"atimeUpdateIntervalSeconds": maxAtimeUpdateIntervalSeconds + 1}},
		{name: "null POSIX ACL", nfs: map[string]any{"posixAcl": nil}},
		{name: "null atime", nfs: map[string]any{"atimeUpdateIntervalSeconds": nil}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			valid := newCRDValidator(t, fileStorageCRDFile).validatesUnstructured(t, fileStorageWithNFS(tc.nfs))
			require.Equal(t, tc.valid, valid)
		})
	}
}

func fileStorageWithNFS(nfs map[string]any) map[string]any {
	return map[string]any{
		"apiVersion": "region.unikorn-cloud.org/v1alpha1",
		"kind":       "FileStorage",
		"metadata": map[string]any{
			"name":      "storage",
			"namespace": "default",
		},
		"spec": map[string]any{
			"storageClassID": "storage-class",
			"size":           "1Gi",
			"nfs":            nfs,
		},
	}
}
