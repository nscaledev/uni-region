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

	structuraldefaulting "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/defaulting"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"
)

const maxAtimeUpdateIntervalSeconds int64 = 86_399_999_999_999

func TestFileStorageNFSPolicySchema(t *testing.T) {
	t.Parallel()

	nfs := requireSchemaProperty(t, crdSchema(t, fileStorageCRDFile), "spec", "nfs")
	rootSquash := requireSchemaProperty(t, nfs, "rootSquash")
	require.Equal(t, "boolean", rootSquash.Type)
	require.False(t, rootSquash.Nullable)
	require.NotContains(t, nfs.Required, "rootSquash")

	posixACL := requireSchemaProperty(t, nfs, "posixAcl")
	require.Equal(t, "boolean", posixACL.Type)
	require.False(t, posixACL.Nullable)
	require.Contains(t, nfs.Required, "posixAcl")

	atime := requireSchemaProperty(t, nfs, "atimeUpdateIntervalSeconds")
	require.Equal(t, "integer", atime.Type)
	require.Equal(t, "int64", atime.Format)
	require.False(t, atime.Nullable)
	require.Contains(t, nfs.Required, "atimeUpdateIntervalSeconds")
	require.NotNil(t, atime.Minimum)
	require.InDelta(t, float64(0), *atime.Minimum, 0)
	require.NotNil(t, atime.Maximum)
	require.InDelta(t, float64(maxAtimeUpdateIntervalSeconds), *atime.Maximum, 0)
}

func TestFileStorageNFSPolicyPresenceRoundTrip(t *testing.T) {
	t.Parallel()

	var omitted regionv1.NFS

	require.NoError(t, json.Unmarshal([]byte(`{}`), &omitted))
	require.False(t, omitted.RootSquash)
	require.Nil(t, omitted.POSIXACL)
	require.Nil(t, omitted.AtimeUpdateIntervalSeconds)

	cases := []struct {
		name   string
		nfs    regionv1.NFS
		want   string
		assert func(*testing.T, regionv1.NFS)
	}{
		{
			name: "zero values remain present",
			nfs: regionv1.NFS{
				POSIXACL:                   ptr.To(false),
				AtimeUpdateIntervalSeconds: ptr.To(int64(0)),
			},
			want: `{"posixAcl":false,"atimeUpdateIntervalSeconds":0}`,
			assert: func(t *testing.T, got regionv1.NFS) {
				t.Helper()
				require.Equal(t, ptr.To(false), got.POSIXACL)
				require.Equal(t, ptr.To(int64(0)), got.AtimeUpdateIntervalSeconds)
			},
		},
		{
			name: "explicit values remain present",
			nfs: regionv1.NFS{
				RootSquash:                 true,
				POSIXACL:                   ptr.To(true),
				AtimeUpdateIntervalSeconds: ptr.To(maxAtimeUpdateIntervalSeconds),
			},
			want: `{"rootSquash":true,"posixAcl":true,"atimeUpdateIntervalSeconds":86399999999999}`,
			assert: func(t *testing.T, got regionv1.NFS) {
				t.Helper()
				require.Equal(t, ptr.To(true), got.POSIXACL)
				require.Equal(t, ptr.To(maxAtimeUpdateIntervalSeconds), got.AtimeUpdateIntervalSeconds)
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

func TestFileStorageNFSPolicyDefaultsBeforeValidation(t *testing.T) {
	t.Parallel()

	resource := fileStorageWithNFS(map[string]any{"rootSquash": true})
	validator := newCRDValidator(t, fileStorageCRDFile)

	structuraldefaulting.Default(resource, validator.structural)

	posixACL, found, err := unstructured.NestedBool(resource, "spec", "nfs", "posixAcl")
	require.NoError(t, err)
	require.True(t, found)
	require.False(t, posixACL)

	atime, found, err := unstructured.NestedInt64(resource, "spec", "nfs", "atimeUpdateIntervalSeconds")
	require.NoError(t, err)
	require.True(t, found)
	require.Zero(t, atime)
	require.True(t, validator.validatesUnstructured(t, resource))
}

func TestFileStorageNFSPolicyBoundsValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		nfs   map[string]any
		valid bool
	}{
		{name: "omitted values", nfs: map[string]any{}},
		{name: "missing root squash", nfs: map[string]any{"posixAcl": false, "atimeUpdateIntervalSeconds": int64(0)}, valid: true},
		{name: "explicit false and lower bound", nfs: map[string]any{"rootSquash": false, "posixAcl": false, "atimeUpdateIntervalSeconds": int64(0)}, valid: true},
		{name: "upper bound", nfs: map[string]any{"rootSquash": true, "posixAcl": true, "atimeUpdateIntervalSeconds": maxAtimeUpdateIntervalSeconds}, valid: true},
		{name: "below lower bound", nfs: map[string]any{"rootSquash": true, "posixAcl": true, "atimeUpdateIntervalSeconds": int64(-1)}},
		{name: "above upper bound", nfs: map[string]any{"rootSquash": true, "posixAcl": true, "atimeUpdateIntervalSeconds": maxAtimeUpdateIntervalSeconds + 1}},
		{name: "null POSIX ACL", nfs: map[string]any{"rootSquash": true, "posixAcl": nil, "atimeUpdateIntervalSeconds": int64(0)}},
		{name: "null atime", nfs: map[string]any{"rootSquash": true, "posixAcl": false, "atimeUpdateIntervalSeconds": nil}},
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
