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
	"testing"

	"github.com/stretchr/testify/require"

	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestVolumeClaimRefValidation(t *testing.T) {
	t.Parallel()

	const serverID = "66666666-6666-4666-a666-666666666666"

	validClaimRef := &regionv1.VolumeClaimRef{
		Kind: regionv1.VolumeClaimKindServer,
		ID:   serverID,
	}

	cases := []struct {
		name  string
		obj   func(*testing.T) map[string]any
		valid bool
	}{
		{
			name: "omitted claim ref is available for claiming",
			obj: func(t *testing.T) map[string]any {
				t.Helper()

				return toUnstructured(t, volumeWithClaimRef(nil))
			},
			valid: true,
		},
		{
			name: "server claim ref is accepted",
			obj: func(t *testing.T) map[string]any {
				t.Helper()

				return toUnstructured(t, volumeWithClaimRef(validClaimRef))
			},
			valid: true,
		},
		{
			name: "unknown claim kind is rejected",
			obj: func(t *testing.T) map[string]any {
				t.Helper()

				return toUnstructured(t, volumeWithClaimRef(&regionv1.VolumeClaimRef{
					Kind: regionv1.VolumeClaimKind("Instance"),
					ID:   serverID,
				}))
			},
		},
		{
			name: "claim ref without kind is rejected",
			obj: func(t *testing.T) map[string]any {
				t.Helper()

				obj := toUnstructured(t, volumeWithClaimRef(validClaimRef))
				delete(volumeClaimRefObject(t, obj), "kind")

				return obj
			},
		},
		{
			name: "claim ref without id is rejected",
			obj: func(t *testing.T) map[string]any {
				t.Helper()

				obj := toUnstructured(t, volumeWithClaimRef(validClaimRef))
				delete(volumeClaimRefObject(t, obj), "id")

				return obj
			},
		},
		{
			name: "legacy serverID claim ref shape is rejected",
			obj: func(t *testing.T) map[string]any {
				t.Helper()

				obj := toUnstructured(t, volumeWithClaimRef(nil))
				volumeSpecObject(t, obj)["claimRef"] = map[string]any{
					"serverID": serverID,
				}

				return obj
			},
		},
	}

	validator := newCRDValidator(t, volumeCRDFile)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.valid, validator.validatesUnstructured(t, tc.obj(t)))
		})
	}
}

func volumeWithClaimRef(claimRef *regionv1.VolumeClaimRef) *regionv1.Volume {
	return &regionv1.Volume{
		TypeMeta: metav1.TypeMeta{
			APIVersion: regionv1.Group,
			Kind:       "Volume",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "volume",
			Namespace: "default",
		},
		Spec: regionv1.VolumeSpec{
			NetworkID:     "55555555-5555-4555-a555-555555555555",
			VolumeName:    "database",
			VolumeClassID: "performance",
			Size:          resource.MustParse("1Gi"),
			ClaimRef:      claimRef,
		},
	}
}

func volumeSpecObject(t *testing.T, obj map[string]any) map[string]any {
	t.Helper()

	spec, ok := obj["spec"].(map[string]any)
	require.True(t, ok)

	return spec
}

func volumeClaimRefObject(t *testing.T, obj map[string]any) map[string]any {
	t.Helper()

	claimRef, ok := volumeSpecObject(t, obj)["claimRef"].(map[string]any)
	require.True(t, ok)

	return claimRef
}
