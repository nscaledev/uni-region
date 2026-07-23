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

package openstack_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/volumetypes"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func TestGetVolumeTypesAppliesSelectorVisibilityAndCache(t *testing.T) {
	t.Parallel()

	var (
		requests           int
		gotMethod, gotPath string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path

		if r.Method != http.MethodGet || r.URL.Path != "/types" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}

		requests++

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		fmt.Fprint(w, `{"volume_types":[
			{
				"id":"slow",
				"name":"slow-hdd",
				"description":"Bulk capacity",
				"is_public":true,
				"os-volume-type-access:is_public":true
			},
			{
				"id":"fast",
				"name":"fast-nvme",
				"description":"Latency sensitive",
				"is_public":true,
				"os-volume-type-access:is_public":true
			},
			{
				"id":"private",
				"name":"private-nvme",
				"description":"Provider internal",
				"is_public":false,
				"os-volume-type-access:is_public":false
			}
		]}`)
	}))
	t.Cleanup(srv.Close)

	client := openstack.NewTestBlockStorageClient(srv.URL+"/", &unikornv1.RegionOpenstackBlockStorageSpec{
		VolumeClasses: &unikornv1.OpenstackVolumeClassesSpec{
			Selector: &unikornv1.VolumeClassSelector{
				IDs: []string{"fast", "private"},
			},
		},
	})

	first, err := client.GetVolumeTypes(t.Context())
	require.NoError(t, err)

	second, err := client.GetVolumeTypes(t.Context())
	require.NoError(t, err)

	require.Equal(t, http.MethodGet, gotMethod)
	require.Equal(t, "/types", gotPath)
	require.Equal(t, []volumetypes.VolumeType{
		{
			ID:           "fast",
			Name:         "fast-nvme",
			Description:  "Latency sensitive",
			IsPublic:     true,
			PublicAccess: true,
		},
	}, first)
	require.Equal(t, first, second)
	require.Equal(t, 1, requests)
}

func TestProviderVolumeClassesReusesBlockStorageClientCacheWithDefaultSelector(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		blockStorage *unikornv1.RegionOpenstackBlockStorageSpec
	}{
		{
			name:         "WithoutVolumeClassesConfig",
			blockStorage: &unikornv1.RegionOpenstackBlockStorageSpec{},
		},
		{
			name: "WithEmptySelector",
			blockStorage: &unikornv1.RegionOpenstackBlockStorageSpec{
				VolumeClasses: &unikornv1.OpenstackVolumeClassesSpec{
					Selector: &unikornv1.VolumeClassSelector{},
				},
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ks := newFakeOpenstack(t)

			region := &unikornv1.Region{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-region",
					Namespace: "default",
				},
				Spec: unikornv1.RegionSpec{
					Openstack: &unikornv1.RegionOpenstackSpec{
						Endpoint: ks.ts.URL,
						ServiceAccountSecret: &unikornv1.NamespacedObject{
							Name:      "test-secret",
							Namespace: "default",
						},
						BlockStorage: test.blockStorage,
					},
				},
			}

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"domain-id":  []byte("domain"),
					"user-id":    []byte("user"),
					"password":   []byte("password"),
					"project-id": []byte("project"),
				},
			}

			client := newRaceTestClient(t, region, secret)
			provider := openstack.NewTestProvider(client, region)

			first, err := provider.VolumeClasses(t.Context())
			require.NoError(t, err)

			second, err := provider.VolumeClasses(t.Context())
			require.NoError(t, err)

			require.Equal(t, types.VolumeClassList{
				{
					ID:          "slow",
					Name:        "slow-hdd",
					Description: "Bulk capacity",
				},
				{
					ID:          "fast",
					Name:        "fast-nvme",
					Description: "Latency sensitive",
				},
			}, first)
			require.Equal(t, first, second)
			require.Equal(t, int64(1), ks.volumeTypeRequests.Load())
		})
	}
}

func TestConvertVolumeClassesAppliesMetadata(t *testing.T) {
	t.Parallel()

	region := &unikornv1.Region{
		Spec: unikornv1.RegionSpec{
			Openstack: &unikornv1.RegionOpenstackSpec{
				BlockStorage: &unikornv1.RegionOpenstackBlockStorageSpec{
					VolumeClasses: &unikornv1.OpenstackVolumeClassesSpec{
						Metadata: []unikornv1.VolumeClassMetadata{
							{
								ID:    "fast",
								Media: unikornv1.VolumeClassMediaNVMe,
								Performance: &unikornv1.VolumeClassPerformanceSpec{
									MaxIOPS:       ptr.To(25000),
									MaxThroughput: ptr.To(500),
								},
								Encrypted: true,
							},
						},
					},
				},
			},
		},
	}

	in := []volumetypes.VolumeType{
		{
			ID:          "fast",
			Name:        "fast-nvme",
			Description: "Latency sensitive",
		},
	}

	out := openstack.ConvertVolumeClasses(region, in)

	require.Equal(t, types.VolumeClassList{
		{
			ID:          "fast",
			Name:        "fast-nvme",
			Description: "Latency sensitive",
			Media:       types.VolumeClassMediaNVMe,
			Performance: &types.VolumeClassPerformance{
				MaxIOPS:       ptr.To(25000),
				MaxThroughput: ptr.To(500),
			},
			Encrypted: true,
		},
	}, out)
}
