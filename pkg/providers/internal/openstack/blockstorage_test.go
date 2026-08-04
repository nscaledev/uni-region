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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/volumes"
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/volumetypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func TestCreateVolumeUsesRegionIntentAndMetadata(t *testing.T) {
	t.Parallel()

	volume := &unikornv1.Volume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "11111111-1111-1111-1111-111111111111",
		},
		Spec: unikornv1.VolumeSpec{
			VolumeClassID: "fast",
			Size:          resource.MustParse("20Gi"),
		},
	}
	metadata := map[string]string{
		"region:volume_id": volume.Name,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/volumes", r.URL.Path)

		var body map[string]any

		decoder := json.NewDecoder(r.Body)
		decoder.UseNumber()

		if !assert.NoError(t, decoder.Decode(&body)) {
			http.Error(w, "invalid request body", http.StatusBadRequest)

			return
		}

		volumeBody, ok := body["volume"].(map[string]any)
		if !assert.True(t, ok) {
			http.Error(w, "missing volume body", http.StatusBadRequest)

			return
		}

		assert.Equal(t, "volume-"+volume.Name, volumeBody["name"])
		assert.Equal(t, json.Number("20"), volumeBody["size"])
		assert.Equal(t, volume.Spec.VolumeClassID, volumeBody["volume_type"])
		assert.Equal(t, map[string]any{
			"region:volume_id": volume.Name,
		}, volumeBody["metadata"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)

		fmt.Fprintf(w, `{"volume":{"id":"provider-id","name":"volume-%s"}}`, volume.Name)
	}))
	t.Cleanup(srv.Close)

	client := openstack.NewTestBlockStorageClient(srv.URL+"/", nil)

	result, err := client.CreateVolume(t.Context(), volume, metadata)
	require.NoError(t, err)
	require.Equal(t, "provider-id", result.ID)
}

func TestDeleteVolumeUsesProviderID(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/volumes/provider-id", r.URL.Path)

		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	client := openstack.NewTestBlockStorageClient(srv.URL+"/", nil)

	require.NoError(t, client.DeleteVolume(t.Context(), "provider-id"))
}

func TestGetVolumeUsesStableNameAndExactMatch(t *testing.T) {
	t.Parallel()

	volume := &unikornv1.Volume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "11111111-1111-1111-1111-111111111111",
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/volumes/detail", r.URL.Path)
		assert.Equal(t, "volume-"+volume.Name, r.URL.Query().Get("name"))

		w.Header().Set("Content-Type", "application/json")

		fmt.Fprintf(w, `{"volumes":[
			{"id":"prefix","name":"volume-%s-extra"},
			{"id":"exact","name":"volume-%s"}
		]}`, volume.Name, volume.Name)
	}))
	t.Cleanup(srv.Close)

	client := openstack.NewTestBlockStorageClient(srv.URL+"/", nil)

	result, err := client.GetVolume(t.Context(), volume)
	require.NoError(t, err)
	require.Equal(t, &volumes.Volume{
		ID:   "exact",
		Name: "volume-" + volume.Name,
	}, result)
}

func TestGetVolumeReturnsResourceNotFound(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		fmt.Fprint(w, `{"volumes":[]}`)
	}))
	t.Cleanup(srv.Close)

	client := openstack.NewTestBlockStorageClient(srv.URL+"/", nil)
	volume := &unikornv1.Volume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "11111111-1111-1111-1111-111111111111",
		},
	}

	result, err := client.GetVolume(t.Context(), volume)
	require.Nil(t, result)
	require.ErrorIs(t, err, coreerrors.ErrResourceNotFound)
}

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

func TestProviderVolumeClassesAppliesFailClosedSelectorAndReusesBlockStorageClientCache(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		blockStorage *unikornv1.RegionOpenstackBlockStorageSpec
		expected     types.VolumeClassList
	}{
		{
			name:         "WithoutBlockStorageConfig",
			blockStorage: nil,
			expected:     types.VolumeClassList{},
		},
		{
			name:         "WithoutVolumeClassesConfig",
			blockStorage: &unikornv1.RegionOpenstackBlockStorageSpec{},
			expected:     types.VolumeClassList{},
		},
		{
			name: "WithoutSelector",
			blockStorage: &unikornv1.RegionOpenstackBlockStorageSpec{
				VolumeClasses: &unikornv1.OpenstackVolumeClassesSpec{},
			},
			expected: types.VolumeClassList{},
		},
		{
			name: "WithNilSelectorIDs",
			blockStorage: &unikornv1.RegionOpenstackBlockStorageSpec{
				VolumeClasses: &unikornv1.OpenstackVolumeClassesSpec{
					Selector: &unikornv1.VolumeClassSelector{},
				},
			},
			expected: types.VolumeClassList{},
		},
		{
			name: "WithEmptySelectorIDs",
			blockStorage: &unikornv1.RegionOpenstackBlockStorageSpec{
				VolumeClasses: &unikornv1.OpenstackVolumeClassesSpec{
					Selector: &unikornv1.VolumeClassSelector{
						IDs: []string{},
					},
				},
			},
			expected: types.VolumeClassList{},
		},
		{
			name: "WithUnmatchedSelectorIDs",
			blockStorage: &unikornv1.RegionOpenstackBlockStorageSpec{
				VolumeClasses: &unikornv1.OpenstackVolumeClassesSpec{
					Selector: &unikornv1.VolumeClassSelector{
						IDs: []string{"unmatched"},
					},
				},
			},
			expected: types.VolumeClassList{},
		},
		{
			name: "WithExplicitSelectorIDs",
			blockStorage: &unikornv1.RegionOpenstackBlockStorageSpec{
				VolumeClasses: &unikornv1.OpenstackVolumeClassesSpec{
					Selector: &unikornv1.VolumeClassSelector{
						IDs: []string{"fast"},
					},
				},
			},
			expected: types.VolumeClassList{
				{
					ID:          "fast",
					Name:        "fast-nvme",
					Description: "Latency sensitive",
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

			require.Equal(t, test.expected, first)
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
