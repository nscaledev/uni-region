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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/v2/openstack/placement/v1/resourceproviders"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	openstack "github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack/mock"

	"k8s.io/utils/ptr"
)

type staticPlacementCredentialProvider struct {
	client *gophercloud.ProviderClient
	err    error
}

func (p staticPlacementCredentialProvider) Client(_ context.Context) (*gophercloud.ProviderClient, error) {
	return p.client, p.err
}

func TestNewPlacementClientSetsMicroversion(t *testing.T) {
	t.Parallel()

	providerClient := &gophercloud.ProviderClient{
		EndpointLocator: func(opts gophercloud.EndpointOpts) (string, error) {
			require.Equal(t, "placement", opts.Type)

			return "https://placement.example/v1/", nil
		},
	}

	client, err := openstack.NewPlacementClient(t.Context(), staticPlacementCredentialProvider{client: providerClient})
	require.NoError(t, err)
	require.Equal(t, openstack.PlacementAPIMicroversion, openstack.PlacementClientMicroversion(client))
}

func TestPlacementPreflightRequiredTraits(t *testing.T) {
	t.Parallel()

	require.Empty(t, openstack.PlacementPreflightRequiredTraits(nil))
	require.Empty(t, openstack.PlacementPreflightRequiredTraits(&unikornv1.PlacementPreflightSpec{}))

	traits := openstack.PlacementPreflightRequiredTraits(&unikornv1.PlacementPreflightSpec{
		RequiredTraits: []string{
			" custom_customer_ready ",
			"",
			"CUSTOM_CUSTOMER_READY",
			"hw_cpu_x86_avx",
		},
	})

	require.Equal(t, []string{"CUSTOM_CUSTOMER_READY", "HW_CPU_X86_AVX"}, traits)
	require.Equal(t, "CUSTOM_CUSTOMER_READY,HW_CPU_X86_AVX", openstack.PlacementRequiredTraitsQuery(traits))
}

func TestPlacementResourceQuery(t *testing.T) {
	t.Parallel()

	require.Equal(t, "CUSTOM_GB300_HOST:1", openstack.PlacementResourceQuery("gb300-host"))
	require.Equal(t, "CUSTOM_GB300_HOST:1", openstack.PlacementResourceQuery(" CUSTOM_GB300_HOST "))
}

func TestFlavorPlacementResourceClass(t *testing.T) {
	t.Parallel()

	t.Run("PositiveCustomResource", func(t *testing.T) {
		t.Parallel()

		resourceClass, err := openstack.FlavorPlacementResourceClass(flavors.Flavor{
			ID: "gpu",
			ExtraSpecs: map[string]string{
				"resources:CUSTOM_GB300_HOST": "1",
				"resources:VCPU":              "0",
			},
		})

		require.NoError(t, err)
		require.Equal(t, "CUSTOM_GB300_HOST", resourceClass)
	})

	t.Run("NoCustomResource", func(t *testing.T) {
		t.Parallel()

		_, err := openstack.FlavorPlacementResourceClass(flavors.Flavor{
			ID: "vm",
			ExtraSpecs: map[string]string{
				"resources:VCPU": "1",
			},
		})

		require.ErrorIs(t, err, coreerrors.ErrConsistency)
	})

	t.Run("MultipleCustomResources", func(t *testing.T) {
		t.Parallel()

		_, err := openstack.FlavorPlacementResourceClass(flavors.Flavor{
			ID: "ambiguous",
			ExtraSpecs: map[string]string{
				"resources:CUSTOM_GPU":  "1",
				"resources:CUSTOM_HOST": "1",
			},
		})

		require.ErrorIs(t, err, coreerrors.ErrConsistency)
	})

	t.Run("InvalidAmount", func(t *testing.T) {
		t.Parallel()

		_, err := openstack.FlavorPlacementResourceClass(flavors.Flavor{
			ID: "invalid",
			ExtraSpecs: map[string]string{
				"resources:CUSTOM_GPU": "many",
			},
		})

		require.ErrorIs(t, err, coreerrors.ErrConsistency)
	})
}

func TestServerCreatePlacementPreflight(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{
		Spec: unikornv1.ServerSpec{
			FlavorID:          "flavor-a",
			InfrastructureRef: ptr.To("node-a"),
		},
	}

	t.Run("DisabledSkipsDependencies", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		t.Cleanup(c.Finish)

		preflight := openstack.NewTestServerCreatePlacementPreflight(
			&unikornv1.PlacementPreflightSpec{},
			mock.NewMockFlavorInterface(c),
			mock.NewMockPlacementInterface(c),
		)

		require.NoError(t, preflight(t.Context(), server))
	})

	t.Run("UnpinnedSkipsDependencies", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		t.Cleanup(c.Finish)

		unpinned := server.DeepCopy()
		unpinned.Spec.InfrastructureRef = nil

		preflight := openstack.NewTestServerCreatePlacementPreflight(
			&unikornv1.PlacementPreflightSpec{Enabled: true},
			mock.NewMockFlavorInterface(c),
			mock.NewMockPlacementInterface(c),
		)

		require.NoError(t, preflight(t.Context(), unpinned))
	})

	t.Run("AvailableProviderPasses", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		t.Cleanup(c.Finish)

		flavorClient := mock.NewMockFlavorInterface(c)
		flavorClient.EXPECT().GetFlavors(t.Context()).Return([]flavors.Flavor{
			{
				ID: "flavor-a",
				ExtraSpecs: map[string]string{
					"resources:CUSTOM_GPU": "1",
				},
			},
		}, nil)

		placementClient := mock.NewMockPlacementInterface(c)
		placementClient.EXPECT().ResourceProviderAvailable(t.Context(), openstack.PlacementResourceProviderQuery{
			InfrastructureRef: "node-a",
			ResourceClass:     "CUSTOM_GPU",
			RequiredTraits:    []string{"CUSTOM_READY"},
		}).Return(true, nil)

		preflight := openstack.NewTestServerCreatePlacementPreflight(
			&unikornv1.PlacementPreflightSpec{
				Enabled:        true,
				RequiredTraits: []string{"custom_ready"},
			},
			flavorClient,
			placementClient,
		)

		require.NoError(t, preflight(t.Context(), server))
	})

	t.Run("UnavailableProviderYields", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		t.Cleanup(c.Finish)

		flavorClient := mock.NewMockFlavorInterface(c)
		flavorClient.EXPECT().GetFlavors(t.Context()).Return([]flavors.Flavor{
			{
				ID: "flavor-a",
				ExtraSpecs: map[string]string{
					"resources:CUSTOM_GPU": "1",
				},
			},
		}, nil)

		placementClient := mock.NewMockPlacementInterface(c)
		placementClient.EXPECT().ResourceProviderAvailable(t.Context(), openstack.PlacementResourceProviderQuery{
			InfrastructureRef: "node-a",
			ResourceClass:     "CUSTOM_GPU",
		}).Return(false, nil)

		preflight := openstack.NewTestServerCreatePlacementPreflight(
			&unikornv1.PlacementPreflightSpec{Enabled: true},
			flavorClient,
			placementClient,
		)

		require.ErrorIs(t, preflight(t.Context(), server), provisioners.ErrYield)
	})
}

func TestPlacementClientResourceProviderAvailable(t *testing.T) {
	t.Parallel()

	requests := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++

		if got, want := r.URL.Path, "/resource_providers"; got != want {
			t.Errorf("path = %q, want %q", got, want)
		}

		if got, want := r.URL.Query().Get("resources"), "CUSTOM_GB300_HOST:1"; got != want {
			t.Errorf("resources query = %q, want %q", got, want)
		}

		if got, want := r.URL.Query().Get("required"), "CUSTOM_CUSTOMER_READY,HW_CPU_X86_AVX"; got != want {
			t.Errorf("required query = %q, want %q", got, want)
		}

		if got, want := r.Header.Get("OpenStack-API-Version"), "placement 1.18"; got != want {
			t.Errorf("microversion header = %q, want %q", got, want)
		}

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(map[string][]resourceproviders.ResourceProvider{
			"resource_providers": {
				{UUID: "rp-a", Name: "node-a"},
				{UUID: "rp-b", Name: "node-b"},
			},
		}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	client := openstack.NewTestPlacementClient(server.URL, server.Client())

	available, err := client.ResourceProviderAvailable(t.Context(), openstack.PlacementResourceProviderQuery{
		InfrastructureRef: "node-a",
		ResourceClass:     "gb300-host",
		RequiredTraits:    []string{"custom_customer_ready", "HW_CPU_X86_AVX"},
	})
	require.NoError(t, err)
	require.True(t, available)

	available, err = client.ResourceProviderAvailable(t.Context(), openstack.PlacementResourceProviderQuery{
		InfrastructureRef: "rp-b",
		ResourceClass:     "gb300-host",
		RequiredTraits:    []string{"custom_customer_ready", "HW_CPU_X86_AVX"},
	})
	require.NoError(t, err)
	require.True(t, available)

	available, err = client.ResourceProviderAvailable(t.Context(), openstack.PlacementResourceProviderQuery{
		InfrastructureRef: "missing",
		ResourceClass:     "gb300-host",
		RequiredTraits:    []string{"custom_customer_ready", "HW_CPU_X86_AVX"},
	})
	require.NoError(t, err)
	require.False(t, available)

	require.Equal(t, 3, requests)
}

func TestPlacementClientOmitsEmptyRequiredTraits(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.URL.Query()["required"]; ok {
			t.Errorf("required query present, want omitted")
		}

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(map[string][]resourceproviders.ResourceProvider{
			"resource_providers": {
				{UUID: "rp-a", Name: "node-a"},
			},
		}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	client := openstack.NewTestPlacementClient(server.URL, server.Client())

	available, err := client.ResourceProviderAvailable(t.Context(), openstack.PlacementResourceProviderQuery{
		InfrastructureRef: "node-a",
		ResourceClass:     "CUSTOM_GB300_HOST",
	})
	require.NoError(t, err)
	require.True(t, available)
}
