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

package simulated_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/simulated"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newProvider(t *testing.T) *simulated.Provider {
	t.Helper()

	provider, err := simulated.New(t.Context(), nil, &unikornv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "simulated-region",
			Namespace: "default",
		},
		Spec: unikornv1.RegionSpec{
			Provider: unikornv1.ProviderSimulated,
		},
	})
	require.NoError(t, err)

	return provider
}

func TestFlavors(t *testing.T) {
	t.Parallel()

	provider := newProvider(t)

	flavors, err := provider.Flavors(t.Context())
	require.NoError(t, err)
	require.Len(t, flavors, 2)
	require.Equal(t, "sim-standard-4", flavors[0].Name)
	require.Equal(t, "sim-gpu-8", flavors[1].Name)
	require.NotNil(t, flavors[1].GPU)
}

func TestImages(t *testing.T) {
	t.Parallel()

	provider := newProvider(t)

	query, err := provider.QueryImages()
	require.NoError(t, err)

	images, err := query.AvailableToOrganization("org-1").StatusIn(types.ImageStatusReady).List(t.Context())
	require.NoError(t, err)
	require.Len(t, images.Items, 2)

	created, err := provider.CreateImage(t.Context(), &types.Image{
		Name:           "custom-image",
		OrganizationID: ptrTo("org-1"),
		Architecture:   types.X86_64,
		Virtualization: types.Virtualized,
		OS: types.ImageOS{
			Kernel:  types.Linux,
			Family:  types.Debian,
			Distro:  types.Ubuntu,
			Version: "24.04",
		},
	}, "https://example.invalid/image.raw")
	require.NoError(t, err)
	require.Equal(t, types.ImageStatusReady, created.Status)

	query, err = provider.QueryImages()
	require.NoError(t, err)

	owned, err := query.OwnedByOrganization("org-1").List(t.Context())
	require.NoError(t, err)
	require.Len(t, owned.Items, 1)
	require.Equal(t, created.ID, owned.Items[0].ID)

	image, err := provider.GetImage(t.Context(), "org-1", created.ID)
	require.NoError(t, err)
	require.Equal(t, created.ID, image.ID)

	err = provider.DeleteImage(t.Context(), created.ID)
	require.NoError(t, err)

	_, err = provider.GetImage(t.Context(), "org-1", created.ID)
	require.Error(t, err)
}

func TestIdentityLifecycle(t *testing.T) {
	t.Parallel()

	provider := newProvider(t)
	identity := &unikornv1.Identity{}

	require.NoError(t, provider.CreateIdentity(t.Context(), identity))
	require.NoError(t, provider.DeleteIdentity(t.Context(), identity))
}

func TestCreateNetwork(t *testing.T) {
	t.Parallel()

	provider := newProvider(t)
	_, prefix, err := net.ParseCIDR("10.32.0.0/24")
	require.NoError(t, err)

	network := &unikornv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-network",
		},
		Spec: unikornv1.NetworkSpec{
			Prefix: &unikornv1core.IPv4Prefix{
				IPNet: *prefix,
			},
		},
	}

	err = provider.CreateNetwork(t.Context(), &unikornv1.Identity{}, network)
	require.NoError(t, err)
	require.NotNil(t, network.Status.Openstack)
	require.NotNil(t, network.Status.Openstack.NetworkID)
	require.NotNil(t, network.Status.Openstack.SubnetID)
	require.Equal(t, "10.32.0.16", network.Status.Openstack.StorageRange.Start.String())
	require.Equal(t, "10.32.0.127", network.Status.Openstack.StorageRange.End.String())
	require.NoError(t, provider.DeleteNetwork(t.Context(), &unikornv1.Identity{}, network))
}

func ptrTo[T any](v T) *T {
	return &v
}
