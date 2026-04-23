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
	unikorncoreclient "github.com/unikorn-cloud/core/pkg/client"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers/internal/simulated"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newProvider(t *testing.T, objects ...client.Object) *simulated.Provider {
	t.Helper()

	scheme, err := unikorncoreclient.NewScheme(unikornv1.AddToScheme)
	require.NoError(t, err)

	providerClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

	provider, err := simulated.New(t.Context(), providerClient, &unikornv1.Region{
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

func networkFixture(t *testing.T, name, cidr string) *unikornv1.Network {
	t.Helper()

	_, prefix, err := net.ParseCIDR(cidr)
	require.NoError(t, err)

	return &unikornv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: unikornv1.NetworkSpec{
			Prefix: &unikornv1core.IPv4Prefix{
				IPNet: *prefix,
			},
		},
	}
}

func loadBalancerFixture(name string) *unikornv1.LoadBalancer {
	return &unikornv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels: map[string]string{
				constants.NetworkLabel: "test-network",
			},
		},
	}
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

func TestCreateLoadBalancerRequestedVIPPassthrough(t *testing.T) {
	t.Parallel()

	provider := newProvider(t)
	requestedVIP := &unikornv1core.IPv4Address{IP: net.ParseIP("10.32.0.50").To4()}
	loadBalancer := loadBalancerFixture("loadbalancer-requested")
	loadBalancer.Spec.RequestedVIPAddress = requestedVIP

	require.NoError(t, provider.CreateLoadBalancer(t.Context(), &unikornv1.Identity{}, loadBalancer))
	require.NotNil(t, loadBalancer.Status.VIPAddress)
	require.Equal(t, "10.32.0.50", loadBalancer.Status.VIPAddress.String())

	require.NoError(t, provider.CreateLoadBalancer(t.Context(), &unikornv1.Identity{}, loadBalancer))
	require.NotNil(t, loadBalancer.Status.VIPAddress)
	require.Equal(t, "10.32.0.50", loadBalancer.Status.VIPAddress.String())
}

func TestCreateLoadBalancerDerivedVIPDeterministic(t *testing.T) {
	t.Parallel()

	network := networkFixture(t, "test-network", "10.32.0.0/24")
	provider := newProvider(t, network)
	loadBalancer := loadBalancerFixture("loadbalancer-derived")

	require.NoError(t, provider.CreateLoadBalancer(t.Context(), &unikornv1.Identity{}, loadBalancer))
	require.NotNil(t, loadBalancer.Status.VIPAddress)
	require.Equal(t, "10.32.0.91", loadBalancer.Status.VIPAddress.String())
	require.True(t, network.Spec.Prefix.Contains(loadBalancer.Status.VIPAddress.IP))

	firstVIP := loadBalancer.Status.VIPAddress.String()

	require.NoError(t, provider.CreateLoadBalancer(t.Context(), &unikornv1.Identity{}, loadBalancer))
	require.NotNil(t, loadBalancer.Status.VIPAddress)
	require.Equal(t, firstVIP, loadBalancer.Status.VIPAddress.String())
}

func TestCreateLoadBalancerPublicIPDeterministic(t *testing.T) {
	t.Parallel()

	network := networkFixture(t, "test-network", "10.32.0.0/24")
	provider := newProvider(t, network)
	loadBalancer := loadBalancerFixture("loadbalancer-public")
	loadBalancer.Spec.PublicIP = true

	require.NoError(t, provider.CreateLoadBalancer(t.Context(), &unikornv1.Identity{}, loadBalancer))
	require.NotNil(t, loadBalancer.Status.PublicIP)
	require.Equal(t, "198.51.100.108", loadBalancer.Status.PublicIP.String())

	documentationPrefix := net.IPNet{
		IP:   net.IPv4(198, 51, 100, 0).To4(),
		Mask: net.CIDRMask(24, 32),
	}
	require.True(t, documentationPrefix.Contains(loadBalancer.Status.PublicIP.IP))

	firstPublicIP := loadBalancer.Status.PublicIP.String()

	require.NoError(t, provider.CreateLoadBalancer(t.Context(), &unikornv1.Identity{}, loadBalancer))
	require.NotNil(t, loadBalancer.Status.PublicIP)
	require.Equal(t, firstPublicIP, loadBalancer.Status.PublicIP.String())
}

func TestCreateLoadBalancerPublicIPDisabled(t *testing.T) {
	t.Parallel()

	network := networkFixture(t, "test-network", "10.32.0.0/24")
	provider := newProvider(t, network)
	loadBalancer := loadBalancerFixture("loadbalancer-private")
	loadBalancer.Status.PublicIP = &unikornv1core.IPv4Address{IP: net.ParseIP("198.51.100.99").To4()}

	require.NoError(t, provider.CreateLoadBalancer(t.Context(), &unikornv1.Identity{}, loadBalancer))
	require.Nil(t, loadBalancer.Status.PublicIP)
}

func TestDeleteLoadBalancerIdempotent(t *testing.T) {
	t.Parallel()

	provider := newProvider(t)
	loadBalancer := loadBalancerFixture("loadbalancer-delete")
	loadBalancer.Status.VIPAddress = &unikornv1core.IPv4Address{IP: net.ParseIP("10.32.0.60").To4()}
	loadBalancer.Status.PublicIP = &unikornv1core.IPv4Address{IP: net.ParseIP("198.51.100.60").To4()}

	require.NoError(t, provider.DeleteLoadBalancer(t.Context(), &unikornv1.Identity{}, loadBalancer))
	require.Equal(t, "10.32.0.60", loadBalancer.Status.VIPAddress.String())
	require.Equal(t, "198.51.100.60", loadBalancer.Status.PublicIP.String())

	require.NoError(t, provider.DeleteLoadBalancer(t.Context(), &unikornv1.Identity{}, loadBalancer))
	require.Equal(t, "10.32.0.60", loadBalancer.Status.VIPAddress.String())
	require.Equal(t, "198.51.100.60", loadBalancer.Status.PublicIP.String())
}

func TestCreateLoadBalancerFailsWhenNetworkMissing(t *testing.T) {
	t.Parallel()

	provider := newProvider(t)
	loadBalancer := loadBalancerFixture("loadbalancer-missing-network")

	err := provider.CreateLoadBalancer(t.Context(), &unikornv1.Identity{}, loadBalancer)
	require.Error(t, err)
	require.Nil(t, loadBalancer.Status.VIPAddress)
}

func ptrTo[T any](v T) *T {
	return &v
}
