/*
Copyright 2025 the Unikorn Authors.

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
	"net"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/floatingips"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	corev1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers/openstack"
	"github.com/unikorn-cloud/region/pkg/providers/openstack/mock"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestImageFiltering checks that when filtering images we only get those
// that are public or scoped to the organization.
func TestImageFiltering(t *testing.T) {
	t.Parallel()

	public1 := *imageFixtureWithID("foo")
	public2 := *imageFixtureWithID("foo")
	private1 := *withOrganizationID(imageFixtureWithID("felix"), "cats")
	private2 := *withOrganizationID(imageFixtureWithID("rover"), "dogs")

	images := []images.Image{
		public1,
		public2,
		private1,
		private2,
	}

	images = openstack.GetPublicOrOrganizationOwnedImages(images, "cats")
	require.Len(t, images, 3)
	require.Contains(t, images, public1)
	require.Contains(t, images, public2)
	require.Contains(t, images, private1)
	require.NotContains(t, images, private2)
}

// TestGatewayIP tests we allocate .1 as the gateway so we can set the DHCP
// range in relative safety.
func TestGatewayIP(t *testing.T) {
	t.Parallel()

	prefix := net.IPNet{
		IP:   net.IP{192, 168, 10, 0},
		Mask: net.IPMask{255, 255, 255, 0},
	}

	gateway := openstack.GatewayIP(prefix)
	require.Equal(t, "192.168.10.1", gateway)
}

// TestDHCPRange checks that the DHCP range function correctly removes a /25
// from the end of the provided prefix.
func TestDHCPRange(t *testing.T) {
	t.Parallel()

	prefix := net.IPNet{
		IP:   net.IP{192, 168, 10, 0},
		Mask: net.IPMask{255, 255, 255, 0},
	}

	start, end := openstack.DHCPRange(prefix)
	require.Equal(t, "192.168.10.2", start)
	require.Equal(t, "192.168.10.127", end)
}

// TestStorageRange checks that the DHCP range function correctly starting at
// the top /25 and ending before the broadcast address.
func TestStorageRange(t *testing.T) {
	t.Parallel()

	prefix := net.IPNet{
		IP:   net.IP{192, 168, 10, 0},
		Mask: net.IPMask{255, 255, 255, 0},
	}

	start, end := openstack.StorageRange(prefix)
	require.Equal(t, "192.168.10.128", start)
	require.Equal(t, "192.168.10.254", end)
}

const (
	organizationID  = "spectre"
	projectID       = "manhattan"
	regionID        = "africa"
	identityID      = "1792e5ca-5127-4a16-bfb6-bb8a309d0688"
	networkID       = "ae699252-5356-4824-be96-1d09d84dc033"
	securityGroupID = "35f467b2-badd-4437-8e2a-645ad25f997b"
	serverID        = "21fb10d9-e319-424c-bfd2-ec43526c179e"
	serverName      = "server-abcdef"
	sshKeyName      = "skeleton"
)

// regionFixture creates a region definition.
func regionFixture() *regionv1.Region {
	return &regionv1.Region{
		Spec: regionv1.RegionSpec{
			Openstack: &regionv1.RegionOpenstackSpec{},
		},
	}
}

// networkFixture creates a basic network definition.
func networkFixture() *regionv1.Network {
	return &regionv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name: networkID,
		},
		Spec: regionv1.NetworkSpec{
			Prefix: &corev1.IPv4Prefix{
				IPNet: net.IPNet{
					IP:   net.IP{192, 168, 0, 0},
					Mask: net.IPMask{255, 255, 255, 0},
				},
			},
			DNSNameservers: []corev1.IPv4Address{
				{
					IP: net.IP{8, 8, 4, 4},
				},
			},
		},
	}
}

// networkMatcher is used to check mock function call parameters, as the object
// may have been copied, and it may have been mutated.
func networkMatcher() gomock.Matcher {
	return gomock.Cond(func(x *regionv1.Network) bool {
		return x.Name == networkID
	})
}

// securityGroupFixture creates a basic security group definition.
func securityGroupFixture() *regionv1.SecurityGroup {
	return &regionv1.SecurityGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: securityGroupID,
		},
		Spec: regionv1.SecurityGroupSpec{
			Rules: []regionv1.SecurityGroupRule{
				{
					Direction: regionv1.Ingress,
					Protocol:  regionv1.TCP,
					Port: regionv1.SecurityGroupRulePort{
						Number: ptr.To(22),
					},
					CIDR: &corev1.IPv4Prefix{
						IPNet: net.IPNet{
							IP:   net.IP{172, 16, 0, 0},
							Mask: net.IPMask{255, 240, 0, 0},
						},
					},
				},
			},
		},
	}
}

// securityGroupMatcher is used to check mock function call parameters, as the object
// may have been copied, and it may have been mutated.
func securityGroupMatcher() gomock.Matcher {
	return gomock.Cond(func(x *regionv1.SecurityGroup) bool {
		return x.Name == securityGroupID
	})
}

// withFloatingIP allows a server to have a floating IP set.
func withFloatingIP(s *regionv1.Server) {
	s.Spec.PublicIPAllocation = &regionv1.ServerPublicIPAllocationSpec{
		Enabled: true,
	}
}

// serverFixture creates a basic server definition.
func serverFixture(opts ...func(*regionv1.Server)) *regionv1.Server {
	s := &regionv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Name: serverID,
			Labels: map[string]string{
				coreconstants.NameLabel:         serverName,
				coreconstants.OrganizationLabel: organizationID,
				coreconstants.ProjectLabel:      projectID,
				constants.RegionLabel:           regionID,
			},
		},
		Spec: regionv1.ServerSpec{
			Networks: []regionv1.ServerNetworkSpec{
				{
					ID: networkID,
				},
			},
			SecurityGroups: []regionv1.ServerSecurityGroupSpec{
				{
					ID: securityGroupID,
				},
			},
		},
	}

	for _, o := range opts {
		o(s)
	}

	return s
}

// getClient is a terse way to create a Kubernetes client.
func getClient(t *testing.T, objects []client.Object) client.Client {
	t.Helper()

	scheme, err := coreclient.NewScheme(regionv1.AddToScheme)
	require.NoError(t, err)

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

// TestCreateNetwork tests a resource is created when one isn't present.
func TestCreateNetwork(t *testing.T) {
	t.Parallel()

	client := getClient(t, nil)

	c := gomock.NewController(t)
	defer c.Finish()

	network := networkFixture()

	networking := mock.NewMockNetworkInterface(c)
	networking.EXPECT().GetNetwork(t.Context(), network).Return(nil, openstack.ErrNotFound)
	networking.EXPECT().CreateNetwork(t.Context(), network, nil).Return(nil, nil)

	p := openstack.NewTestProvider(client, regionFixture())

	_, err := openstack.ReconcileNetwork(t.Context(), p, networking, network)
	require.NoError(t, err)
}

// TestCreateSubnet tests a resource is created when one isn't present.
func TestCreateSubnet(t *testing.T) {
	t.Parallel()

	client := getClient(t, nil)

	c := gomock.NewController(t)
	defer c.Finish()

	network := networkFixture()

	openstackNetwork := &networks.Network{
		ID: "foo",
	}

	allocationPools := []subnets.AllocationPool{
		{
			Start: "192.168.0.2",
			End:   "192.168.0.127",
		},
	}

	networking := mock.NewMockSubnetInterface(c)
	networking.EXPECT().GetSubnet(t.Context(), network).Return(nil, openstack.ErrNotFound)
	networking.EXPECT().CreateSubnet(t.Context(), network, "foo", "192.168.0.0/24", gomock.Any(), []string{"8.8.4.4"}, allocationPools).Return(nil, nil)

	p := openstack.NewTestProvider(client, regionFixture())

	_, err := openstack.ReconcileSubnet(t.Context(), p, networking, network, openstackNetwork)
	require.NoError(t, err)
}

// TestCreateRouter tests a resource is created when one isn't present.
func TestCreateRouter(t *testing.T) {
	t.Parallel()

	client := getClient(t, nil)

	c := gomock.NewController(t)
	defer c.Finish()

	network := networkFixture()

	networking := mock.NewMockRouterInterface(c)
	networking.EXPECT().GetRouter(t.Context(), network).Return(nil, openstack.ErrNotFound)
	networking.EXPECT().CreateRouter(t.Context(), network).Return(nil, nil)

	p := openstack.NewTestProvider(client, regionFixture())

	_, err := openstack.ReconcileRouter(t.Context(), p, networking, network)
	require.NoError(t, err)
}

// TestCreateRouterInterface tests a resource is created when one isn't present.
func TestCreateRouterInterface(t *testing.T) {
	t.Parallel()

	client := getClient(t, nil)

	c := gomock.NewController(t)
	defer c.Finish()

	router := &routers.Router{
		ID: "foo",
	}

	subnet := &subnets.Subnet{
		ID: "bar",
	}

	networking := mock.NewMockNetworkingInterface(c)
	networking.EXPECT().ListRouterPorts(t.Context(), "foo").Return([]ports.Port{}, nil)
	networking.EXPECT().AddRouterInterface(t.Context(), "foo", "bar").Return(nil)

	p := openstack.NewTestProvider(client, regionFixture())

	require.NoError(t, openstack.ReconcileRouterInterface(t.Context(), p, networking, router, subnet))
}

// TestCreateSecurityGroup tests a resource is created when one isn't present.
func TestCreateSecurityGroup(t *testing.T) {
	t.Parallel()

	client := getClient(t, nil)

	c := gomock.NewController(t)
	defer c.Finish()

	securityGroup := securityGroupFixture()

	networking := mock.NewMockSecurityGroupInterface(c)
	networking.EXPECT().GetSecurityGroup(t.Context(), securityGroup).Return(nil, openstack.ErrNotFound)
	networking.EXPECT().CreateSecurityGroup(t.Context(), securityGroup).Return(nil, nil)

	p := openstack.NewTestProvider(client, regionFixture())

	_, err := openstack.ReconcileSecurityGroup(t.Context(), p, networking, securityGroup)
	require.NoError(t, err)
}

// TestCreateSecurityGroupRules tests a resource is created when one isn't present.
func TestCreateSecurityGroupRules(t *testing.T) {
	t.Parallel()

	client := getClient(t, nil)

	c := gomock.NewController(t)
	defer c.Finish()

	securityGroup := securityGroupFixture()

	openstackSecurityGroup := &groups.SecGroup{
		ID: "foo",
	}

	openstackSecurityGroupRules := []rules.SecGroupRule{
		{
			Direction: "egress",
		},
	}

	networking := mock.NewMockSecurityGroupInterface(c)
	networking.EXPECT().ListSecurityGroupRules(t.Context(), "foo").Return(openstackSecurityGroupRules, nil)
	networking.EXPECT().CreateSecurityGroupRule(t.Context(), "foo", rules.DirIngress, rules.ProtocolTCP, 22, 22, "172.16.0.0/12").Return(nil, nil)

	p := openstack.NewTestProvider(client, regionFixture())

	require.NoError(t, openstack.ReconcileSecurityGroupRules(t.Context(), p, networking, securityGroup, openstackSecurityGroup))
}

// TestCreateServerPort tests a resource is created when one isn't present.
func TestCreateServerPort(t *testing.T) {
	t.Parallel()

	network := networkFixture()
	securityGroup := securityGroupFixture()

	objects := []client.Object{
		network,
		securityGroup,
	}

	client := getClient(t, objects)

	c := gomock.NewController(t)
	defer c.Finish()

	server := serverFixture()

	openstackNetwork := &openstack.NetworkExt{
		Network: networks.Network{
			ID: "foo",
		},
	}

	openstackSecurityGroup := &groups.SecGroup{
		ID: "bar",
	}

	networking := mock.NewMockNetworkingInterface(c)
	networking.EXPECT().GetNetwork(t.Context(), networkMatcher()).Return(openstackNetwork, nil)
	networking.EXPECT().GetSecurityGroup(t.Context(), securityGroupMatcher()).Return(openstackSecurityGroup, nil)
	networking.EXPECT().GetPort(t.Context(), serverID).Return(nil, openstack.ErrNotFound)
	networking.EXPECT().CreatePort(t.Context(), "foo", serverID, []string{"bar"}, []ports.AddressPair{}).Return(nil, nil)

	p := openstack.NewTestProvider(client, regionFixture())

	_, err := openstack.ReconcileServerPort(t.Context(), p, networking, server)
	require.NoError(t, err)
}

// TestCreateFloatingIP tests a resource is created when one isn't present.
func TestCreateFloatingIP(t *testing.T) {
	t.Parallel()

	client := getClient(t, nil)

	c := gomock.NewController(t)
	defer c.Finish()

	server := serverFixture(withFloatingIP)

	openstackPort := &ports.Port{
		ID: "foo",
	}

	openstackFloatingIP := &floatingips.FloatingIP{
		FloatingIP: "192.168.0.42",
	}

	networking := mock.NewMockFloatingIPInterface(c)
	networking.EXPECT().GetFloatingIP(t.Context(), "foo").Return(nil, openstack.ErrNotFound)
	networking.EXPECT().CreateFloatingIP(t.Context(), "foo").Return(openstackFloatingIP, nil)

	p := openstack.NewTestProvider(client, regionFixture())

	require.NoError(t, openstack.ReconcileFloatingIP(t.Context(), p, networking, server, openstackPort))
	require.NotNil(t, server.Status.PublicIP)
	require.Equal(t, "192.168.0.42", *server.Status.PublicIP)
}

// TestCreateServer tests a resource is created when one isn't present.
func TestCreateServer(t *testing.T) {
	t.Parallel()

	client := getClient(t, nil)

	c := gomock.NewController(t)
	defer c.Finish()

	server := serverFixture(withFloatingIP)

	openstackPort := &ports.Port{
		ID:        "foo",
		NetworkID: networkID,
	}

	openstackNetworks := []servers.Network{
		{
			UUID: networkID,
			Port: "foo",
		},
	}

	metadata := map[string]string{
		"serverID":       serverID,
		"organizationID": organizationID,
		"projectID":      projectID,
		"regionID":       regionID,
	}

	openstackServer := &servers.Server{}

	compute := mock.NewMockServerInterface(c)
	compute.EXPECT().GetServer(t.Context(), server).Return(nil, openstack.ErrNotFound)
	compute.EXPECT().CreateServer(t.Context(), server, sshKeyName, openstackNetworks, nil, metadata).Return(openstackServer, nil)

	p := openstack.NewTestProvider(client, regionFixture())

	_, err := openstack.ReconcileServer(t.Context(), p, compute, server, openstackPort, sshKeyName)
	require.NoError(t, err)
}
