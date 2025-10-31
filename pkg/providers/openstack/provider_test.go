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
	"k8s.io/apimachinery/pkg/util/uuid"
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
	organizationID = "spectre"
	projectID      = "manhattan"
	regionID       = "africa"
	identityID     = "1792e5ca-5127-4a16-bfb6-bb8a309d0688"
	serverName     = "server-abcdef"
	sshKeyName     = "skeleton"
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
			Name: string(uuid.NewUUID()),
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
		Status: regionv1.NetworkStatus{
			Openstack: &regionv1.NetworkStatusOpenstack{},
		},
	}
}

// networkMatcher is used to check mock function call parameters, as the object
// may have been copied, and it may have been mutated.
func networkMatcher(network *regionv1.Network) gomock.Matcher {
	return gomock.Cond(func(x *regionv1.Network) bool {
		return x.Name == network.Name
	})
}

func openstackNetworkFixture(network *regionv1.Network) *openstack.NetworkExt {
	return &openstack.NetworkExt{
		Network: networks.Network{
			ID:   string(uuid.NewUUID()),
			Name: openstack.NetworkName(network),
		},
	}
}

func openstackSubnetFixture(network *regionv1.Network, openstackNetwork *openstack.NetworkExt) *subnets.Subnet {
	return &subnets.Subnet{
		ID:        string(uuid.NewUUID()),
		Name:      openstack.NetworkName(network),
		NetworkID: openstackNetwork.ID,
	}
}

func openstackRouterFixture(network *regionv1.Network) *routers.Router {
	return &routers.Router{
		ID:   string(uuid.NewUUID()),
		Name: openstack.NetworkName(network),
	}
}

func openstackRouterPortsFixture(openstackRouter *routers.Router, openstackSubnet *subnets.Subnet) []ports.Port {
	return []ports.Port{
		{
			ID:          string(uuid.NewUUID()),
			DeviceOwner: "network:router_interface",
			DeviceID:    openstackRouter.ID,
			FixedIPs: []ports.IP{
				{
					SubnetID: openstackSubnet.ID,
				},
			},
		},
	}
}

func securityGroupRuleFixtureSingle(t *testing.T, dir regionv1.SecurityGroupRuleDirection, proto regionv1.SecurityGroupRuleProtocol, port int, prefix string) regionv1.SecurityGroupRule {
	t.Helper()

	_, cidr, err := net.ParseCIDR(prefix)
	require.NoError(t, err)

	return regionv1.SecurityGroupRule{
		Direction: dir,
		Protocol:  proto,
		Port: regionv1.SecurityGroupRulePort{
			Number: ptr.To(port),
		},
		CIDR: &corev1.IPv4Prefix{
			IPNet: *cidr,
		},
	}
}

// securityGroupFixture creates a basic security group definition.
func securityGroupFixture(rules ...regionv1.SecurityGroupRule) *regionv1.SecurityGroup {
	return &regionv1.SecurityGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: string(uuid.NewUUID()),
		},
		Spec: regionv1.SecurityGroupSpec{
			Rules: rules,
		},
	}
}

// securityGroupMatcher is used to check mock function call parameters, as the object
// may have been copied, and it may have been mutated.
func securityGroupMatcher(securityGroup *regionv1.SecurityGroup) gomock.Matcher {
	return gomock.Cond(func(x *regionv1.SecurityGroup) bool {
		return x.Name == securityGroup.Name
	})
}

func openstackSecurityGroupRuleFixtureSingle(dir rules.RuleDirection, proto rules.RuleProtocol, port int, prefix string) rules.SecGroupRule {
	return rules.SecGroupRule{
		ID:             string(uuid.NewUUID()),
		Direction:      string(dir),
		Protocol:       string(proto),
		PortRangeMin:   port,
		PortRangeMax:   port,
		RemoteIPPrefix: prefix,
	}
}

func openstackSecurityGroupRuleFixtureDefault() rules.SecGroupRule {
	return openstackSecurityGroupRuleFixtureSingle(rules.DirEgress, rules.ProtocolAny, 0, "")
}

func openstackSecurityGroupFixture(securityGroup *regionv1.SecurityGroup, rules ...rules.SecGroupRule) *groups.SecGroup {
	return &groups.SecGroup{
		ID:    string(uuid.NewUUID()),
		Name:  openstack.SecurityGroupName(securityGroup),
		Rules: rules,
	}
}

// withFloatingIP allows a server to have a floating IP set.
func withFloatingIP(s *regionv1.Server) {
	s.Spec.PublicIPAllocation = &regionv1.ServerPublicIPAllocationSpec{
		Enabled: true,
	}
}

func withSecurityGroup(securityGroup *regionv1.SecurityGroup) func(*regionv1.Server) {
	return func(s *regionv1.Server) {
		s.Spec.SecurityGroups = append(s.Spec.SecurityGroups, regionv1.ServerSecurityGroupSpec{
			ID: securityGroup.Name,
		})
	}
}

func withNetwork(network *regionv1.Network) func(*regionv1.Server) {
	return func(s *regionv1.Server) {
		s.Spec.Networks = append(s.Spec.Networks, regionv1.ServerNetworkSpec{
			ID: network.Name,
		})
	}
}

// serverFixture creates a basic server definition.
func serverFixture(opts ...func(*regionv1.Server)) *regionv1.Server {
	s := &regionv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Name: string(uuid.NewUUID()),
			Labels: map[string]string{
				coreconstants.NameLabel:         serverName,
				coreconstants.OrganizationLabel: organizationID,
				coreconstants.ProjectLabel:      projectID,
				constants.RegionLabel:           regionID,
			},
		},
	}

	for _, o := range opts {
		o(s)
	}

	return s
}

const serverPortIP = "192.168.0.42"

func openstackServerPortFixture(server *regionv1.Server, openstackNetwork *openstack.NetworkExt, openstackSubnet *subnets.Subnet) *ports.Port {
	return &ports.Port{
		ID:          string(uuid.NewUUID()),
		Name:        openstack.ServerName(server),
		DeviceOwner: "compute:nova",
		NetworkID:   openstackNetwork.ID,
		FixedIPs: []ports.IP{
			{
				SubnetID:  openstackSubnet.ID,
				IPAddress: serverPortIP,
			},
		},
	}
}

func openstackFloatingIPFixture(port *ports.Port) *floatingips.FloatingIP {
	return &floatingips.FloatingIP{
		ID:         string(uuid.NewUUID()),
		FloatingIP: "12.34.56.78",
		PortID:     port.ID,
	}
}

func openstackServerFixture(server *regionv1.Server) *servers.Server {
	return &servers.Server{
		ID:   string(uuid.NewUUID()),
		Name: server.Labels[coreconstants.NameLabel],
	}
}

// getClient is a terse way to create a Kubernetes client.
func getClient(t *testing.T, objects []client.Object) client.Client {
	t.Helper()

	scheme, err := coreclient.NewScheme(regionv1.AddToScheme)
	require.NoError(t, err)

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

// TestReconcileNetwork tests a resource is created when one isn't present.
func TestReconcileNetwork(t *testing.T) {
	t.Parallel()

	client := getClient(t, nil)

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	network := networkFixture()

	openStackNetwork := openstackNetworkFixture(network)

	t.Run("ItDoesntExist", func(t *testing.T) {
		t.Parallel()

		networking := mock.NewMockNetworkInterface(c)
		networking.EXPECT().GetNetwork(t.Context(), network).Return(nil, openstack.ErrNotFound)
		networking.EXPECT().CreateNetwork(t.Context(), network, nil).Return(openStackNetwork, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileNetwork(t.Context(), p, networking, network)
		require.NoError(t, err)
		require.NotNil(t, network.Status.Openstack.NetworkID)
		require.Equal(t, openStackNetwork.ID, *network.Status.Openstack.NetworkID)
	})

	t.Run("IfExists", func(t *testing.T) {
		t.Parallel()

		networking := mock.NewMockNetworkInterface(c)
		networking.EXPECT().GetNetwork(t.Context(), network).Return(openStackNetwork, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileNetwork(t.Context(), p, networking, network)
		require.NoError(t, err)
		require.NotNil(t, network.Status.Openstack.NetworkID)
		require.Equal(t, openStackNetwork.ID, *network.Status.Openstack.NetworkID)
	})
}

// TestReconcileSubnet tests a resource is created when one isn't present.
func TestReconcileSubnet(t *testing.T) {
	t.Parallel()

	client := getClient(t, nil)

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	network := networkFixture()

	openstackNetwork := openstackNetworkFixture(network)
	openstackSubnet := openstackSubnetFixture(network, openstackNetwork)

	allocationPools := []subnets.AllocationPool{
		{
			Start: "192.168.0.2",
			End:   "192.168.0.127",
		},
	}

	t.Run("ItDoesntExist", func(t *testing.T) {
		t.Parallel()

		networking := mock.NewMockSubnetInterface(c)
		networking.EXPECT().GetSubnet(t.Context(), network).Return(nil, openstack.ErrNotFound)
		networking.EXPECT().CreateSubnet(t.Context(), network, openstackNetwork.ID, "192.168.0.0/24", gomock.Any(), []string{"8.8.4.4"}, allocationPools).Return(openstackSubnet, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileSubnet(t.Context(), p, networking, network, openstackNetwork)
		require.NoError(t, err)
		require.NotNil(t, network.Status.Openstack.SubnetID)
		require.Equal(t, openstackSubnet.ID, *network.Status.Openstack.SubnetID)
	})

	t.Run("ItExists", func(t *testing.T) {
		t.Parallel()

		networking := mock.NewMockSubnetInterface(c)
		networking.EXPECT().GetSubnet(t.Context(), network).Return(openstackSubnet, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileSubnet(t.Context(), p, networking, network, openstackNetwork)
		require.NoError(t, err)
		require.NotNil(t, network.Status.Openstack.SubnetID)
		require.Equal(t, openstackSubnet.ID, *network.Status.Openstack.SubnetID)
	})
}

// TestReconcileRouter tests a resource is created when one isn't present.
func TestReconcileRouter(t *testing.T) {
	t.Parallel()

	client := getClient(t, nil)

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	network := networkFixture()

	openstackRouter := openstackRouterFixture(network)

	t.Run("ItDoesntExist", func(t *testing.T) {
		t.Parallel()

		networking := mock.NewMockRouterInterface(c)
		networking.EXPECT().GetRouter(t.Context(), network).Return(nil, openstack.ErrNotFound)
		networking.EXPECT().CreateRouter(t.Context(), network).Return(openstackRouter, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileRouter(t.Context(), p, networking, network)
		require.NoError(t, err)
	})

	t.Run("ItExists", func(t *testing.T) {
		t.Parallel()

		networking := mock.NewMockRouterInterface(c)
		networking.EXPECT().GetRouter(t.Context(), network).Return(openstackRouter, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileRouter(t.Context(), p, networking, network)
		require.NoError(t, err)
	})
}

// TestReconcileRouterInterface tests a resource is created when one isn't present.
func TestReconcileRouterInterface(t *testing.T) {
	t.Parallel()

	client := getClient(t, nil)

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	network := networkFixture()

	openstackNetwork := openstackNetworkFixture(network)
	openstackSubnet := openstackSubnetFixture(network, openstackNetwork)
	openstackRouter := openstackRouterFixture(network)
	openstackRouterPorts := openstackRouterPortsFixture(openstackRouter, openstackSubnet)

	t.Run("ItDoesntExist", func(t *testing.T) {
		t.Parallel()

		networking := mock.NewMockNetworkingInterface(c)
		networking.EXPECT().ListRouterPorts(t.Context(), openstackRouter.ID).Return([]ports.Port{}, nil)
		networking.EXPECT().AddRouterInterface(t.Context(), openstackRouter.ID, openstackSubnet.ID).Return(nil)

		p := openstack.NewTestProvider(client, regionFixture())

		require.NoError(t, openstack.ReconcileRouterInterface(t.Context(), p, networking, openstackRouter, openstackSubnet))
	})

	t.Run("ItExists", func(t *testing.T) {
		t.Parallel()

		networking := mock.NewMockNetworkingInterface(c)
		networking.EXPECT().ListRouterPorts(t.Context(), openstackRouter.ID).Return(openstackRouterPorts, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		require.NoError(t, openstack.ReconcileRouterInterface(t.Context(), p, networking, openstackRouter, openstackSubnet))
	})
}

// TestReconcileSecurityGroup tests a resource is created when one isn't present.
func TestReconcileSecurityGroup(t *testing.T) {
	t.Parallel()

	client := getClient(t, nil)

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	securityGroup := securityGroupFixture(
		securityGroupRuleFixtureSingle(t, regionv1.Ingress, regionv1.TCP, 22, "172.16.0.0/12"),
	)

	openstackSecurityGroup := openstackSecurityGroupFixture(securityGroup)

	t.Run("ItDoesntExist", func(t *testing.T) {
		t.Parallel()

		networking := mock.NewMockSecurityGroupInterface(c)
		networking.EXPECT().GetSecurityGroup(t.Context(), securityGroup).Return(nil, openstack.ErrNotFound)
		networking.EXPECT().CreateSecurityGroup(t.Context(), securityGroup).Return(openstackSecurityGroup, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileSecurityGroup(t.Context(), p, networking, securityGroup)
		require.NoError(t, err)
	})

	t.Run("ItExists", func(t *testing.T) {
		t.Parallel()

		networking := mock.NewMockSecurityGroupInterface(c)
		networking.EXPECT().GetSecurityGroup(t.Context(), securityGroup).Return(openstackSecurityGroup, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileSecurityGroup(t.Context(), p, networking, securityGroup)
		require.NoError(t, err)
	})
}

// TestReconcileSecurityGroupRules tests a resource is created when one isn't present.
func TestReconcileSecurityGroupRules(t *testing.T) {
	t.Parallel()

	client := getClient(t, nil)

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	t.Run("ItDoesntExist", func(t *testing.T) {
		t.Parallel()

		securityGroup := securityGroupFixture(
			securityGroupRuleFixtureSingle(t, regionv1.Ingress, regionv1.TCP, 22, "172.16.0.0/12"),
		)

		openstackSecurityGroup := openstackSecurityGroupFixture(securityGroup, openstackSecurityGroupRuleFixtureDefault())

		networking := mock.NewMockSecurityGroupInterface(c)
		networking.EXPECT().ListSecurityGroupRules(t.Context(), openstackSecurityGroup.ID).Return(openstackSecurityGroup.Rules, nil)
		networking.EXPECT().CreateSecurityGroupRule(t.Context(), openstackSecurityGroup.ID, rules.DirIngress, rules.ProtocolTCP, 22, 22, "172.16.0.0/12").Return(nil, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		require.NoError(t, openstack.ReconcileSecurityGroupRules(t.Context(), p, networking, securityGroup, openstackSecurityGroup))
	})

	t.Run("ItExists", func(t *testing.T) {
		t.Parallel()

		securityGroup := securityGroupFixture(
			securityGroupRuleFixtureSingle(t, regionv1.Ingress, regionv1.TCP, 22, "172.16.0.0/12"),
		)

		openstackSecurityGroup := openstackSecurityGroupFixture(securityGroup,
			openstackSecurityGroupRuleFixtureDefault(),
			openstackSecurityGroupRuleFixtureSingle(rules.DirIngress, rules.ProtocolTCP, 22, "172.16.0.0/12"),
		)

		networking := mock.NewMockSecurityGroupInterface(c)
		networking.EXPECT().ListSecurityGroupRules(t.Context(), openstackSecurityGroup.ID).Return(openstackSecurityGroup.Rules, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		require.NoError(t, openstack.ReconcileSecurityGroupRules(t.Context(), p, networking, securityGroup, openstackSecurityGroup))
	})

	t.Run("ItShouldntExist", func(t *testing.T) {
		t.Parallel()

		securityGroup := securityGroupFixture()

		openstackSecurityGroup := openstackSecurityGroupFixture(securityGroup,
			openstackSecurityGroupRuleFixtureDefault(),
			openstackSecurityGroupRuleFixtureSingle(rules.DirIngress, rules.ProtocolTCP, 22, "172.16.0.0/12"),
		)

		networking := mock.NewMockSecurityGroupInterface(c)
		networking.EXPECT().ListSecurityGroupRules(t.Context(), openstackSecurityGroup.ID).Return(openstackSecurityGroup.Rules, nil)
		networking.EXPECT().DeleteSecurityGroupRule(t.Context(), openstackSecurityGroup.ID, openstackSecurityGroup.Rules[1].ID).Return(nil)

		p := openstack.NewTestProvider(client, regionFixture())

		require.NoError(t, openstack.ReconcileSecurityGroupRules(t.Context(), p, networking, securityGroup, openstackSecurityGroup))
	})
}

// TestReconcileServerPort tests a resource is created when one isn't present.
// TODO: allowed address pairs for NFV.
func TestReconcileServerPort(t *testing.T) {
	t.Parallel()

	network := networkFixture()
	securityGroup := securityGroupFixture()
	securityGroup2 := securityGroupFixture()

	objects := []client.Object{
		network,
		securityGroup,
		securityGroup2,
	}

	client := getClient(t, objects)

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	// Must clone me in tests as they will update the status,
	server := serverFixture(withNetwork(network), withSecurityGroup(securityGroup))

	openstackNetwork := openstackNetworkFixture(network)
	openstackSubnet := openstackSubnetFixture(network, openstackNetwork)
	openstackSecurityGroup := openstackSecurityGroupFixture(securityGroup)
	openstackSecurityGroup2 := openstackSecurityGroupFixture(securityGroup2)
	openstackServerPort := openstackServerPortFixture(server, openstackNetwork, openstackSubnet)

	t.Run("ItDoesntExist", func(t *testing.T) {
		t.Parallel()

		server := server.DeepCopy()

		networking := mock.NewMockNetworkingInterface(c)
		networking.EXPECT().GetNetwork(t.Context(), networkMatcher(network)).Return(openstackNetwork, nil)
		networking.EXPECT().GetSecurityGroup(t.Context(), securityGroupMatcher(securityGroup)).Return(openstackSecurityGroup, nil)
		networking.EXPECT().GetServerPort(t.Context(), server).Return(nil, openstack.ErrNotFound)
		networking.EXPECT().CreateServerPort(t.Context(), server, openstackNetwork.ID, []string{openstackSecurityGroup.ID}, []ports.AddressPair{}).Return(openstackServerPort, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileServerPort(t.Context(), p, networking, server)
		require.NoError(t, err)
		require.NotNil(t, server.Status.PrivateIP)
		require.Equal(t, serverPortIP, *server.Status.PrivateIP)
	})

	t.Run("ItExists", func(t *testing.T) {
		t.Parallel()

		server := server.DeepCopy()

		networking := mock.NewMockNetworkingInterface(c)
		networking.EXPECT().GetNetwork(t.Context(), networkMatcher(network)).Return(openstackNetwork, nil)
		networking.EXPECT().GetSecurityGroup(t.Context(), securityGroupMatcher(securityGroup)).Return(openstackSecurityGroup, nil)
		networking.EXPECT().GetServerPort(t.Context(), server).Return(openstackServerPort, nil)
		// TODO: this shouldn't happen as it's not been modified.
		networking.EXPECT().UpdatePort(t.Context(), openstackServerPort.ID, []string{openstackSecurityGroup.ID}, []ports.AddressPair{}).Return(openstackServerPort, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileServerPort(t.Context(), p, networking, server)
		require.NoError(t, err)
		require.NotNil(t, server.Status.PrivateIP)
		require.Equal(t, serverPortIP, *server.Status.PrivateIP)
	})

	t.Run("ItUpdatesSecurityGroups", func(t *testing.T) {
		t.Parallel()

		server := server.DeepCopy()
		server.Spec.SecurityGroups = append(server.Spec.SecurityGroups, regionv1.ServerSecurityGroupSpec{
			ID: securityGroup2.Name,
		})

		networking := mock.NewMockNetworkingInterface(c)
		networking.EXPECT().GetNetwork(t.Context(), networkMatcher(network)).Return(openstackNetwork, nil)
		networking.EXPECT().GetSecurityGroup(t.Context(), securityGroupMatcher(securityGroup)).Return(openstackSecurityGroup, nil)
		networking.EXPECT().GetSecurityGroup(t.Context(), securityGroupMatcher(securityGroup2)).Return(openstackSecurityGroup2, nil)
		networking.EXPECT().GetServerPort(t.Context(), server).Return(openstackServerPort, nil)
		networking.EXPECT().UpdatePort(t.Context(), openstackServerPort.ID, []string{openstackSecurityGroup.ID, openstackSecurityGroup2.ID}, []ports.AddressPair{}).Return(openstackServerPort, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileServerPort(t.Context(), p, networking, server)
		require.NoError(t, err)
	})
}

// TestReconcileFloatingIP tests a resource is created when one isn't present.
func TestReconcileFloatingIP(t *testing.T) {
	t.Parallel()

	client := getClient(t, nil)

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	// Must clone me in tests as they will update the status,
	server := serverFixture(withFloatingIP)
	network := networkFixture()

	openstackNetwork := openstackNetworkFixture(network)
	openstackSubnet := openstackSubnetFixture(network, openstackNetwork)
	openstackServerPort := openstackServerPortFixture(server, openstackNetwork, openstackSubnet)
	openstackFloatingIP := openstackFloatingIPFixture(openstackServerPort)

	t.Run("ItDoesntExist", func(t *testing.T) {
		t.Parallel()

		server := server.DeepCopy()

		networking := mock.NewMockFloatingIPInterface(c)
		networking.EXPECT().GetFloatingIP(t.Context(), openstackServerPort.ID).Return(nil, openstack.ErrNotFound)
		networking.EXPECT().CreateFloatingIP(t.Context(), openstackServerPort.ID).Return(openstackFloatingIP, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		require.NoError(t, openstack.ReconcileFloatingIP(t.Context(), p, networking, server, openstackServerPort))
		require.NotNil(t, server.Status.PublicIP)
		require.Equal(t, openstackFloatingIP.FloatingIP, *server.Status.PublicIP)
	})

	t.Run("ItExists", func(t *testing.T) {
		t.Parallel()

		server := server.DeepCopy()

		networking := mock.NewMockFloatingIPInterface(c)
		networking.EXPECT().GetFloatingIP(t.Context(), openstackServerPort.ID).Return(openstackFloatingIP, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		require.NoError(t, openstack.ReconcileFloatingIP(t.Context(), p, networking, server, openstackServerPort))
		require.NotNil(t, server.Status.PublicIP)
		require.Equal(t, openstackFloatingIP.FloatingIP, *server.Status.PublicIP)
	})

	t.Run("ItShouldntExist", func(t *testing.T) {
		t.Parallel()

		server := server.DeepCopy()
		server.Spec.PublicIPAllocation = nil

		networking := mock.NewMockFloatingIPInterface(c)
		networking.EXPECT().GetFloatingIP(t.Context(), openstackServerPort.ID).Return(openstackFloatingIP, nil)
		networking.EXPECT().DeleteFloatingIP(t.Context(), openstackFloatingIP.ID).Return(nil)

		p := openstack.NewTestProvider(client, regionFixture())

		require.NoError(t, openstack.ReconcileFloatingIP(t.Context(), p, networking, server, openstackServerPort))
		require.Nil(t, server.Status.PublicIP)
	})
}

// TestReconcileServer tests a resource is created when one isn't present.
func TestReconcileServer(t *testing.T) {
	t.Parallel()

	client := getClient(t, nil)

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	server := serverFixture()
	network := networkFixture()

	openstackNetwork := openstackNetworkFixture(network)
	openstackSubnet := openstackSubnetFixture(network, openstackNetwork)
	openstackServerPort := openstackServerPortFixture(server, openstackNetwork, openstackSubnet)
	openstackServer := openstackServerFixture(server)

	openstackNetworks := []servers.Network{
		{
			UUID: openstackNetwork.ID,
			Port: openstackServerPort.ID,
		},
	}

	metadata := map[string]string{
		"serverID":       server.Name,
		"organizationID": organizationID,
		"projectID":      projectID,
		"regionID":       regionID,
	}

	t.Run("ItDoesntExist", func(t *testing.T) {
		t.Parallel()

		compute := mock.NewMockServerInterface(c)
		compute.EXPECT().GetServer(t.Context(), server).Return(nil, openstack.ErrNotFound)
		compute.EXPECT().CreateServer(t.Context(), server, sshKeyName, openstackNetworks, nil, metadata).Return(openstackServer, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileServer(t.Context(), p, compute, server, openstackServerPort, sshKeyName)
		require.NoError(t, err)
	})

	t.Run("ItExists", func(t *testing.T) {
		t.Parallel()

		compute := mock.NewMockServerInterface(c)
		compute.EXPECT().GetServer(t.Context(), server).Return(openstackServer, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileServer(t.Context(), p, compute, server, openstackServerPort, sshKeyName)
		require.NoError(t, err)
	})
}
