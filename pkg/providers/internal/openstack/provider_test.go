/*
Copyright 2025 the Unikorn Authors.
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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/loadbalancers"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/monitors"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/pools"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/floatingips"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	corev1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	"github.com/unikorn-cloud/core/pkg/util/cache"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack/mock"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	k8sv1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func mustConvertImage(t *testing.T, in *images.Image) *types.Image {
	t.Helper()

	out, err := openstack.ConvertImage(in)
	require.NoError(t, err)

	return out
}

// TestImageFiltering checks that when filtering images we only get those
// that are public or scoped to the organization.
func TestImageFiltering(t *testing.T) {
	t.Parallel()

	public1 := mustConvertImage(t, imageFixtureWithID("foo"))
	public2 := mustConvertImage(t, withStatus(imageFixtureWithID("foo"), images.ImageStatusQueued))
	private1 := mustConvertImage(t, withOrganizationID(imageFixtureWithID("felix"), "cats"))
	private2 := mustConvertImage(t, withOrganizationID(imageFixtureWithID("rover"), "dogs"))

	//nolint:unparam // lint doesn't know this needs to be this func type
	listimages := func() (*cache.ListSnapshot[types.Image], error) {
		return &cache.ListSnapshot[types.Image]{
			Items: []*types.Image{
				public1,
				public2,
				private1,
				private2,
			},
		}, nil
	}

	t.Run("filter by available to organization", func(t *testing.T) {
		t.Parallel()

		query := openstack.NewImageQuery(listimages)
		images, err := query.AvailableToOrganization("cats").List(t.Context())
		require.NoError(t, err)

		require.ElementsMatch(t, images.Items, []*types.Image{
			public1,
			public2,
			private1,
		})
	})

	t.Run("filter by status", func(t *testing.T) {
		t.Parallel()

		query := openstack.NewImageQuery(listimages)
		images, err := query.StatusIn(types.ImageStatusReady).List(t.Context())
		require.NoError(t, err)

		require.ElementsMatch(t, images.Items, []*types.Image{
			public1,
			private1,
			private2,
		})
	})

	t.Run("filter by available to org and ready", func(t *testing.T) {
		t.Parallel()

		query := openstack.NewImageQuery(listimages)
		images, err := query.
			StatusIn(types.ImageStatusReady).
			AvailableToOrganization("cats").
			List(t.Context())
		require.NoError(t, err)

		require.ElementsMatch(t, images.Items, []*types.Image{
			public1,
			private1,
		})
	})
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

// TestDHCPRange checks that the DHCP range starts after the reservation.
func TestDHCPRange(t *testing.T) {
	t.Parallel()

	prefix := net.IPNet{
		IP:   net.IP{192, 168, 10, 0},
		Mask: net.IPMask{255, 255, 255, 0},
	}

	reservations := &regionv1.NetworkReservations{
		PrefixLength: 25,
	}

	start, end := openstack.DHCPRange(prefix, reservations)
	require.Equal(t, "192.168.10.128", start)
	require.Equal(t, "192.168.10.254", end)
}

// TestStorageRange checks that the storage range is allocated from the reservation.
func TestStorageRange(t *testing.T) {
	t.Parallel()

	prefix := net.IPNet{
		IP:   net.IP{192, 168, 10, 0},
		Mask: net.IPMask{255, 255, 255, 0},
	}

	// /25 starts at .2 and ends at .127.
	reservations := &regionv1.NetworkReservations{
		PrefixLength: 25,
	}

	r := openstack.StorageRange(prefix, reservations)
	require.NotNil(t, r)
	require.Equal(t, "192.168.10.2", r.Start.String())
	require.Equal(t, "192.168.10.127", r.End.String())

	// /25 with a /29 infrastructure pool starts storage at .16 and ends at .127.
	reservations = &regionv1.NetworkReservations{
		PrefixLength:                 25,
		ProviderReservedPrefixLength: ptr.To(29),
	}

	r = openstack.StorageRange(prefix, reservations)
	require.NotNil(t, r)
	require.Equal(t, "192.168.10.8", r.Start.String())
	require.Equal(t, "192.168.10.127", r.End.String())

	// /29 with a /29 infrastructure pool opts out of storage entirely.
	reservations = &regionv1.NetworkReservations{
		PrefixLength:                 29,
		ProviderReservedPrefixLength: ptr.To(29),
	}

	r = openstack.StorageRange(prefix, reservations)
	require.Nil(t, r)
}

const (
	organizationID = "spectre"
	projectID      = "manhattan"
	regionID       = "africa"
	identityID     = "1792e5ca-5127-4a16-bfb6-bb8a309d0688"
	serverName     = "server-abcdef"
	sshKeyName     = "skeleton"
)

type regionFixtureOption func(*regionv1.Region)

// regionFixture creates a region definition.
func regionFixture(opts ...regionFixtureOption) *regionv1.Region {
	region := &regionv1.Region{
		Spec: regionv1.RegionSpec{
			Openstack: &regionv1.RegionOpenstackSpec{},
		},
	}

	for _, opt := range opts {
		opt(region)
	}

	return region
}

func withOpenstackEndpoint(endpoint string) regionFixtureOption {
	return func(region *regionv1.Region) {
		region.Spec.Openstack.Endpoint = endpoint
	}
}

func withOpenstackServiceAccountSecret(name, namespace string) regionFixtureOption {
	return func(region *regionv1.Region) {
		region.Spec.Openstack.ServiceAccountSecret = &regionv1.NamespacedObject{
			Name:      name,
			Namespace: namespace,
		}
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

func networkForDeleteFixture(identity *regionv1.Identity, status *regionv1.NetworkStatusOpenstack) *regionv1.Network {
	network := networkFixture()
	network.Namespace = identity.Namespace
	network.Status.Openstack = status

	return network
}

// networkMatcher is used to check mock function call parameters, as the object
// may have been copied, and it may have been mutated.
func networkMatcher(network *regionv1.Network) gomock.Matcher {
	return gomock.Cond(func(x *regionv1.Network) bool {
		return x.Name == network.Name
	})
}

func identityFixture() *regionv1.Identity {
	return &regionv1.Identity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      identityID,
			Namespace: "default",
		},
	}
}

func openstackIdentityFixture(identity *regionv1.Identity) *regionv1.OpenstackIdentity {
	return &regionv1.OpenstackIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      identity.Name,
			Namespace: identity.Namespace,
		},
		Spec: regionv1.OpenstackIdentitySpec{
			UserID:    ptr.To("user-id"),
			Password:  ptr.To("password"),
			ProjectID: ptr.To("project-id"),
		},
	}
}

func openstackServiceAccountSecretFixture(name, namespace string) *k8sv1.Secret {
	return &k8sv1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"domain-id":  []byte("admin-domain-id"),
			"user-id":    []byte("admin-user-id"),
			"password":   []byte("admin-password"),
			"project-id": []byte("admin-project-id"),
		},
	}
}

func writeOpenstackAuthCatalog(w http.ResponseWriter, endpoint string) {
	w.Header().Set("X-Subject-Token", "test-token")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"token":{"catalog":[
		{"type":"identity","endpoints":[{"interface":"public","url":%[1]q,"region_id":""}]},
		{"type":"compute","endpoints":[{"interface":"public","url":%[1]q,"region_id":""}]},
		{"type":"image","endpoints":[{"interface":"public","url":%[1]q,"region_id":""}]},
		{"type":"network","endpoints":[{"interface":"public","url":%[1]q,"region_id":""}]}
		],"expires_at":"2099-01-01T00:00:00.000000Z"}}`,
		endpoint)
}

func writeOpenstackVersions(w http.ResponseWriter, endpoint string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w,
		`{"versions":{"values":[
			{"id":"v2.1","status":"CURRENT","links":[{"href":%q,"rel":"self"}]},
			{"id":"v3","status":"current","links":[{"href":%q,"rel":"self"}]}
			]}}`,
		endpoint+"/v2.1/", endpoint+"/v3/")
}

func writeOpenstackFlavors(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"flavors":[{"id":"f1","name":"m1.small","vcpus":1,"ram":1024,"disk":10,"swap":""}]}`)
}

func newIdentityDeleteOpenStack(t *testing.T, serviceUserID, serviceProjectID string, deletedUser, deletedProject *atomic.Bool) *httptest.Server {
	t.Helper()

	var server *httptest.Server

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)

				return
			}

			if strings.Contains(string(body), fmt.Sprintf("%q", serviceUserID)) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}`)

				return
			}

			writeOpenstackAuthCatalog(w, server.URL)

			return
		}

		if r.URL.Path == "/" {
			writeOpenstackVersions(w, server.URL)

			return
		}

		if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/users/"+serviceUserID) {
			deletedUser.Store(true)
			w.WriteHeader(http.StatusNoContent)

			return
		}

		if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/projects/"+serviceProjectID) {
			deletedProject.Store(true)
			w.WriteHeader(http.StatusNoContent)

			return
		}

		writeOpenstackFlavors(w)
	}))
	t.Cleanup(server.Close)

	return server
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
		DNSNameservers: []string{
			"8.8.4.4",
		},
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

	var p *corev1.IPv4Prefix

	if prefix != "" {
		_, cidr, err := net.ParseCIDR(prefix)
		require.NoError(t, err)

		p = &corev1.IPv4Prefix{
			IPNet: *cidr,
		}
	}

	return regionv1.SecurityGroupRule{
		Direction: dir,
		Protocol:  proto,
		Port: &regionv1.SecurityGroupRulePort{
			Number: ptr.To(port),
		},
		CIDR: p,
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

func securityGroupForDeleteFixture(identity *regionv1.Identity) *regionv1.SecurityGroup {
	securityGroup := securityGroupFixture()
	securityGroup.Namespace = identity.Namespace

	return securityGroup
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

func withTags(tags ...corev1.Tag) func(*regionv1.Server) {
	return func(s *regionv1.Server) {
		s.Spec.Tags = append(s.Spec.Tags, tags...)
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
const serverPortMAC = "fa:16:3e:12:34:56"

func openstackServerPortFixture(server *regionv1.Server, openstackNetwork *openstack.NetworkExt, openstackSubnet *subnets.Subnet) *ports.Port {
	return &ports.Port{
		ID:          string(uuid.NewUUID()),
		Name:        openstack.ServerName(server),
		MACAddress:  serverPortMAC,
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

func sshCertificateAuthorityFixture() *regionv1.SSHCertificateAuthority {
	return &regionv1.SSHCertificateAuthority{
		ObjectMeta: metav1.ObjectMeta{
			Name:      string(uuid.NewUUID()),
			Namespace: "default",
		},
		Spec: regionv1.SSHCertificateAuthoritySpec{
			PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMI0BxP3V7j7iB5nV5d8zWwM9W4a8W2R7x5gNBy3M2Q7 test-ca",
		},
	}
}

func withSSHCertificateAuthority(sshCertificateAuthority *regionv1.SSHCertificateAuthority) func(*regionv1.Server) {
	return func(s *regionv1.Server) {
		s.Namespace = sshCertificateAuthority.Namespace
		s.Spec.SSHCertificateAuthorityID = ptr.To(sshCertificateAuthority.Name)
	}
}

// loadBalancerNetworkFixture creates a Network CRD with a populated
// Status.Openstack.SubnetID, suitable for seeding the fake client when the
// load balancer reconciler resolves its parent network.
func loadBalancerNetworkFixture() *regionv1.Network {
	return &regionv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      string(uuid.NewUUID()),
			Namespace: "default",
		},
		Status: regionv1.NetworkStatus{
			Openstack: &regionv1.NetworkStatusOpenstack{
				SubnetID: ptr.To(string(uuid.NewUUID())),
			},
		},
	}
}

// loadBalancerMember encodes a CRD pool member.
func loadBalancerMember(address string, port int) regionv1.LoadBalancerMember {
	return regionv1.LoadBalancerMember{
		Address: corev1.IPv4Address{IP: net.ParseIP(address).To4()},
		Port:    port,
	}
}

// withRequestedVIP sets Spec.RequestedVIPAddress on a load balancer fixture.
func withRequestedVIP(addr string) func(*regionv1.LoadBalancer) {
	return func(lb *regionv1.LoadBalancer) {
		lb.Spec.RequestedVIPAddress = &corev1.IPv4Address{IP: net.ParseIP(addr).To4()}
	}
}

// withPublicIP enables Spec.PublicIP on a load balancer fixture.
func withPublicIP() func(*regionv1.LoadBalancer) {
	return func(lb *regionv1.LoadBalancer) {
		lb.Spec.PublicIP = true
	}
}

func withLoadBalancerVIPStatus(addr string) func(*regionv1.LoadBalancer) {
	return func(lb *regionv1.LoadBalancer) {
		lb.Status.VIPAddress = &corev1.IPv4Address{IP: net.ParseIP(addr).To4()}
	}
}

// listenerFixture creates a CRD listener with the given name/protocol/port and
// applies any per-listener mutators. IdleTimeoutSeconds is preset to 60 for TCP
// listeners (mirroring the handler default) and left nil for UDP; opts may
// override either.
func listenerFixture(name string, protocol regionv1.LoadBalancerListenerProtocol, port int, opts ...func(*regionv1.LoadBalancerListener)) regionv1.LoadBalancerListener {
	listener := regionv1.LoadBalancerListener{
		Name:     name,
		Protocol: protocol,
		Port:     port,
		Pool: regionv1.LoadBalancerPool{
			Members: []regionv1.LoadBalancerMember{},
		},
	}

	if protocol == regionv1.LoadBalancerListenerProtocolTCP {
		listener.IdleTimeoutSeconds = ptr.To(60)
	}

	for _, o := range opts {
		o(&listener)
	}

	return listener
}

// withMember appends a member to a listener's pool.
func withMember(addr string, port int) func(*regionv1.LoadBalancerListener) {
	return func(l *regionv1.LoadBalancerListener) {
		l.Pool.Members = append(l.Pool.Members, loadBalancerMember(addr, port))
	}
}

// withHealthCheck attaches a HealthCheck to the listener's pool.
//
//nolint:unparam
func withHealthCheck(interval, timeout, healthy, unhealthy int) func(*regionv1.LoadBalancerListener) {
	return func(l *regionv1.LoadBalancerListener) {
		l.Pool.HealthCheck = &regionv1.LoadBalancerHealthCheck{
			IntervalSeconds:    interval,
			TimeoutSeconds:     timeout,
			HealthyThreshold:   healthy,
			UnhealthyThreshold: unhealthy,
		}
	}
}

// withProxyProtocolV2 enables PROXYV2 on a TCP listener's pool.
func withProxyProtocolV2() func(*regionv1.LoadBalancerListener) {
	return func(l *regionv1.LoadBalancerListener) {
		l.Pool.ProxyProtocolV2 = true
	}
}

// withIdleTimeoutSeconds overrides the listener's idle timeout.
func withIdleTimeoutSeconds(seconds int) func(*regionv1.LoadBalancerListener) {
	return func(l *regionv1.LoadBalancerListener) {
		l.IdleTimeoutSeconds = ptr.To(seconds)
	}
}

// withAllowedCIDRs sets the listener's allow list.
func withAllowedCIDRs(cidrs ...string) func(*regionv1.LoadBalancerListener) {
	return func(l *regionv1.LoadBalancerListener) {
		l.AllowedCIDRs = make([]corev1.IPv4Prefix, len(cidrs))

		for i, c := range cidrs {
			_, ipnet, err := net.ParseCIDR(c)
			if err != nil {
				panic(err)
			}

			l.AllowedCIDRs[i] = corev1.IPv4Prefix{IPNet: *ipnet}
		}
	}
}

// loadBalancerFixture creates a basic load balancer pinned to the given
// network. The default listener is "http" tcp/80 with a single member.
func loadBalancerFixture(network *regionv1.Network, opts ...func(*regionv1.LoadBalancer)) *regionv1.LoadBalancer {
	lb := &regionv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      string(uuid.NewUUID()),
			Namespace: network.Namespace,
			Labels: map[string]string{
				constants.NetworkLabel: network.Name,
			},
		},
		Spec: regionv1.LoadBalancerSpec{
			Listeners: []regionv1.LoadBalancerListener{
				listenerFixture("http", regionv1.LoadBalancerListenerProtocolTCP, 80,
					withMember("10.0.0.5", 8080),
				),
			},
		},
	}

	for _, o := range opts {
		o(lb)
	}

	return lb
}

// loadBalancerMatcher matches a LoadBalancer argument by Name.
func loadBalancerMatcher(lb *regionv1.LoadBalancer) gomock.Matcher {
	return gomock.Cond(func(x *regionv1.LoadBalancer) bool {
		return x.Name == lb.Name
	})
}

// listenerCRDMatcher matches a CRD listener argument by Name.
func listenerCRDMatcher(name string) gomock.Matcher {
	return gomock.Cond(func(x *regionv1.LoadBalancerListener) bool {
		return x.Name == name
	})
}

// withProvisioningStatus sets the openstack load balancer's ProvisioningStatus.
func withProvisioningStatus(s string) func(*loadbalancers.LoadBalancer) {
	return func(lb *loadbalancers.LoadBalancer) {
		lb.ProvisioningStatus = s
	}
}

// withVip sets the openstack load balancer's VipAddress.
func withVip(addr string) func(*loadbalancers.LoadBalancer) {
	return func(lb *loadbalancers.LoadBalancer) {
		lb.VipAddress = addr
	}
}

// withVipPortID sets the openstack load balancer's VipPortID.
func withVipPortID(id string) func(*loadbalancers.LoadBalancer) {
	return func(lb *loadbalancers.LoadBalancer) {
		lb.VipPortID = id
	}
}

// openstackLoadBalancerFixture builds a default ACTIVE load balancer with the
// canonical VIP, optionally tweaked. VipPortID defaults to a fresh UUID so the
// orchestrator's VIP-port guard always passes; tests that need to exercise the
// guard should use withVipPortID("").
func openstackLoadBalancerFixture(lb *regionv1.LoadBalancer, opts ...func(*loadbalancers.LoadBalancer)) *loadbalancers.LoadBalancer {
	osLB := &loadbalancers.LoadBalancer{
		ID:                 string(uuid.NewUUID()),
		Name:               openstack.LoadBalancerName(lb),
		ProvisioningStatus: "ACTIVE",
		VipAddress:         "10.0.0.42",
		VipPortID:          string(uuid.NewUUID()),
	}

	for _, o := range opts {
		o(osLB)
	}

	return osLB
}

// expectNoFloatingIP records the default no-public-IP convergence —
// GetFloatingIP returns ErrResourceNotFound on the VIP port and no
// Create/Delete is invoked.
func expectNoFloatingIP(t *testing.T, c *gomock.Controller, vipPortID string) *mock.MockNetworkingInterface {
	t.Helper()

	m := mock.NewMockNetworkingInterface(c)
	m.EXPECT().GetFloatingIP(t.Context(), vipPortID).Return(nil, errors.ErrResourceNotFound)

	return m
}

func deleteLoadBalancerWithClients(
	t *testing.T,
	network *regionv1.Network,
	lb *regionv1.LoadBalancer,
	lbClient openstack.LoadBalancingInterface,
	fipClient openstack.FloatingIPInterface,
) error {
	t.Helper()

	p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())

	return openstack.DeleteLoadBalancerWithClient(t.Context(), p, lbClient, fipClient, lb)
}

func requireLoadBalancerIPsCleared(t *testing.T, lb *regionv1.LoadBalancer) {
	t.Helper()

	require.Nil(t, lb.Status.PublicIP)
	require.Nil(t, lb.Status.VIPAddress)
}

// openstackListenerFixture builds an ACTIVE listener live representation. The
// timeout fields default to the 60s admission default in millis so steady-state
// tests don't need to repeat them.
func openstackListenerFixture(lb *regionv1.LoadBalancer, listener *regionv1.LoadBalancerListener) *listeners.Listener {
	return &listeners.Listener{
		ID:                 string(uuid.NewUUID()),
		Name:               openstack.LoadBalancerListenerName(lb, listener),
		ProvisioningStatus: "ACTIVE",
		Protocol:           string(openstack.OctaviaListenerProtocol(listener.Protocol)),
		ProtocolPort:       listener.Port,
		TimeoutClientData:  60000,
		TimeoutMemberData:  60000,
	}
}

// openstackPoolFixture builds an ACTIVE pool live representation.
func openstackPoolFixture(lb *regionv1.LoadBalancer, listener *regionv1.LoadBalancerListener) *pools.Pool {
	return &pools.Pool{
		ID:                 string(uuid.NewUUID()),
		Name:               openstack.LoadBalancerPoolName(lb, listener),
		ProvisioningStatus: "ACTIVE",
		Protocol:           string(openstack.OctaviaPoolProtocol(listener.Protocol, listener.Pool.ProxyProtocolV2)),
		LBMethod:           string(pools.LBMethodRoundRobin),
	}
}

// openstackMonitorFixture builds an ACTIVE health monitor live representation.
func openstackMonitorFixture(lb *regionv1.LoadBalancer, listener *regionv1.LoadBalancerListener) *monitors.Monitor {
	hc := listener.Pool.HealthCheck

	return &monitors.Monitor{
		ID:                 string(uuid.NewUUID()),
		Name:               openstack.LoadBalancerMonitorName(lb, listener),
		ProvisioningStatus: "ACTIVE",
		Type:               openstack.OctaviaMonitorType(listener.Protocol),
		Delay:              hc.IntervalSeconds,
		Timeout:            hc.TimeoutSeconds,
		MaxRetries:         hc.HealthyThreshold,
		MaxRetriesDown:     hc.UnhealthyThreshold,
	}
}

// openstackMemberFixture builds a live pool.Member for a (address, port) pair.
//
//nolint:unparam
func openstackMemberFixture(address string, port int) pools.Member {
	return pools.Member{
		ID:           string(uuid.NewUUID()),
		Address:      address,
		ProtocolPort: port,
	}
}

// getClient is a terse way to create a Kubernetes client.
func getClient(t *testing.T, objects []client.Object) client.Client {
	t.Helper()

	scheme, err := coreclient.NewScheme(regionv1.AddToScheme)
	require.NoError(t, err)

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func testProviderFixture(t *testing.T, region *regionv1.Region, objects ...client.Object) *openstack.Provider {
	t.Helper()

	return openstack.NewTestProvider(getClient(t, objects), region)
}

func deleteLoadBalancerClientSetupFixture(t *testing.T, endpoint string, provisioned bool) (*openstack.Provider, *regionv1.Identity, *regionv1.LoadBalancer) {
	t.Helper()

	identity := identityFixture()
	openstackIdentity := openstackIdentityFixture(identity)
	network := loadBalancerNetworkFixture()
	lb := loadBalancerFixture(network)

	if provisioned {
		withLoadBalancerVIPStatus("10.0.0.42")(lb)
	}

	provider := testProviderFixture(t, regionFixture(withOpenstackEndpoint(endpoint)), openstackIdentity)

	return provider, identity, lb
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
		networking.EXPECT().GetNetwork(t.Context(), network).Return(nil, errors.ErrResourceNotFound)
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
			Start: "192.168.0.128",
			End:   "192.168.0.254",
		},
	}

	t.Run("ItDoesntExist", func(t *testing.T) {
		t.Parallel()

		networking := mock.NewMockSubnetInterface(c)
		networking.EXPECT().GetSubnet(t.Context(), network).Return(nil, errors.ErrResourceNotFound)
		networking.EXPECT().CreateSubnet(t.Context(), network, openstackNetwork.ID, "192.168.0.0/24", gomock.Any(), []string{"8.8.4.4"}, []subnets.HostRoute{}, allocationPools).Return(openstackSubnet, nil)

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
		networking.EXPECT().UpdateSubnet(t.Context(), openstackSubnet.ID, []string{"8.8.4.4"}, []subnets.HostRoute{}).Return(openstackSubnet, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileSubnet(t.Context(), p, networking, network, openstackNetwork)
		require.NoError(t, err)
		require.NotNil(t, network.Status.Openstack.SubnetID)
		require.Equal(t, openstackSubnet.ID, *network.Status.Openstack.SubnetID)
	})

	t.Run("ItUpdatesSubnets", func(t *testing.T) {
		t.Parallel()

		updatedNetwork := network.DeepCopy()
		updatedNetwork.Spec.DNSNameservers = nil

		networking := mock.NewMockSubnetInterface(c)
		networking.EXPECT().GetSubnet(t.Context(), updatedNetwork).Return(openstackSubnet, nil)
		networking.EXPECT().UpdateSubnet(t.Context(), openstackSubnet.ID, nil, []subnets.HostRoute{}).Return(openstackSubnet, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileSubnet(t.Context(), p, networking, updatedNetwork, openstackNetwork)

		require.NoError(t, err)
		require.NotNil(t, updatedNetwork.Status.Openstack.SubnetID)
		require.Equal(t, openstackSubnet.ID, *updatedNetwork.Status.Openstack.SubnetID)
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
		networking.EXPECT().GetRouter(t.Context(), network).Return(nil, errors.ErrResourceNotFound)
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
		networking.EXPECT().GetSecurityGroup(t.Context(), securityGroup).Return(nil, errors.ErrResourceNotFound)
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
			securityGroupRuleFixtureSingle(t, regionv1.Ingress, regionv1.Any, 0, ""),
		)

		openstackSecurityGroup := openstackSecurityGroupFixture(securityGroup, openstackSecurityGroupRuleFixtureDefault())

		networking := mock.NewMockSecurityGroupInterface(c)
		networking.EXPECT().ListSecurityGroupRules(t.Context(), openstackSecurityGroup.ID).Return(openstackSecurityGroup.Rules, nil)
		networking.EXPECT().CreateSecurityGroupRule(t.Context(), openstackSecurityGroup.ID, rules.DirIngress, rules.ProtocolTCP, 22, 22, "172.16.0.0/12").Return(nil, nil)
		networking.EXPECT().CreateSecurityGroupRule(t.Context(), openstackSecurityGroup.ID, rules.DirIngress, rules.ProtocolAny, 0, 0, "").Return(nil, nil)

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

	t.Run("ItOverridesImplicitEgress", func(t *testing.T) {
		t.Parallel()

		securityGroup := securityGroupFixture(
			securityGroupRuleFixtureSingle(t, regionv1.Egress, regionv1.Any, 0, ""),
			securityGroupRuleFixtureSingle(t, regionv1.Egress, regionv1.Any, 0, "0.0.0.0/0"),
		)

		openstackSecurityGroup := openstackSecurityGroupFixture(securityGroup,
			openstackSecurityGroupRuleFixtureDefault(),
		)

		networking := mock.NewMockSecurityGroupInterface(c)
		networking.EXPECT().ListSecurityGroupRules(t.Context(), openstackSecurityGroup.ID).Return(openstackSecurityGroup.Rules, nil)

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
		networking.EXPECT().GetServerPort(t.Context(), server).Return(nil, errors.ErrResourceNotFound)
		networking.EXPECT().CreateServerPort(t.Context(), server, openstackNetwork.ID, []string{openstackSecurityGroup.ID}, []ports.AddressPair{}).Return(openstackServerPort, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileServerPort(t.Context(), p, networking, server)
		require.NoError(t, err)
		require.NotNil(t, server.Status.PrivateIP)
		require.Equal(t, serverPortIP, *server.Status.PrivateIP)
		require.NotNil(t, server.Status.MACAddress)
		require.Equal(t, serverPortMAC, *server.Status.MACAddress)
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
		require.NotNil(t, server.Status.MACAddress)
		require.Equal(t, serverPortMAC, *server.Status.MACAddress)
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
		networking.EXPECT().GetFloatingIP(t.Context(), openstackServerPort.ID).Return(nil, errors.ErrResourceNotFound)
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

// TestReconcileLoadBalancerFloatingIP exercises the floating-IP convergence on
// the Octavia VIP port.
func TestReconcileLoadBalancerFloatingIP(t *testing.T) {
	t.Parallel()

	client := getClient(t, nil)

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	network := loadBalancerNetworkFixture()
	lb := loadBalancerFixture(network)
	vipPortID := string(uuid.NewUUID())
	openstackFloatingIP := openstackFloatingIPFixture(&ports.Port{ID: vipPortID})

	t.Run("ItDoesntExistAndDisabled", func(t *testing.T) {
		t.Parallel()

		lb := lb.DeepCopy()

		networking := mock.NewMockFloatingIPInterface(c)
		networking.EXPECT().GetFloatingIP(t.Context(), vipPortID).Return(nil, errors.ErrResourceNotFound)

		p := openstack.NewTestProvider(client, regionFixture())

		require.NoError(t, openstack.ReconcileLoadBalancerFloatingIP(t.Context(), p, networking, lb, vipPortID))
		require.Nil(t, lb.Status.PublicIP)
	})

	t.Run("ItDoesntExistAndEnabled", func(t *testing.T) {
		t.Parallel()

		lb := lb.DeepCopy()
		lb.Spec.PublicIP = true

		networking := mock.NewMockFloatingIPInterface(c)
		networking.EXPECT().GetFloatingIP(t.Context(), vipPortID).Return(nil, errors.ErrResourceNotFound)
		networking.EXPECT().CreateFloatingIP(t.Context(), vipPortID).Return(openstackFloatingIP, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		require.NoError(t, openstack.ReconcileLoadBalancerFloatingIP(t.Context(), p, networking, lb, vipPortID))
		require.NotNil(t, lb.Status.PublicIP)
		require.Equal(t, openstackFloatingIP.FloatingIP, lb.Status.PublicIP.String())
	})

	t.Run("ItExistsAndEnabled", func(t *testing.T) {
		t.Parallel()

		lb := lb.DeepCopy()
		lb.Spec.PublicIP = true

		networking := mock.NewMockFloatingIPInterface(c)
		networking.EXPECT().GetFloatingIP(t.Context(), vipPortID).Return(openstackFloatingIP, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		require.NoError(t, openstack.ReconcileLoadBalancerFloatingIP(t.Context(), p, networking, lb, vipPortID))
		require.NotNil(t, lb.Status.PublicIP)
		require.Equal(t, openstackFloatingIP.FloatingIP, lb.Status.PublicIP.String())
	})

	t.Run("ItExistsAndDisabled", func(t *testing.T) {
		t.Parallel()

		lb := lb.DeepCopy()
		lb.Status.PublicIP = &corev1.IPv4Address{IP: net.ParseIP("99.88.77.66").To4()}

		networking := mock.NewMockFloatingIPInterface(c)
		networking.EXPECT().GetFloatingIP(t.Context(), vipPortID).Return(openstackFloatingIP, nil)
		networking.EXPECT().DeleteFloatingIP(t.Context(), openstackFloatingIP.ID).Return(nil)

		p := openstack.NewTestProvider(client, regionFixture())

		require.NoError(t, openstack.ReconcileLoadBalancerFloatingIP(t.Context(), p, networking, lb, vipPortID))
		require.Nil(t, lb.Status.PublicIP)
	})

	t.Run("ItErrorsOnAmbiguousLiveState", func(t *testing.T) {
		t.Parallel()

		lb := lb.DeepCopy()
		lb.Spec.PublicIP = true

		networking := mock.NewMockFloatingIPInterface(c)
		networking.EXPECT().GetFloatingIP(t.Context(), vipPortID).Return(nil, errors.ErrConsistency)

		p := openstack.NewTestProvider(client, regionFixture())

		err := openstack.ReconcileLoadBalancerFloatingIP(t.Context(), p, networking, lb, vipPortID)
		require.ErrorIs(t, err, errors.ErrConsistency)
		require.Nil(t, lb.Status.PublicIP)
	})

	t.Run("ItErrorsOnEmptyFloatingIPField", func(t *testing.T) {
		t.Parallel()

		lb := lb.DeepCopy()
		lb.Spec.PublicIP = true

		networking := mock.NewMockFloatingIPInterface(c)
		networking.EXPECT().GetFloatingIP(t.Context(), vipPortID).Return(&floatingips.FloatingIP{ID: string(uuid.NewUUID()), FloatingIP: ""}, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		err := openstack.ReconcileLoadBalancerFloatingIP(t.Context(), p, networking, lb, vipPortID)
		require.ErrorIs(t, err, errors.ErrConsistency)
		require.Nil(t, lb.Status.PublicIP)
	})

	t.Run("ItErrorsOnMalformedFloatingIP", func(t *testing.T) {
		t.Parallel()

		lb := lb.DeepCopy()
		lb.Spec.PublicIP = true

		networking := mock.NewMockFloatingIPInterface(c)
		networking.EXPECT().GetFloatingIP(t.Context(), vipPortID).Return(&floatingips.FloatingIP{ID: string(uuid.NewUUID()), FloatingIP: "not-an-ip"}, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		err := openstack.ReconcileLoadBalancerFloatingIP(t.Context(), p, networking, lb, vipPortID)
		require.ErrorIs(t, err, errors.ErrConsistency)
		require.Nil(t, lb.Status.PublicIP)
	})

	t.Run("ItErrorsOnIPv6FloatingIP", func(t *testing.T) {
		t.Parallel()

		lb := lb.DeepCopy()
		lb.Spec.PublicIP = true

		networking := mock.NewMockFloatingIPInterface(c)
		networking.EXPECT().GetFloatingIP(t.Context(), vipPortID).Return(&floatingips.FloatingIP{ID: string(uuid.NewUUID()), FloatingIP: "2001:db8::1"}, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		err := openstack.ReconcileLoadBalancerFloatingIP(t.Context(), p, networking, lb, vipPortID)
		require.ErrorIs(t, err, errors.ErrConsistency)
		require.Nil(t, lb.Status.PublicIP)
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
		// Legacy camelCase keys.
		"serverID":       server.Name,
		"organizationID": organizationID,
		"projectID":      projectID,
		"regionID":       regionID,
		// Namespaced duplicates.
		"region:server_id":         server.Name,
		"identity:organization_id": organizationID,
		"identity:project_id":      projectID,
		"region:region_id":         regionID,
	}

	t.Run("ItDoesntExist", func(t *testing.T) {
		t.Parallel()

		compute := mock.NewMockServerInterface(c)
		compute.EXPECT().GetServer(t.Context(), server).Return(nil, errors.ErrResourceNotFound)
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

// TestImageTagRoundTrip tests the round-trip conversion of tags:
// types.Image.Tags -> createImageMetadata -> Glance properties -> imageTags -> map[string]string.
func TestImageTagRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		image *types.Image
	}{
		{
			name: "image with multiple tags",
			image: &types.Image{
				Name: "my-snapshot",
				Tags: map[string]string{
					"name":         "server-xyz", // verify it doesn't collide with the field Name
					"snapshotType": "manual",
					"requestId":    "req-789",
				},
				OS: types.ImageOS{
					Kernel:  types.Linux,
					Family:  "debian",
					Distro:  "ubuntu",
					Version: "24.04",
				},
			},
		},
		{
			name: "image with no tags",
			image: &types.Image{
				Name: "base-image",
				Tags: nil,
				OS: types.ImageOS{
					Kernel:  types.Linux,
					Family:  "redhat",
					Distro:  "rocky",
					Version: "9.3",
				},
			},
		},
		{
			name: "image with special characters in tag keys",
			image: &types.Image{
				Name: "test-image",
				Tags: map[string]string{
					"backup-id":   "daily-2025-01-23",
					"env.type":    "production",
					"owner_email": "user@example.com",
				},
				OS: types.ImageOS{
					Kernel:  types.Linux,
					Family:  "debian",
					Distro:  "ubuntu",
					Version: "22.04",
				},
			},
		},
		{
			name: "image with single tag",
			image: &types.Image{
				Name: "single-tag-image",
				Tags: map[string]string{
					"instanceId": "abc-123",
				},
				OS: types.ImageOS{
					Kernel:  types.Linux,
					Family:  "debian",
					Distro:  "ubuntu",
					Version: "24.04",
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			properties, err := openstack.CreateImageMetadata(c.image)
			require.NoError(t, err)

			// We send map[string]string to the Glance client, but it returns map[string]any,
			// containing any properties it didn't recognise as its own.
			glanceProperties := make(map[string]any)
			for k, v := range properties {
				glanceProperties[k] = v
			}

			glanceImage := &images.Image{
				Properties: glanceProperties,
			}

			extractedTags := openstack.ImageTags(glanceImage)

			require.Equal(t, c.image.Tags, extractedTags)
		})
	}
}

// TestMetadataKey tests the tag key transformation from namespaced CRD tag format
// to the OpenStack metadata key format.
func TestMetadataKey(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		input    string
		expected string
		ok       bool
	}{
		{
			name:     "ValidSimple",
			input:    "compute.unikorn-cloud.org/instance-id",
			expected: "compute:instance_id",
			ok:       true,
		},
		{
			name:     "ValidOtherService",
			input:    "kubernetes.unikorn-cloud.org/cluster-id",
			expected: "kubernetes:cluster_id",
			ok:       true,
		},
		{
			name:     "ValidHyphenInSubdomain",
			input:    "my-service.unikorn-cloud.org/foo-bar",
			expected: "my-service:foo_bar",
			ok:       true,
		},
		{
			name:  "InvalidNoSlash",
			input: "compute.unikorn-cloud.org",
			ok:    false,
		},
		{
			name:  "InvalidUppercase",
			input: "Compute.unikorn-cloud.org/id",
			ok:    false,
		},
		{
			name:  "InvalidBareName",
			input: "instance-id",
			ok:    false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			got, ok := openstack.MetadataKey(c.input)
			require.Equal(t, c.ok, ok)

			if c.ok {
				require.Equal(t, c.expected, got)
			}
		})
	}
}

// TestReconcileServerTags verifies that server tags are correctly forwarded to
// OpenStack instance metadata, invalid keys are silently dropped, and system keys
// are always present and cannot be overwritten by user tags.
func TestReconcileServerTags(t *testing.T) {
	t.Parallel()

	client := getClient(t, nil)

	network := networkFixture()
	openstackNetwork := openstackNetworkFixture(network)
	openstackSubnet := openstackSubnetFixture(network, openstackNetwork)

	t.Run("ValidTagsForwarded", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		t.Cleanup(c.Finish)

		server := serverFixture(withTags(
			corev1.Tag{Name: "compute.unikorn-cloud.org/instance-type", Value: "large"},
			corev1.Tag{Name: "app.unikorn-cloud.org/env", Value: "prod"},
			// Invalid key — should be silently dropped.
			corev1.Tag{Name: "not-a-valid-key", Value: "ignored"},
		))
		openstackServerPort := openstackServerPortFixture(server, openstackNetwork, openstackSubnet)
		openstackNetworks := []servers.Network{
			{
				UUID: openstackNetwork.ID,
				Port: openstackServerPort.ID,
			},
		}
		openstackServer := openstackServerFixture(server)

		expectedMetadata := map[string]string{
			// User tags.
			"compute:instance_type": "large",
			"app:env":               "prod",
			// Legacy system keys.
			"serverID":       server.Name,
			"organizationID": organizationID,
			"projectID":      projectID,
			"regionID":       regionID,
			// Namespaced system keys.
			"region:server_id":         server.Name,
			"identity:organization_id": organizationID,
			"identity:project_id":      projectID,
			"region:region_id":         regionID,
		}

		compute := mock.NewMockServerInterface(c)
		compute.EXPECT().GetServer(t.Context(), server).Return(nil, errors.ErrResourceNotFound)
		compute.EXPECT().CreateServer(t.Context(), server, sshKeyName, openstackNetworks, nil, expectedMetadata).Return(openstackServer, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileServer(t.Context(), p, compute, server, openstackServerPort, sshKeyName)
		require.NoError(t, err)
	})

	t.Run("SystemKeysOverwriteCollision", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		t.Cleanup(c.Finish)

		// A user tag that collides with the namespaced system key "identity:organization_id".
		server := serverFixture(withTags(
			corev1.Tag{Name: "identity.unikorn-cloud.org/organization-id", Value: "attacker"},
		))
		openstackServerPort := openstackServerPortFixture(server, openstackNetwork, openstackSubnet)
		openstackNetworks := []servers.Network{
			{
				UUID: openstackNetwork.ID,
				Port: openstackServerPort.ID,
			},
		}
		openstackServer := openstackServerFixture(server)

		// The system key must win — value must be the real organizationID.
		expectedMetadata := map[string]string{
			"serverID":                 server.Name,
			"organizationID":           organizationID,
			"projectID":                projectID,
			"regionID":                 regionID,
			"region:server_id":         server.Name,
			"identity:organization_id": organizationID,
			"identity:project_id":      projectID,
			"region:region_id":         regionID,
		}

		compute := mock.NewMockServerInterface(c)
		compute.EXPECT().GetServer(t.Context(), server).Return(nil, errors.ErrResourceNotFound)
		compute.EXPECT().CreateServer(t.Context(), server, sshKeyName, openstackNetworks, nil, expectedMetadata).Return(openstackServer, nil)

		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileServer(t.Context(), p, compute, server, openstackServerPort, sshKeyName)
		require.NoError(t, err)
	})
}

func TestResolveServerKeyName(t *testing.T) {
	t.Parallel()

	t.Run("UsesImplicitKeyWithoutSSHCertificateAuthority", func(t *testing.T) {
		t.Parallel()

		server := serverFixture()
		identity := &regionv1.OpenstackIdentity{
			Spec: regionv1.OpenstackIdentitySpec{
				SSHKeyName: ptr.To(sshKeyName),
			},
		}

		require.Equal(t, sshKeyName, openstack.ResolveServerKeyName(server, identity))
	})

	t.Run("SuppressesImplicitKeyWithSSHCertificateAuthority", func(t *testing.T) {
		t.Parallel()

		sshCertificateAuthority := sshCertificateAuthorityFixture()
		server := serverFixture(withSSHCertificateAuthority(sshCertificateAuthority))
		identity := &regionv1.OpenstackIdentity{
			Spec: regionv1.OpenstackIdentitySpec{
				SSHKeyName: ptr.To(sshKeyName),
			},
		}

		require.Empty(t, openstack.ResolveServerKeyName(server, identity))
	})
}

func TestDeleteIdentitySkipsUnauthorizedComputeCleanup(t *testing.T) {
	t.Parallel()

	identity := identityFixture()
	openstackIdentity := openstackIdentityFixture(identity)
	openstackIdentity.Spec.UserID = ptr.To("service-user-id")
	openstackIdentity.Spec.ProjectID = ptr.To("service-project-id")
	openstackIdentity.Spec.SSHKeyName = ptr.To("unikorn-openstack-provider")
	openstackIdentity.Spec.ServerGroupID = ptr.To("server-group-id")

	var (
		deletedUser    atomic.Bool
		deletedProject atomic.Bool
	)

	server := newIdentityDeleteOpenStack(t, *openstackIdentity.Spec.UserID, *openstackIdentity.Spec.ProjectID, &deletedUser, &deletedProject)

	region := regionFixture(
		withOpenstackEndpoint(server.URL),
		withOpenstackServiceAccountSecret("test-secret", "default"),
	)
	region.ObjectMeta = metav1.ObjectMeta{
		Name:      "test-region",
		Namespace: "default",
	}

	secret := openstackServiceAccountSecretFixture("test-secret", "default")

	kubeClient := newRaceTestClient(t, region, secret, openstackIdentity)
	provider, err := openstack.New(t.Context(), kubeClient, kubeClient, region, openstack.Options{})
	require.NoError(t, err)

	require.NoError(t, provider.DeleteIdentity(t.Context(), identity))

	var result regionv1.OpenstackIdentity
	err = kubeClient.Get(t.Context(), client.ObjectKeyFromObject(openstackIdentity), &result)
	require.True(t, kerrors.IsNotFound(err))
	require.True(t, deletedUser.Load())
	require.True(t, deletedProject.Load())
}

func TestServerForCreate(t *testing.T) {
	t.Parallel()

	t.Run("ReturnsOriginalServerWithoutInjectedUserData", func(t *testing.T) {
		t.Parallel()

		server := serverFixture()

		result := openstack.ServerForCreate(server, nil)

		require.Same(t, server, result)
		require.Nil(t, server.Spec.UserData)
	})

	t.Run("ReturnsCopyWhenInjectedUserDataIsPresent", func(t *testing.T) {
		t.Parallel()

		sshCertificateAuthority := sshCertificateAuthorityFixture()
		server := serverFixture(withSSHCertificateAuthority(sshCertificateAuthority))
		server.Status.PrivateIP = ptr.To(serverPortIP)
		server.Status.PublicIP = ptr.To("12.34.56.78")
		server.Status.MACAddress = ptr.To(serverPortMAC)

		options := &types.ServerCreateOptions{
			UserData: []byte("#cloud-config\nusers: []\n"),
		}

		result := openstack.ServerForCreate(server, options)

		require.NotSame(t, server, result)
		require.Equal(t, options.UserData, result.Spec.UserData)
		require.Nil(t, server.Spec.UserData)
		require.Equal(t, ptr.To(serverPortIP), server.Status.PrivateIP)
		require.Equal(t, ptr.To("12.34.56.78"), server.Status.PublicIP)
		require.Equal(t, ptr.To(serverPortMAC), server.Status.MACAddress)
	})
}

func TestLoadBalancerNetwork(t *testing.T) {
	t.Parallel()

	t.Run("ItHasNoNetworkLabel", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		delete(lb.Labels, constants.NetworkLabel)

		c := getClient(t, []client.Object{network})
		p := openstack.NewTestProvider(c, regionFixture())

		_, err := openstack.LoadBalancerNetwork(t.Context(), p, lb)
		require.ErrorIs(t, err, errors.ErrConsistency)
	})

	t.Run("ItReferencesMissingNetwork", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		c := getClient(t, nil)
		p := openstack.NewTestProvider(c, regionFixture())

		_, err := openstack.LoadBalancerNetwork(t.Context(), p, lb)
		require.ErrorIs(t, err, errors.ErrConsistency)
	})

	t.Run("ItFindsTheNetwork", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		c := getClient(t, []client.Object{network})
		p := openstack.NewTestProvider(c, regionFixture())

		got, err := openstack.LoadBalancerNetwork(t.Context(), p, lb)
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, network.Name, got.Name)
	})
}

func TestReconcileLoadBalancer(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	t.Run("ItDoesntExist", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network,
			withRequestedVIP("10.0.0.42"),
		)

		osLB := openstackLoadBalancerFixture(lb)

		expectedOpts := openstack.BuildLoadBalancerCreateOpts(lb, *network.Status.Openstack.SubnetID)

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(nil, errors.ErrResourceNotFound)
		lbClient.EXPECT().CreateLoadBalancer(t.Context(), expectedOpts).Return(osLB, nil)

		client := getClient(t, []client.Object{network})
		p := openstack.NewTestProvider(client, regionFixture())

		got, err := openstack.ReconcileLoadBalancer(t.Context(), p, lbClient, lb, *network.Status.Openstack.SubnetID)
		require.NoError(t, err)
		require.Equal(t, osLB.ID, got.ID)
		require.NotNil(t, lb.Status.VIPAddress)
		require.Equal(t, osLB.VipAddress, lb.Status.VIPAddress.String())
	})

	t.Run("ItIsAlreadyCorrect", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		osLB := openstackLoadBalancerFixture(lb)

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)

		client := getClient(t, []client.Object{network})
		p := openstack.NewTestProvider(client, regionFixture())

		got, err := openstack.ReconcileLoadBalancer(t.Context(), p, lbClient, lb, *network.Status.Openstack.SubnetID)
		require.NoError(t, err)
		require.Equal(t, osLB.ID, got.ID)
		require.Equal(t, "ACTIVE", got.ProvisioningStatus)
		require.NotNil(t, lb.Status.VIPAddress)
		require.Equal(t, osLB.VipAddress, lb.Status.VIPAddress.String())
	})

	t.Run("ItIsPending", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		osLB := openstackLoadBalancerFixture(lb, withProvisioningStatus("PENDING_UPDATE"))

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)

		client := getClient(t, []client.Object{network})
		p := openstack.NewTestProvider(client, regionFixture())

		got, err := openstack.ReconcileLoadBalancer(t.Context(), p, lbClient, lb, *network.Status.Openstack.SubnetID)
		require.NoError(t, err)
		require.Equal(t, "PENDING_UPDATE", got.ProvisioningStatus)
		require.NotNil(t, lb.Status.VIPAddress)
		require.Equal(t, osLB.VipAddress, lb.Status.VIPAddress.String())
	})

	t.Run("ItHasMismatchedVIP", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network, withRequestedVIP("10.0.0.5"))

		osLB := openstackLoadBalancerFixture(lb, withVip("10.0.0.7"))

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)

		client := getClient(t, []client.Object{network})
		p := openstack.NewTestProvider(client, regionFixture())

		_, err := openstack.ReconcileLoadBalancer(t.Context(), p, lbClient, lb, *network.Status.Openstack.SubnetID)
		require.ErrorIs(t, err, errors.ErrConsistency)
		require.NotNil(t, lb.Status.VIPAddress)
		require.Equal(t, "10.0.0.7", lb.Status.VIPAddress.String())
	})
}

func TestBuildLoadBalancerCreateOpts(t *testing.T) {
	t.Parallel()

	t.Run("Minimal", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		opts := openstack.BuildLoadBalancerCreateOpts(lb, *network.Status.Openstack.SubnetID)

		require.Equal(t, openstack.LoadBalancerName(lb), opts.Name)
		require.Equal(t, *network.Status.Openstack.SubnetID, opts.VipSubnetID)
		require.Empty(t, opts.VipAddress)
		require.Len(t, opts.Listeners, 1)

		listener := opts.Listeners[0]
		require.Equal(t, listeners.ProtocolTCP, listener.Protocol)
		require.Equal(t, 80, listener.ProtocolPort)
		require.Nil(t, listener.AllowedCIDRs)
		require.Equal(t, ptr.To(60000), listener.TimeoutClientData)
		require.Equal(t, ptr.To(60000), listener.TimeoutMemberData)

		require.NotNil(t, listener.DefaultPool)
		require.Equal(t, pools.ProtocolTCP, listener.DefaultPool.Protocol)
		require.Equal(t, pools.LBMethodRoundRobin, listener.DefaultPool.LBMethod)

		require.Len(t, listener.DefaultPool.Members, 1)
		require.Equal(t, "10.0.0.5", listener.DefaultPool.Members[0].Address)
		require.Equal(t, 8080, listener.DefaultPool.Members[0].ProtocolPort)
		require.Empty(t, listener.DefaultPool.Members[0].SubnetID)
		require.Nil(t, listener.DefaultPool.Members[0].Weight)

		require.Nil(t, listener.DefaultPool.Monitor)
	})

	t.Run("WithRequestedVIP", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network, withRequestedVIP("10.0.0.42"))

		opts := openstack.BuildLoadBalancerCreateOpts(lb, *network.Status.Openstack.SubnetID)
		require.Equal(t, "10.0.0.42", opts.VipAddress)
	})

	t.Run("WithProxyProtocolV2", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("proxy", regionv1.LoadBalancerListenerProtocolTCP, 443,
				withMember("10.0.0.5", 8443),
				withProxyProtocolV2(),
			),
		}

		opts := openstack.BuildLoadBalancerCreateOpts(lb, *network.Status.Openstack.SubnetID)
		require.Len(t, opts.Listeners, 1)
		require.Equal(t, pools.ProtocolPROXYV2, opts.Listeners[0].DefaultPool.Protocol)
	})

	t.Run("WithHealthCheck", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("http", regionv1.LoadBalancerListenerProtocolTCP, 80,
				withMember("10.0.0.5", 8080),
				withHealthCheck(10, 5, 3, 3),
			),
		}

		opts := openstack.BuildLoadBalancerCreateOpts(lb, *network.Status.Openstack.SubnetID)
		require.NotNil(t, opts.Listeners[0].DefaultPool.Monitor)

		monitorOpts, ok := opts.Listeners[0].DefaultPool.Monitor.(monitors.CreateOpts)
		require.True(t, ok)
		require.Equal(t, monitors.TypeTCP, monitorOpts.Type)
		require.Equal(t, 10, monitorOpts.Delay)
		require.Equal(t, 5, monitorOpts.Timeout)
		require.Equal(t, 3, monitorOpts.MaxRetries)
		require.Equal(t, 3, monitorOpts.MaxRetriesDown)
	})

	t.Run("WithIdleTimeout", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("http", regionv1.LoadBalancerListenerProtocolTCP, 80,
				withMember("10.0.0.5", 8080),
				withIdleTimeoutSeconds(60),
			),
		}

		opts := openstack.BuildLoadBalancerCreateOpts(lb, *network.Status.Openstack.SubnetID)
		require.Equal(t, ptr.To(60000), opts.Listeners[0].TimeoutClientData)
		require.Equal(t, ptr.To(60000), opts.Listeners[0].TimeoutMemberData)
	})

	t.Run("MultipleListeners", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("http", regionv1.LoadBalancerListenerProtocolTCP, 80,
				withMember("10.0.0.5", 8080),
			),
			listenerFixture("dns", regionv1.LoadBalancerListenerProtocolUDP, 53,
				withMember("10.0.0.6", 53),
			),
		}

		opts := openstack.BuildLoadBalancerCreateOpts(lb, *network.Status.Openstack.SubnetID)
		require.Len(t, opts.Listeners, 2)
		require.Equal(t, listeners.ProtocolTCP, opts.Listeners[0].Protocol)
		require.Equal(t, listeners.ProtocolUDP, opts.Listeners[1].Protocol)
		require.Equal(t, pools.ProtocolUDP, opts.Listeners[1].DefaultPool.Protocol)
	})

	t.Run("UDPListenerHasNilTimeouts", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("dns", regionv1.LoadBalancerListenerProtocolUDP, 53,
				withMember("10.0.0.6", 53),
			),
		}

		opts := openstack.BuildLoadBalancerCreateOpts(lb, *network.Status.Openstack.SubnetID)
		require.Len(t, opts.Listeners, 1)
		require.Nil(t, opts.Listeners[0].TimeoutClientData)
		require.Nil(t, opts.Listeners[0].TimeoutMemberData)
	})
}

func TestReconcileListener(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	t.Run("ItDoesntExist", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("http", regionv1.LoadBalancerListenerProtocolTCP, 80,
				withMember("10.0.0.5", 8080),
				withIdleTimeoutSeconds(60),
				withAllowedCIDRs("10.0.0.0/8"),
			),
		}
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)
		osListener := openstackListenerFixture(lb, listener)

		expectedOpts := openstack.BuildListenerCreateOpts(lb, listener, osLB.ID, osPool.ID)

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetListener(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(nil, errors.ErrResourceNotFound)
		lbClient.EXPECT().CreateListener(t.Context(), expectedOpts).Return(osListener, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		got, err := openstack.ReconcileListener(t.Context(), p, lbClient, lb, listener, osLB.ID, osPool.ID)
		require.NoError(t, err)
		require.Equal(t, osListener.ID, got.ID)
	})

	t.Run("ItIsAlreadyCorrect", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("http", regionv1.LoadBalancerListenerProtocolTCP, 80,
				withMember("10.0.0.5", 8080),
				withAllowedCIDRs("10.0.0.0/8"),
			),
		}
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)
		osListener := openstackListenerFixture(lb, listener)
		osListener.AllowedCIDRs = []string{"10.0.0.0/8"}
		osListener.DefaultPoolID = osPool.ID

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetListener(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osListener, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		got, err := openstack.ReconcileListener(t.Context(), p, lbClient, lb, listener, osLB.ID, osPool.ID)
		require.NoError(t, err)
		require.Equal(t, osListener.ID, got.ID)
	})

	t.Run("ItUpdatesAllowedCIDRsOnly", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("http", regionv1.LoadBalancerListenerProtocolTCP, 80,
				withMember("10.0.0.5", 8080),
				withAllowedCIDRs("10.0.0.0/8"),
			),
		}
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)
		osListener := openstackListenerFixture(lb, listener)
		osListener.AllowedCIDRs = []string{"172.16.0.0/12"}
		osListener.DefaultPoolID = osPool.ID

		expectedUpdate := listeners.UpdateOpts{
			AllowedCIDRs: &[]string{"10.0.0.0/8"},
		}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetListener(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osListener, nil)
		lbClient.EXPECT().UpdateListener(t.Context(), osListener.ID, expectedUpdate).Return(osListener, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		_, err := openstack.ReconcileListener(t.Context(), p, lbClient, lb, listener, osLB.ID, osPool.ID)
		require.NoError(t, err)
	})

	t.Run("ItClearsAllowedCIDRs", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)
		osListener := openstackListenerFixture(lb, listener)
		osListener.AllowedCIDRs = []string{"10.0.0.0/8"}
		osListener.DefaultPoolID = osPool.ID

		expectedUpdate := listeners.UpdateOpts{
			AllowedCIDRs: &[]string{},
		}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetListener(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osListener, nil)
		lbClient.EXPECT().UpdateListener(t.Context(), osListener.ID, expectedUpdate).Return(osListener, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		_, err := openstack.ReconcileListener(t.Context(), p, lbClient, lb, listener, osLB.ID, osPool.ID)
		require.NoError(t, err)
	})

	t.Run("ItUpdatesDefaultPoolIDOnly", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)
		osListener := openstackListenerFixture(lb, listener)
		osListener.DefaultPoolID = string(uuid.NewUUID())

		expectedUpdate := listeners.UpdateOpts{
			DefaultPoolID: ptr.To(osPool.ID),
		}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetListener(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osListener, nil)
		lbClient.EXPECT().UpdateListener(t.Context(), osListener.ID, expectedUpdate).Return(osListener, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		_, err := openstack.ReconcileListener(t.Context(), p, lbClient, lb, listener, osLB.ID, osPool.ID)
		require.NoError(t, err)
	})

	t.Run("ItUpdatesTimeoutToDefaultWhenSpecOmitted", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)
		osListener := openstackListenerFixture(lb, listener)
		osListener.DefaultPoolID = osPool.ID
		osListener.TimeoutClientData = 30000
		osListener.TimeoutMemberData = 30000

		expectedUpdate := listeners.UpdateOpts{
			TimeoutClientData: ptr.To(60000),
			TimeoutMemberData: ptr.To(60000),
		}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetListener(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osListener, nil)
		lbClient.EXPECT().UpdateListener(t.Context(), osListener.ID, expectedUpdate).Return(osListener, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		_, err := openstack.ReconcileListener(t.Context(), p, lbClient, lb, listener, osLB.ID, osPool.ID)
		require.NoError(t, err)
	})

	t.Run("ItSkipsTimeoutUpdateWhenSpecIsNil", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("dns", regionv1.LoadBalancerListenerProtocolUDP, 53,
				withMember("10.0.0.6", 53),
			),
		}
		listener := &lb.Spec.Listeners[0]
		require.Nil(t, listener.IdleTimeoutSeconds)

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)
		osListener := openstackListenerFixture(lb, listener)
		osListener.DefaultPoolID = osPool.ID

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetListener(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("dns")).Return(osListener, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		got, err := openstack.ReconcileListener(t.Context(), p, lbClient, lb, listener, osLB.ID, osPool.ID)
		require.NoError(t, err)
		require.Equal(t, osListener.ID, got.ID)
	})
}

func TestReconcilePool(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	t.Run("ItDoesntExist", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)

		expectedOpts := openstack.BuildPoolCreateOpts(lb, listener)
		expectedOpts.LoadbalancerID = osLB.ID

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetPool(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(nil, errors.ErrResourceNotFound)
		lbClient.EXPECT().CreatePool(t.Context(), expectedOpts).Return(osPool, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		got, err := openstack.ReconcilePool(t.Context(), p, lbClient, lb, listener, osLB.ID)
		require.NoError(t, err)
		require.Equal(t, osPool.ID, got.ID)
	})

	t.Run("ItHasProxyProtocolV2", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("proxy", regionv1.LoadBalancerListenerProtocolTCP, 443,
				withMember("10.0.0.5", 8443),
				withProxyProtocolV2(),
			),
		}
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)

		expectedOpts := openstack.BuildPoolCreateOpts(lb, listener)
		expectedOpts.LoadbalancerID = osLB.ID
		require.Equal(t, pools.ProtocolPROXYV2, expectedOpts.Protocol)

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetPool(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("proxy")).Return(nil, errors.ErrResourceNotFound)
		lbClient.EXPECT().CreatePool(t.Context(), expectedOpts).Return(osPool, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		_, err := openstack.ReconcilePool(t.Context(), p, lbClient, lb, listener, osLB.ID)
		require.NoError(t, err)
	})

	t.Run("ItIsUDP", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("dns", regionv1.LoadBalancerListenerProtocolUDP, 53,
				withMember("10.0.0.6", 53),
			),
		}
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)

		expectedOpts := openstack.BuildPoolCreateOpts(lb, listener)
		expectedOpts.LoadbalancerID = osLB.ID
		require.Equal(t, pools.ProtocolUDP, expectedOpts.Protocol)

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetPool(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("dns")).Return(nil, errors.ErrResourceNotFound)
		lbClient.EXPECT().CreatePool(t.Context(), expectedOpts).Return(osPool, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		_, err := openstack.ReconcilePool(t.Context(), p, lbClient, lb, listener, osLB.ID)
		require.NoError(t, err)
	})

	t.Run("ItIsAlreadyCorrect", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetPool(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osPool, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		got, err := openstack.ReconcilePool(t.Context(), p, lbClient, lb, listener, osLB.ID)
		require.NoError(t, err)
		require.Equal(t, osPool.ID, got.ID)
	})
}

func TestReconcileMembers(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	t.Run("ItIsIdempotent", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		listener := &lb.Spec.Listeners[0]

		osPool := openstackPoolFixture(lb, listener)

		liveMembers := []pools.Member{
			openstackMemberFixture("10.0.0.5", 8080),
		}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().ListMembers(t.Context(), osPool.ID).Return(liveMembers, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		mutated, err := openstack.ReconcileMembers(t.Context(), p, lbClient, lb, listener, osPool.ID)
		require.NoError(t, err)
		require.False(t, mutated)
	})

	t.Run("ItIsIdempotentRegardlessOfOrder", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("http", regionv1.LoadBalancerListenerProtocolTCP, 80,
				withMember("10.0.0.5", 8080),
				withMember("10.0.0.6", 8080),
			),
		}
		listener := &lb.Spec.Listeners[0]

		osPool := openstackPoolFixture(lb, listener)

		liveMembers := []pools.Member{
			openstackMemberFixture("10.0.0.6", 8080),
			openstackMemberFixture("10.0.0.5", 8080),
		}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().ListMembers(t.Context(), osPool.ID).Return(liveMembers, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		mutated, err := openstack.ReconcileMembers(t.Context(), p, lbClient, lb, listener, osPool.ID)
		require.NoError(t, err)
		require.False(t, mutated)
	})

	t.Run("ItHasNewMembers", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("http", regionv1.LoadBalancerListenerProtocolTCP, 80,
				withMember("10.0.0.5", 8080),
				withMember("10.0.0.6", 8080),
			),
		}
		listener := &lb.Spec.Listeners[0]

		osPool := openstackPoolFixture(lb, listener)

		expectedPayload := []pools.BatchUpdateMemberOpts{
			{Address: "10.0.0.5", ProtocolPort: 8080},
			{Address: "10.0.0.6", ProtocolPort: 8080},
		}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().ListMembers(t.Context(), osPool.ID).Return(nil, nil)
		lbClient.EXPECT().BatchUpdateMembers(t.Context(), osPool.ID, expectedPayload).Return(nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		mutated, err := openstack.ReconcileMembers(t.Context(), p, lbClient, lb, listener, osPool.ID)
		require.NoError(t, err)
		require.True(t, mutated)
	})

	t.Run("ItHasRemovedMember", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		listener := &lb.Spec.Listeners[0]

		osPool := openstackPoolFixture(lb, listener)

		liveMembers := []pools.Member{
			openstackMemberFixture("10.0.0.5", 8080),
			openstackMemberFixture("10.0.0.99", 8080),
		}

		expectedPayload := []pools.BatchUpdateMemberOpts{
			{Address: "10.0.0.5", ProtocolPort: 8080},
		}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().ListMembers(t.Context(), osPool.ID).Return(liveMembers, nil)
		lbClient.EXPECT().BatchUpdateMembers(t.Context(), osPool.ID, expectedPayload).Return(nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		mutated, err := openstack.ReconcileMembers(t.Context(), p, lbClient, lb, listener, osPool.ID)
		require.NoError(t, err)
		require.True(t, mutated)
	})
}

func TestReconcileMonitor(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	t.Run("ItDoesntExist", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("http", regionv1.LoadBalancerListenerProtocolTCP, 80,
				withMember("10.0.0.5", 8080),
				withHealthCheck(10, 5, 3, 3),
			),
		}
		listener := &lb.Spec.Listeners[0]

		osPool := openstackPoolFixture(lb, listener)
		osMonitor := openstackMonitorFixture(lb, listener)

		expectedOpts := openstack.BuildMonitorCreateOpts(lb, listener, osPool.ID)

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetMonitor(t.Context(), osPool.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(nil, errors.ErrResourceNotFound)
		lbClient.EXPECT().CreateMonitor(t.Context(), expectedOpts).Return(osMonitor, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		got, err := openstack.ReconcileMonitor(t.Context(), p, lbClient, lb, listener, osPool.ID)
		require.NoError(t, err)
		require.Equal(t, osMonitor.ID, got.ID)
	})

	t.Run("ItIsAlreadyCorrect", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("http", regionv1.LoadBalancerListenerProtocolTCP, 80,
				withMember("10.0.0.5", 8080),
				withHealthCheck(10, 5, 3, 3),
			),
		}
		listener := &lb.Spec.Listeners[0]

		osPool := openstackPoolFixture(lb, listener)
		osMonitor := openstackMonitorFixture(lb, listener)

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetMonitor(t.Context(), osPool.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osMonitor, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		got, err := openstack.ReconcileMonitor(t.Context(), p, lbClient, lb, listener, osPool.ID)
		require.NoError(t, err)
		require.Equal(t, osMonitor.ID, got.ID)
	})

	t.Run("ItUpdatesDelayOnly", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("http", regionv1.LoadBalancerListenerProtocolTCP, 80,
				withMember("10.0.0.5", 8080),
				withHealthCheck(10, 5, 3, 3),
			),
		}
		listener := &lb.Spec.Listeners[0]

		osPool := openstackPoolFixture(lb, listener)
		osMonitor := openstackMonitorFixture(lb, listener)
		osMonitor.Delay = 5

		expectedUpdate := monitors.UpdateOpts{
			Delay: 10,
		}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetMonitor(t.Context(), osPool.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osMonitor, nil)
		lbClient.EXPECT().UpdateMonitor(t.Context(), osMonitor.ID, expectedUpdate).Return(osMonitor, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		_, err := openstack.ReconcileMonitor(t.Context(), p, lbClient, lb, listener, osPool.ID)
		require.NoError(t, err)
	})

	t.Run("ItUpdatesAllFourFields", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("http", regionv1.LoadBalancerListenerProtocolTCP, 80,
				withMember("10.0.0.5", 8080),
				withHealthCheck(10, 5, 3, 3),
			),
		}
		listener := &lb.Spec.Listeners[0]

		osPool := openstackPoolFixture(lb, listener)
		osMonitor := openstackMonitorFixture(lb, listener)
		osMonitor.Delay = 1
		osMonitor.Timeout = 1
		osMonitor.MaxRetries = 1
		osMonitor.MaxRetriesDown = 1

		expectedUpdate := monitors.UpdateOpts{
			Delay:          10,
			Timeout:        5,
			MaxRetries:     3,
			MaxRetriesDown: 3,
		}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetMonitor(t.Context(), osPool.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osMonitor, nil)
		lbClient.EXPECT().UpdateMonitor(t.Context(), osMonitor.ID, expectedUpdate).Return(osMonitor, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		_, err := openstack.ReconcileMonitor(t.Context(), p, lbClient, lb, listener, osPool.ID)
		require.NoError(t, err)
	})
}

//nolint:dupl // distinct mock surfaces and assertions; sharing would obscure intent.
func TestPruneOrphanedListenersOnce(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	t.Run("ItHasNothingToPrune", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osListener := openstackListenerFixture(lb, listener)

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().ListListeners(t.Context(), osLB.ID, "").Return([]listeners.Listener{*osListener}, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		mutated, err := openstack.PruneOrphanedListenersOnce(t.Context(), p, lbClient, lb, osLB.ID)
		require.NoError(t, err)
		require.False(t, mutated)
	})

	t.Run("ItDeletesRenamedListener", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		osLB := openstackLoadBalancerFixture(lb)

		oldListener := listeners.Listener{
			ID:   string(uuid.NewUUID()),
			Name: openstack.LoadBalancerName(lb) + "-old-listener",
		}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().ListListeners(t.Context(), osLB.ID, "").Return([]listeners.Listener{oldListener}, nil)
		lbClient.EXPECT().DeleteListener(t.Context(), oldListener.ID).Return(nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		mutated, err := openstack.PruneOrphanedListenersOnce(t.Context(), p, lbClient, lb, osLB.ID)
		require.NoError(t, err)
		require.True(t, mutated)
	})
}

//nolint:dupl // distinct mock surfaces and assertions; sharing would obscure intent.
func TestPruneOrphanedPoolsAndMonitorsOnce(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	t.Run("ItHasNothingToPrune", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().ListPools(t.Context(), osLB.ID, "").Return([]pools.Pool{*osPool}, nil)
		lbClient.EXPECT().ListMonitors(t.Context(), osPool.ID, "").Return([]monitors.Monitor{}, nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		mutated, err := openstack.PruneOrphanedPoolsAndMonitorsOnce(t.Context(), p, lbClient, lb, osLB.ID)
		require.NoError(t, err)
		require.False(t, mutated)
	})

	t.Run("ItDeletesOrphanedPool", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		osLB := openstackLoadBalancerFixture(lb)

		oldPool := pools.Pool{
			ID:   string(uuid.NewUUID()),
			Name: openstack.LoadBalancerName(lb) + "-old-pool",
		}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().ListPools(t.Context(), osLB.ID, "").Return([]pools.Pool{oldPool}, nil)
		lbClient.EXPECT().DeletePool(t.Context(), oldPool.ID).Return(nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		mutated, err := openstack.PruneOrphanedPoolsAndMonitorsOnce(t.Context(), p, lbClient, lb, osLB.ID)
		require.NoError(t, err)
		require.True(t, mutated)
	})

	t.Run("ItDeletesOrphanedMonitor", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)

		oldMonitor := monitors.Monitor{
			ID:   string(uuid.NewUUID()),
			Name: openstack.LoadBalancerName(lb) + "-old-monitor",
		}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().ListPools(t.Context(), osLB.ID, "").Return([]pools.Pool{*osPool}, nil)
		lbClient.EXPECT().ListMonitors(t.Context(), osPool.ID, "").Return([]monitors.Monitor{oldMonitor}, nil)
		lbClient.EXPECT().DeleteMonitor(t.Context(), oldMonitor.ID).Return(nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		mutated, err := openstack.PruneOrphanedPoolsAndMonitorsOnce(t.Context(), p, lbClient, lb, osLB.ID)
		require.NoError(t, err)
		require.True(t, mutated)
	})

	t.Run("ItDeletesMonitorWhenHealthCheckRemoved", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)

		// The live monitor is owned by the desired pool but the spec listener
		// no longer declares a HealthCheck — desiredLoadBalancerNames omits the
		// monitor, and pruneOrphanedMonitor should delete it.
		liveMonitor := monitors.Monitor{
			ID:   string(uuid.NewUUID()),
			Name: openstack.LoadBalancerMonitorName(lb, listener),
		}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().ListPools(t.Context(), osLB.ID, "").Return([]pools.Pool{*osPool}, nil)
		lbClient.EXPECT().ListMonitors(t.Context(), osPool.ID, "").Return([]monitors.Monitor{liveMonitor}, nil)
		lbClient.EXPECT().DeleteMonitor(t.Context(), liveMonitor.ID).Return(nil)

		p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

		mutated, err := openstack.PruneOrphanedPoolsAndMonitorsOnce(t.Context(), p, lbClient, lb, osLB.ID)
		require.NoError(t, err)
		require.True(t, mutated)
	})
}

func TestClassifyOctaviaStatus(t *testing.T) {
	t.Parallel()

	t.Run("Active", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, openstack.ClassifyOctaviaStatus("loadbalancer", "name", "ACTIVE"))
	})

	pendings := []string{"PENDING_CREATE", "PENDING_UPDATE", "PENDING_DELETE"}
	for _, status := range pendings {
		t.Run("Pending/"+status, func(t *testing.T) {
			t.Parallel()

			err := openstack.ClassifyOctaviaStatus("pool", "name", status)
			require.ErrorIs(t, err, provisioners.ErrYield)
		})
	}

	terminals := []string{"ERROR", "DELETED", ""}
	for _, status := range terminals {
		t.Run("Terminal/"+status, func(t *testing.T) {
			t.Parallel()

			err := openstack.ClassifyOctaviaStatus("listener", "name", status)
			require.ErrorIs(t, err, errors.ErrConsistency)
		})
	}
}

//nolint:maintidx // table of focused subtests; splitting would fragment the reconcile contract.
func TestCreateLoadBalancer(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	t.Run("MissingVIP_Errors", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		osLB := openstackLoadBalancerFixture(lb, withVip(""))

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)

		p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())

		err := openstack.CreateLoadBalancerWithClient(t.Context(), p, lbClient, nil, lb, *network.Status.Openstack.SubnetID)
		require.ErrorIs(t, err, errors.ErrConsistency)
	})

	t.Run("MalformedVIP_Errors", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		osLB := openstackLoadBalancerFixture(lb, withVip("not-an-ip"))

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)

		p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())

		err := openstack.CreateLoadBalancerWithClient(t.Context(), p, lbClient, nil, lb, *network.Status.Openstack.SubnetID)
		require.ErrorIs(t, err, errors.ErrConsistency)
	})

	t.Run("LBPending_Yields", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		osLB := openstackLoadBalancerFixture(lb, withProvisioningStatus("PENDING_UPDATE"))

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)

		p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())

		err := openstack.CreateLoadBalancerWithClient(t.Context(), p, lbClient, nil, lb, *network.Status.Openstack.SubnetID)
		require.ErrorIs(t, err, provisioners.ErrYield)
	})

	t.Run("LBTerminal_Errors", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		osLB := openstackLoadBalancerFixture(lb, withProvisioningStatus("ERROR"))

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)

		p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())

		err := openstack.CreateLoadBalancerWithClient(t.Context(), p, lbClient, nil, lb, *network.Status.Openstack.SubnetID)
		require.ErrorIs(t, err, errors.ErrConsistency)
	})

	t.Run("ZeroMembers_Provisioned", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("http", regionv1.LoadBalancerListenerProtocolTCP, 80),
		}
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)
		osListener := openstackListenerFixture(lb, listener)
		osListener.DefaultPoolID = osPool.ID

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)
		lbClient.EXPECT().ListListeners(t.Context(), osLB.ID, "").Return([]listeners.Listener{*osListener}, nil)
		lbClient.EXPECT().GetPool(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osPool, nil)
		lbClient.EXPECT().GetListener(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osListener, nil)
		lbClient.EXPECT().ListMembers(t.Context(), osPool.ID).Return(nil, nil)
		lbClient.EXPECT().ListPools(t.Context(), osLB.ID, "").Return([]pools.Pool{*osPool}, nil)
		lbClient.EXPECT().ListMonitors(t.Context(), osPool.ID, "").Return(nil, nil)

		networkClient := expectNoFloatingIP(t, c, osLB.VipPortID)

		p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())

		err := openstack.CreateLoadBalancerWithClient(t.Context(), p, lbClient, networkClient, lb, *network.Status.Openstack.SubnetID)
		require.NoError(t, err)
	})

	t.Run("MembersChanged_Yields", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)
		osListener := openstackListenerFixture(lb, listener)
		osListener.DefaultPoolID = osPool.ID

		expectedPayload := []pools.BatchUpdateMemberOpts{
			{Address: "10.0.0.5", ProtocolPort: 8080},
		}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)
		lbClient.EXPECT().ListListeners(t.Context(), osLB.ID, "").Return([]listeners.Listener{*osListener}, nil)
		lbClient.EXPECT().GetPool(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osPool, nil)
		lbClient.EXPECT().GetListener(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osListener, nil)
		lbClient.EXPECT().ListMembers(t.Context(), osPool.ID).Return([]pools.Member{
			openstackMemberFixture("10.0.0.99", 8080),
		}, nil)
		lbClient.EXPECT().BatchUpdateMembers(t.Context(), osPool.ID, expectedPayload).Return(nil)

		networkClient := expectNoFloatingIP(t, c, osLB.VipPortID)

		p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())

		err := openstack.CreateLoadBalancerWithClient(t.Context(), p, lbClient, networkClient, lb, *network.Status.Openstack.SubnetID)
		require.ErrorIs(t, err, provisioners.ErrYield)
	})

	t.Run("OrphanListenerPruned_Yields", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		osLB := openstackLoadBalancerFixture(lb)

		oldListener := listeners.Listener{
			ID:   string(uuid.NewUUID()),
			Name: openstack.LoadBalancerName(lb) + "-old",
		}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		gomock.InOrder(
			lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil),
			lbClient.EXPECT().ListListeners(t.Context(), osLB.ID, "").Return([]listeners.Listener{oldListener}, nil),
			lbClient.EXPECT().DeleteListener(t.Context(), oldListener.ID).Return(nil),
		)

		networkClient := expectNoFloatingIP(t, c, osLB.VipPortID)

		p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())

		err := openstack.CreateLoadBalancerWithClient(t.Context(), p, lbClient, networkClient, lb, *network.Status.Openstack.SubnetID)
		require.ErrorIs(t, err, provisioners.ErrYield)
	})

	t.Run("ListenerRename_PruneFirst", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("api", regionv1.LoadBalancerListenerProtocolTCP, 80,
				withMember("10.0.0.5", 8080),
			),
		}

		osLB := openstackLoadBalancerFixture(lb)

		// Live listener uses the old "http" name on the same TCP/80 port —
		// without prune-first, a CreateListener for "api" would conflict.
		oldListener := listeners.Listener{
			ID:           string(uuid.NewUUID()),
			Name:         openstack.LoadBalancerName(lb) + "-http",
			Protocol:     string(listeners.ProtocolTCP),
			ProtocolPort: 80,
		}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		gomock.InOrder(
			lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil),
			lbClient.EXPECT().ListListeners(t.Context(), osLB.ID, "").Return([]listeners.Listener{oldListener}, nil),
			lbClient.EXPECT().DeleteListener(t.Context(), oldListener.ID).Return(nil),
		)

		networkClient := expectNoFloatingIP(t, c, osLB.VipPortID)

		p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())

		err := openstack.CreateLoadBalancerWithClient(t.Context(), p, lbClient, networkClient, lb, *network.Status.Openstack.SubnetID)
		require.ErrorIs(t, err, provisioners.ErrYield)
	})

	t.Run("OrphanPoolPruned_Yields", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)
		osListener := openstackListenerFixture(lb, listener)
		osListener.DefaultPoolID = osPool.ID

		oldPool := pools.Pool{
			ID:   string(uuid.NewUUID()),
			Name: openstack.LoadBalancerName(lb) + "-old-pool",
		}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)
		lbClient.EXPECT().ListListeners(t.Context(), osLB.ID, "").Return([]listeners.Listener{*osListener}, nil)
		lbClient.EXPECT().GetPool(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osPool, nil)
		lbClient.EXPECT().GetListener(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osListener, nil)
		lbClient.EXPECT().ListMembers(t.Context(), osPool.ID).Return([]pools.Member{
			openstackMemberFixture("10.0.0.5", 8080),
		}, nil)
		lbClient.EXPECT().ListPools(t.Context(), osLB.ID, "").Return([]pools.Pool{*osPool, oldPool}, nil)
		lbClient.EXPECT().DeletePool(t.Context(), oldPool.ID).Return(nil)

		networkClient := expectNoFloatingIP(t, c, osLB.VipPortID)

		p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())

		err := openstack.CreateLoadBalancerWithClient(t.Context(), p, lbClient, networkClient, lb, *network.Status.Openstack.SubnetID)
		require.ErrorIs(t, err, provisioners.ErrYield)
	})

	t.Run("PoolLBMethodDrift_Updated_Yields", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)
		osPool.LBMethod = string(pools.LBMethodLeastConnections)
		osListener := openstackListenerFixture(lb, listener)

		// UpdatePool returns the pool in PENDING_UPDATE — the classify gate
		// then yields without invoking reconcileListener.
		updatedPool := *osPool
		updatedPool.ProvisioningStatus = "PENDING_UPDATE"
		updatedPool.LBMethod = string(pools.LBMethodRoundRobin)

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)
		lbClient.EXPECT().ListListeners(t.Context(), osLB.ID, "").Return([]listeners.Listener{*osListener}, nil)
		lbClient.EXPECT().GetPool(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osPool, nil)
		lbClient.EXPECT().UpdatePool(t.Context(), osPool.ID, pools.UpdateOpts{LBMethod: pools.LBMethodRoundRobin}).Return(&updatedPool, nil)

		networkClient := expectNoFloatingIP(t, c, osLB.VipPortID)

		p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())

		err := openstack.CreateLoadBalancerWithClient(t.Context(), p, lbClient, networkClient, lb, *network.Status.Openstack.SubnetID)
		require.ErrorIs(t, err, provisioners.ErrYield)
	})

	t.Run("Steady_State_NoMutations_NoYield", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)
		osListener := openstackListenerFixture(lb, listener)
		osListener.DefaultPoolID = osPool.ID

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)
		lbClient.EXPECT().ListListeners(t.Context(), osLB.ID, "").Return([]listeners.Listener{*osListener}, nil)
		lbClient.EXPECT().GetPool(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osPool, nil)
		lbClient.EXPECT().GetListener(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osListener, nil)
		lbClient.EXPECT().ListMembers(t.Context(), osPool.ID).Return([]pools.Member{
			openstackMemberFixture("10.0.0.5", 8080),
		}, nil)
		lbClient.EXPECT().ListPools(t.Context(), osLB.ID, "").Return([]pools.Pool{*osPool}, nil)
		lbClient.EXPECT().ListMonitors(t.Context(), osPool.ID, "").Return(nil, nil)

		networkClient := expectNoFloatingIP(t, c, osLB.VipPortID)

		p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())

		err := openstack.CreateLoadBalancerWithClient(t.Context(), p, lbClient, networkClient, lb, *network.Status.Openstack.SubnetID)
		require.NoError(t, err)
	})

	t.Run("PublicIP_Reconciled", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network, withPublicIP())
		lb.Spec.Listeners = []regionv1.LoadBalancerListener{
			listenerFixture("http", regionv1.LoadBalancerListenerProtocolTCP, 80),
		}
		listener := &lb.Spec.Listeners[0]

		osLB := openstackLoadBalancerFixture(lb)
		osPool := openstackPoolFixture(lb, listener)
		osListener := openstackListenerFixture(lb, listener)
		osListener.DefaultPoolID = osPool.ID

		openstackFloatingIP := openstackFloatingIPFixture(&ports.Port{ID: osLB.VipPortID})

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)
		lbClient.EXPECT().ListListeners(t.Context(), osLB.ID, "").Return([]listeners.Listener{*osListener}, nil)
		lbClient.EXPECT().GetPool(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osPool, nil)
		lbClient.EXPECT().GetListener(t.Context(), osLB.ID, loadBalancerMatcher(lb), listenerCRDMatcher("http")).Return(osListener, nil)
		lbClient.EXPECT().ListMembers(t.Context(), osPool.ID).Return(nil, nil)
		lbClient.EXPECT().ListPools(t.Context(), osLB.ID, "").Return([]pools.Pool{*osPool}, nil)
		lbClient.EXPECT().ListMonitors(t.Context(), osPool.ID, "").Return(nil, nil)

		networkClient := mock.NewMockNetworkingInterface(c)
		networkClient.EXPECT().GetFloatingIP(t.Context(), osLB.VipPortID).Return(nil, errors.ErrResourceNotFound)
		networkClient.EXPECT().CreateFloatingIP(t.Context(), osLB.VipPortID).Return(openstackFloatingIP, nil)

		p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())

		err := openstack.CreateLoadBalancerWithClient(t.Context(), p, lbClient, networkClient, lb, *network.Status.Openstack.SubnetID)
		require.NoError(t, err)
		require.NotNil(t, lb.Status.PublicIP)
		require.Equal(t, openstackFloatingIP.FloatingIP, lb.Status.PublicIP.String())
	})

	t.Run("EmptyVipPortID_Errors", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		osLB := openstackLoadBalancerFixture(lb, withVipPortID(""))

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)

		p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())

		err := openstack.CreateLoadBalancerWithClient(t.Context(), p, lbClient, nil, lb, *network.Status.Openstack.SubnetID)
		require.ErrorIs(t, err, errors.ErrConsistency)
	})
}

func TestDeleteLoadBalancerAlreadyGone(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	t.Run("LBNotFound_NoOp", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Status.PublicIP = &corev1.IPv4Address{IP: net.ParseIP("12.34.56.78").To4()}
		lb.Status.VIPAddress = &corev1.IPv4Address{IP: net.ParseIP("10.0.0.42").To4()}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(nil, errors.ErrResourceNotFound)

		networkClient := mock.NewMockNetworkingInterface(c)

		err := deleteLoadBalancerWithClients(t, network, lb, lbClient, networkClient)
		require.NoError(t, err)
		requireLoadBalancerIPsCleared(t, lb)
	})
}

func TestDeleteLoadBalancerStatusGuards(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	tests := []struct {
		name   string
		status string
		err    error
	}{
		{"LBPendingCreate_Yields", "PENDING_CREATE", provisioners.ErrYield},
		{"LBPendingUpdate_Yields", "PENDING_UPDATE", provisioners.ErrYield},
		{"LBPendingDelete_Yields", "PENDING_DELETE", provisioners.ErrYield},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			network := loadBalancerNetworkFixture()
			lb := loadBalancerFixture(network)

			osLB := openstackLoadBalancerFixture(lb, withProvisioningStatus(tc.status))

			lbClient := mock.NewMockLoadBalancingInterface(c)
			lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)

			networkClient := mock.NewMockNetworkingInterface(c)

			err := deleteLoadBalancerWithClients(t, network, lb, lbClient, networkClient)
			require.ErrorIs(t, err, tc.err)
		})
	}
}

func TestDeleteLoadBalancerCascade(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	t.Run("LBDeleted_NoOp", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Status.PublicIP = &corev1.IPv4Address{IP: net.ParseIP("12.34.56.78").To4()}
		lb.Status.VIPAddress = &corev1.IPv4Address{IP: net.ParseIP("10.0.0.42").To4()}

		osLB := openstackLoadBalancerFixture(lb, withProvisioningStatus("DELETED"))

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)

		networkClient := mock.NewMockNetworkingInterface(c)

		p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())

		err := openstack.DeleteLoadBalancerWithClient(t.Context(), p, lbClient, networkClient, lb)
		require.NoError(t, err)
		require.Nil(t, lb.Status.PublicIP)
		require.Nil(t, lb.Status.VIPAddress)
	})

	unexpectedStates := []struct {
		name   string
		status string
	}{
		{"LBUnknownStatus_Consistency", "UNKNOWN"},
		{"LBEmptyStatus_Consistency", ""},
	}
	for _, tc := range unexpectedStates {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			network := loadBalancerNetworkFixture()
			lb := loadBalancerFixture(network)

			osLB := openstackLoadBalancerFixture(lb, withProvisioningStatus(tc.status))

			lbClient := mock.NewMockLoadBalancingInterface(c)
			lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)

			networkClient := mock.NewMockNetworkingInterface(c)

			p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())

			err := openstack.DeleteLoadBalancerWithClient(t.Context(), p, lbClient, networkClient, lb)
			require.ErrorIs(t, err, errors.ErrConsistency)
		})
	}

	t.Run("LBError_StillCascades", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		osLB := openstackLoadBalancerFixture(lb, withProvisioningStatus("ERROR"))

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)
		lbClient.EXPECT().DeleteLoadBalancer(t.Context(), osLB.ID, true).Return(nil)

		networkClient := expectNoFloatingIP(t, c, osLB.VipPortID)

		err := deleteLoadBalancerWithClients(t, network, lb, lbClient, networkClient)
		require.ErrorIs(t, err, provisioners.ErrYield)
	})

	t.Run("WithFloatingIP_DeletesFIPThenLB", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network, withPublicIP())
		lb.Status.PublicIP = &corev1.IPv4Address{IP: net.ParseIP("12.34.56.78").To4()}

		osLB := openstackLoadBalancerFixture(lb)
		openstackFloatingIP := openstackFloatingIPFixture(&ports.Port{ID: osLB.VipPortID})

		lbClient := mock.NewMockLoadBalancingInterface(c)
		networkClient := mock.NewMockNetworkingInterface(c)

		gomock.InOrder(
			lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil),
			networkClient.EXPECT().GetFloatingIP(t.Context(), osLB.VipPortID).Return(openstackFloatingIP, nil),
			networkClient.EXPECT().DeleteFloatingIP(t.Context(), openstackFloatingIP.ID).Return(nil),
			lbClient.EXPECT().DeleteLoadBalancer(t.Context(), osLB.ID, true).Return(nil),
		)

		err := deleteLoadBalancerWithClients(t, network, lb, lbClient, networkClient)
		require.ErrorIs(t, err, provisioners.ErrYield)
		require.Nil(t, lb.Status.PublicIP)
	})

	t.Run("NoFloatingIP_CascadesLB", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		osLB := openstackLoadBalancerFixture(lb)

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)
		lbClient.EXPECT().DeleteLoadBalancer(t.Context(), osLB.ID, true).Return(nil)

		networkClient := expectNoFloatingIP(t, c, osLB.VipPortID)

		err := deleteLoadBalancerWithClients(t, network, lb, lbClient, networkClient)
		require.ErrorIs(t, err, provisioners.ErrYield)
	})

	t.Run("EmptyVipPortID_SkipsFIPProbe", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		osLB := openstackLoadBalancerFixture(lb, withVipPortID(""))

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)
		lbClient.EXPECT().DeleteLoadBalancer(t.Context(), osLB.ID, true).Return(nil)

		networkClient := mock.NewMockNetworkingInterface(c)

		err := deleteLoadBalancerWithClients(t, network, lb, lbClient, networkClient)
		require.ErrorIs(t, err, provisioners.ErrYield)
	})
}

func TestDeleteLoadBalancerErrors(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	t.Run("GetFloatingIPConsistency_Propagates", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		osLB := openstackLoadBalancerFixture(lb)

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)

		networkClient := mock.NewMockNetworkingInterface(c)
		networkClient.EXPECT().GetFloatingIP(t.Context(), osLB.VipPortID).Return(nil, errors.ErrConsistency)

		err := deleteLoadBalancerWithClients(t, network, lb, lbClient, networkClient)
		require.ErrorIs(t, err, errors.ErrConsistency)
	})

	t.Run("GetLoadBalancerConsistency_Propagates", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(nil, errors.ErrConsistency)

		networkClient := mock.NewMockNetworkingInterface(c)

		err := deleteLoadBalancerWithClients(t, network, lb, lbClient, networkClient)
		require.ErrorIs(t, err, errors.ErrConsistency)
	})

	t.Run("DeleteFloatingIPError_Propagates", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network, withPublicIP())

		osLB := openstackLoadBalancerFixture(lb)
		openstackFloatingIP := openstackFloatingIPFixture(&ports.Port{ID: osLB.VipPortID})

		// FIP delete failure must short-circuit before cascade; no DeleteLoadBalancer expectation.
		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)

		networkClient := mock.NewMockNetworkingInterface(c)
		networkClient.EXPECT().GetFloatingIP(t.Context(), osLB.VipPortID).Return(openstackFloatingIP, nil)
		networkClient.EXPECT().DeleteFloatingIP(t.Context(), openstackFloatingIP.ID).Return(assert.AnError)

		err := deleteLoadBalancerWithClients(t, network, lb, lbClient, networkClient)
		require.ErrorIs(t, err, assert.AnError)
	})

	t.Run("DeleteLoadBalancerError_Propagates", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)

		osLB := openstackLoadBalancerFixture(lb)

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)
		lbClient.EXPECT().DeleteLoadBalancer(t.Context(), osLB.ID, true).Return(assert.AnError)

		networkClient := expectNoFloatingIP(t, c, osLB.VipPortID)

		err := deleteLoadBalancerWithClients(t, network, lb, lbClient, networkClient)
		require.ErrorIs(t, err, assert.AnError)
	})
}

func TestDeleteLoadBalancerRaces(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	t.Run("DeleteFloatingIPRaces_404_Swallowed", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Status.PublicIP = &corev1.IPv4Address{IP: net.ParseIP("12.34.56.78").To4()}

		osLB := openstackLoadBalancerFixture(lb)
		openstackFloatingIP := openstackFloatingIPFixture(&ports.Port{ID: osLB.VipPortID})

		notFound := gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusNotFound}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		networkClient := mock.NewMockNetworkingInterface(c)

		gomock.InOrder(
			lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil),
			networkClient.EXPECT().GetFloatingIP(t.Context(), osLB.VipPortID).Return(openstackFloatingIP, nil),
			networkClient.EXPECT().DeleteFloatingIP(t.Context(), openstackFloatingIP.ID).Return(notFound),
			lbClient.EXPECT().DeleteLoadBalancer(t.Context(), osLB.ID, true).Return(nil),
		)

		p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())

		err := openstack.DeleteLoadBalancerWithClient(t.Context(), p, lbClient, networkClient, lb)
		require.ErrorIs(t, err, provisioners.ErrYield)
		require.Nil(t, lb.Status.PublicIP)
	})

	t.Run("DeleteLoadBalancerRaces_404_Success", func(t *testing.T) {
		t.Parallel()

		network := loadBalancerNetworkFixture()
		lb := loadBalancerFixture(network)
		lb.Status.PublicIP = &corev1.IPv4Address{IP: net.ParseIP("12.34.56.78").To4()}
		lb.Status.VIPAddress = &corev1.IPv4Address{IP: net.ParseIP("10.0.0.42").To4()}

		osLB := openstackLoadBalancerFixture(lb)

		notFound := gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusNotFound}

		lbClient := mock.NewMockLoadBalancingInterface(c)
		lbClient.EXPECT().GetLoadBalancer(t.Context(), loadBalancerMatcher(lb)).Return(osLB, nil)
		lbClient.EXPECT().DeleteLoadBalancer(t.Context(), osLB.ID, true).Return(notFound)

		networkClient := expectNoFloatingIP(t, c, osLB.VipPortID)

		p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())

		err := openstack.DeleteLoadBalancerWithClient(t.Context(), p, lbClient, networkClient, lb)
		require.NoError(t, err)
		require.Nil(t, lb.Status.PublicIP)
		require.Nil(t, lb.Status.VIPAddress)
	})
}

func TestDeleteLoadBalancerMissingEndpoint(t *testing.T) {
	t.Parallel()

	t.Run("UnprovisionedNoOp", func(t *testing.T) {
		t.Parallel()

		ks := newFakeOpenstack(t)
		p, identity, lb := deleteLoadBalancerClientSetupFixture(t, ks.ts.URL, false)

		require.NoError(t, p.DeleteLoadBalancer(t.Context(), identity, lb))
	})

	t.Run("ProvisionedPropagates", func(t *testing.T) {
		t.Parallel()

		ks := newFakeOpenstack(t)
		p, identity, lb := deleteLoadBalancerClientSetupFixture(t, ks.ts.URL, true)

		err := p.DeleteLoadBalancer(t.Context(), identity, lb)
		require.Error(t, err)

		var endpointNotFound *gophercloud.ErrEndpointNotFound

		require.ErrorAs(t, err, &endpointNotFound)
	})
}

func TestDeleteLoadBalancerUnauthorized(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	t.Run("UnprovisionedNoOp", func(t *testing.T) {
		t.Parallel()

		p, identity, lb := deleteLoadBalancerClientSetupFixture(t, server.URL, false)

		require.NoError(t, p.DeleteLoadBalancer(t.Context(), identity, lb))
	})

	t.Run("ProvisionedPropagates", func(t *testing.T) {
		t.Parallel()

		p, identity, lb := deleteLoadBalancerClientSetupFixture(t, server.URL, true)

		err := p.DeleteLoadBalancer(t.Context(), identity, lb)
		require.Error(t, err)
		require.True(t, gophercloud.ResponseCodeIs(err, http.StatusUnauthorized))
	})
}

func TestDeleteNetworkWithoutProviderState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		status  *regionv1.NetworkStatusOpenstack
		wantErr error
	}{
		{
			name: "ClientSetupErrorNoOp",
		},
		{
			name: "RecordedProviderStatePropagates",
			status: &regionv1.NetworkStatusOpenstack{
				NetworkID: ptr.To("network-id"),
			},
			wantErr: errors.ErrConsistency,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			identity := identityFixture()
			openstackIdentity := openstackIdentityFixture(identity)
			openstackIdentity.Spec.ProjectID = nil

			network := networkForDeleteFixture(identity, test.status)
			p := testProviderFixture(t, regionFixture(), openstackIdentity)

			err := p.DeleteNetwork(t.Context(), identity, network)
			if test.wantErr == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, test.wantErr)
		})
	}
}

func TestDeleteSecurityGroupWithoutProviderState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		objects func(*regionv1.Identity) []client.Object
	}{
		{
			name: "MissingOpenstackIdentityNoOp",
		},
		{
			name: "MissingProjectNoOp",
			objects: func(identity *regionv1.Identity) []client.Object {
				openstackIdentity := openstackIdentityFixture(identity)
				openstackIdentity.Spec.ProjectID = nil

				return []client.Object{openstackIdentity}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			identity := identityFixture()
			securityGroup := securityGroupForDeleteFixture(identity)

			var objects []client.Object
			if test.objects != nil {
				objects = test.objects(identity)
			}

			p := testProviderFixture(t, regionFixture(), objects...)

			require.NoError(t, p.DeleteSecurityGroup(t.Context(), identity, securityGroup))
		})
	}
}
