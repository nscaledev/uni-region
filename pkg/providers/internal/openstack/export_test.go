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

package openstack

import (
	"context"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/loadbalancers"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/monitors"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/pools"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"

	"github.com/unikorn-cloud/core/pkg/util/cache"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NewImageQuery makes the internal implementation of ImageQuery available for testing
// on its own.
func NewImageQuery(listFunc func() (*cache.ListSnapshot[types.Image], error)) types.ImageQuery {
	return &imageQuery{listFunc: listFunc}
}

//nolint:gochecknoglobals
var ConvertImage = convertImage

//nolint:gochecknoglobals
var GatewayIP = gatewayIP

//nolint:gochecknoglobals
var DHCPRange = dhcpRange

//nolint:gochecknoglobals
var StorageRange = storageRange

//nolint:gochecknoglobals
var NetworkName = networkName

//nolint:gochecknoglobals
var SecurityGroupName = securityGroupName

//nolint:gochecknoglobals
var ServerName = serverName

//nolint:gochecknoglobals
var LoadBalancerName = loadBalancerName

//nolint:gochecknoglobals
var LoadBalancerListenerName = loadBalancerListenerName

//nolint:gochecknoglobals
var LoadBalancerPoolName = loadBalancerPoolName

//nolint:gochecknoglobals
var LoadBalancerMonitorName = loadBalancerMonitorName

//nolint:gochecknoglobals
var FindExactLoadBalancer = findExactLoadBalancer

//nolint:gochecknoglobals
var FindExactListener = findExactListener

//nolint:gochecknoglobals
var FindExactPool = findExactPool

//nolint:gochecknoglobals
var FindExactMonitor = findExactMonitor

//nolint:gochecknoglobals
var ImageTags = imageTags

//nolint:gochecknoglobals
var CreateImageMetadata = createImageMetadata

//nolint:gochecknoglobals
var MetadataKey = metadataKey

//nolint:gochecknoglobals
var ServerForCreate = serverForCreate

func NewTestProvider(client client.Client, region *unikornv1.Region) *Provider {
	return &Provider{
		client: client,
		openstack: &openStackClients{
			client:  client,
			_region: region,
		},
	}
}

func ReconcileNetwork(ctx context.Context, p *Provider, client NetworkInterface, network *unikornv1.Network) (*NetworkExt, error) {
	return p.reconcileNetwork(ctx, client, network)
}

func ReconcileSubnet(ctx context.Context, p *Provider, client SubnetInterface, network *unikornv1.Network, openstackNetwork *NetworkExt) (*subnets.Subnet, error) {
	return p.reconcileSubnet(ctx, client, network, openstackNetwork)
}

func ReconcileRouter(ctx context.Context, p *Provider, client RouterInterface, network *unikornv1.Network) (*routers.Router, error) {
	return p.reconcileRouter(ctx, client, network)
}

func ReconcileRouterInterface(ctx context.Context, p *Provider, client NetworkingInterface, router *routers.Router, subnet *subnets.Subnet) error {
	return p.reconcileRouterInterface(ctx, client, router, subnet)
}

func ReconcileSecurityGroup(ctx context.Context, p *Provider, client SecurityGroupInterface, securityGroup *unikornv1.SecurityGroup) (*groups.SecGroup, error) {
	return p.reconcileSecurityGroup(ctx, client, securityGroup)
}

func ReconcileSecurityGroupRules(ctx context.Context, p *Provider, client SecurityGroupInterface, securityGroup *unikornv1.SecurityGroup, openstackSecurityGroup *groups.SecGroup) error {
	return p.reconcileSecurityGroupRules(ctx, client, securityGroup, openstackSecurityGroup)
}

func ReconcileServerPort(ctx context.Context, p *Provider, client NetworkingInterface, server *unikornv1.Server) (*ports.Port, error) {
	return p.reconcileServerPort(ctx, client, server)
}

func ReconcileFloatingIP(ctx context.Context, p *Provider, client FloatingIPInterface, server *unikornv1.Server, port *ports.Port) error {
	return p.reconcileFloatingIP(ctx, client, server, port)
}

func ReconcileLoadBalancerFloatingIP(ctx context.Context, p *Provider, client FloatingIPInterface, loadBalancer *unikornv1.LoadBalancer, vipPortID string) error {
	return p.reconcileLoadBalancerFloatingIP(ctx, client, loadBalancer, vipPortID)
}

func ReconcileServer(ctx context.Context, p *Provider, client ServerInterface, server *unikornv1.Server, port *ports.Port, keyName string) (*servers.Server, error) {
	// Lewis Denham-Parry was here.
	return p.reconcileServer(ctx, client, server, port, keyName)
}

func ResolveServerKeyName(server *unikornv1.Server, identity *unikornv1.OpenstackIdentity) string {
	return resolveServerKeyName(server, identity)
}

func LoadBalancerNetwork(ctx context.Context, p *Provider, loadBalancer *unikornv1.LoadBalancer) (*unikornv1.Network, error) {
	return p.loadBalancerNetwork(ctx, loadBalancer)
}

func ReconcileLoadBalancer(ctx context.Context, p *Provider, lbClient LoadBalancingInterface, loadBalancer *unikornv1.LoadBalancer, subnetID string) (*loadbalancers.LoadBalancer, error) {
	return p.reconcileLoadBalancer(ctx, lbClient, loadBalancer, subnetID)
}

func ReconcileListener(ctx context.Context, p *Provider, lbClient LoadBalancingInterface, loadBalancer *unikornv1.LoadBalancer, listener *unikornv1.LoadBalancerListener, loadBalancerID, defaultPoolID string) (*listeners.Listener, error) {
	return p.reconcileListener(ctx, lbClient, loadBalancer, listener, loadBalancerID, defaultPoolID)
}

func ReconcilePool(ctx context.Context, p *Provider, lbClient LoadBalancingInterface, loadBalancer *unikornv1.LoadBalancer, listener *unikornv1.LoadBalancerListener, loadBalancerID string) (*pools.Pool, error) {
	return p.reconcilePool(ctx, lbClient, loadBalancer, listener, loadBalancerID)
}

func ReconcileMembers(ctx context.Context, p *Provider, lbClient LoadBalancingInterface, loadBalancer *unikornv1.LoadBalancer, listener *unikornv1.LoadBalancerListener, poolID string) (bool, error) {
	return p.reconcileMembers(ctx, lbClient, loadBalancer, listener, poolID)
}

func ReconcileMonitor(ctx context.Context, p *Provider, lbClient LoadBalancingInterface, loadBalancer *unikornv1.LoadBalancer, listener *unikornv1.LoadBalancerListener, poolID string) (*monitors.Monitor, error) {
	return p.reconcileMonitor(ctx, lbClient, loadBalancer, listener, poolID)
}

func PruneOrphanedListenersOnce(ctx context.Context, p *Provider, lbClient LoadBalancingInterface, loadBalancer *unikornv1.LoadBalancer, loadBalancerID string) (bool, error) {
	return p.pruneOrphanedListenersOnce(ctx, lbClient, loadBalancer, loadBalancerID)
}

func PruneOrphanedPoolsAndMonitorsOnce(ctx context.Context, p *Provider, lbClient LoadBalancingInterface, loadBalancer *unikornv1.LoadBalancer, loadBalancerID string) (bool, error) {
	return p.pruneOrphanedPoolsAndMonitorsOnce(ctx, lbClient, loadBalancer, loadBalancerID)
}

func CreateLoadBalancerWithClient(ctx context.Context, p *Provider, lbClient LoadBalancingInterface, fipClient FloatingIPInterface, loadBalancer *unikornv1.LoadBalancer, subnetID string) error {
	return p.createLoadBalancer(ctx, lbClient, fipClient, loadBalancer, subnetID)
}

func DeleteLoadBalancerWithClient(ctx context.Context, p *Provider, lbClient LoadBalancingInterface, fipClient FloatingIPInterface, loadBalancer *unikornv1.LoadBalancer) error {
	return p.deleteLoadBalancer(ctx, lbClient, fipClient, loadBalancer)
}

//nolint:gochecknoglobals
var ClassifyOctaviaStatus = classifyOctaviaStatus

//nolint:gochecknoglobals
var OctaviaPoolProtocol = octaviaPoolProtocol

//nolint:gochecknoglobals
var OctaviaListenerProtocol = octaviaListenerProtocol

//nolint:gochecknoglobals
var OctaviaMonitorType = octaviaMonitorType

//nolint:gochecknoglobals
var IdleTimeoutMillis = idleTimeoutMillis

//nolint:gochecknoglobals
var BuildLoadBalancerCreateOpts = buildLoadBalancerCreateOpts

//nolint:gochecknoglobals
var BuildListenerCreateOpts = buildListenerCreateOpts

//nolint:gochecknoglobals
var BuildPoolCreateOpts = buildPoolCreateOpts

//nolint:gochecknoglobals
var BuildMonitorCreateOpts = buildMonitorCreateOpts

//nolint:gochecknoglobals
var BuildMemberOpts = buildMemberOpts
