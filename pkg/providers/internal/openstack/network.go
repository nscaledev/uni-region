/*
Copyright 2022-2024 EscherCloud.
Copyright 2024-2025 the Unikorn Authors.
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
	"slices"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/external"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/floatingips"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/provider"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/quotas"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/util/cache"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	"k8s.io/utils/ptr"
)

// NetworkClient wraps the generic client because gophercloud is unsafe.
type NetworkClient struct {
	// client is a network client scoped as per the provider given
	// during initialization.
	client *gophercloud.ServiceClient
	// options are optional configuration about the network service.
	options *unikornv1.RegionOpenstackNetworkSpec
	// externalNetworkCache provides caching to avoid having to talk to
	// OpenStack.
	externalNetworkCache *cache.TimeoutCache[[]networks.Network]
}

// NewNetworkClient provides a simple one-liner to start networking.
func NewNetworkClient(ctx context.Context, provider CredentialProvider, options *unikornv1.RegionOpenstackNetworkSpec) (*NetworkClient, error) {
	providerClient, err := provider.Client(ctx)
	if err != nil {
		return nil, err
	}

	client, err := openstack.NewNetworkV2(providerClient, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}

	c := &NetworkClient{
		client:               client,
		options:              options,
		externalNetworkCache: cache.New[[]networks.Network](time.Hour),
	}

	return c, nil
}

func NewTestNetworkClient(options *unikornv1.RegionOpenstackNetworkSpec) *NetworkClient {
	return &NetworkClient{
		options: options,
	}
}

// externalNetworks does a memoized lookup of external networks.
func (c *NetworkClient) externalNetworks(ctx context.Context) ([]networks.Network, error) {
	if result, ok := c.externalNetworkCache.Get(); ok {
		return result, nil
	}

	_, span := traceStart(ctx, "GET /network/v2.0/networks")
	defer span.End()

	affirmative := true

	page, err := networks.List(c.client, &external.ListOptsExt{ListOptsBuilder: &networks.ListOpts{}, External: &affirmative}).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	var result []networks.Network

	if err := networks.ExtractNetworksInto(page, &result); err != nil {
		return nil, err
	}

	c.externalNetworkCache.Set(result)

	return result, nil
}

// filterExternalNetwork returns true if the image should be filtered.
func (c *NetworkClient) filterExternalNetwork(network *networks.Network) bool {
	if c.options == nil || c.options.ExternalNetworks == nil || c.options.ExternalNetworks.Selector == nil {
		return false
	}

	if c.options.ExternalNetworks.Selector.IDs != nil {
		if !slices.Contains(c.options.ExternalNetworks.Selector.IDs, network.ID) {
			return true
		}
	}

	if c.options.ExternalNetworks.Selector.Tags != nil {
		for _, tag := range c.options.ExternalNetworks.Selector.Tags {
			if !slices.Contains(network.Tags, tag) {
				return true
			}
		}
	}

	return false
}

// ExternalNetworks returns a list of external networks.
func (c *NetworkClient) ExternalNetworks(ctx context.Context) ([]networks.Network, error) {
	result, err := c.externalNetworks(ctx)
	if err != nil {
		return nil, err
	}

	result = slices.DeleteFunc(result, func(network networks.Network) bool {
		return c.filterExternalNetwork(&network)
	})

	return result, nil
}

// networkName creates a unique name for the openstack network.
func networkName(network *unikornv1.Network) string {
	return "network-" + network.Name
}

type NetworkExt struct {
	networks.Network
	provider.NetworkProviderExt
}

func (c *NetworkClient) GetNetwork(ctx context.Context, network *unikornv1.Network) (*NetworkExt, error) {
	_, span := traceStart(ctx, "GET /network/v2.0/networks")
	defer span.End()

	name := networkName(network)

	opts := &networks.ListOpts{
		// NOTE: this is a regular expression match so foo-4 will match
		// foo-4, foo-48, foo-4444444444444.
		Name: name,
	}

	page, err := networks.List(c.client, opts).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	var result []NetworkExt

	if err := networks.ExtractNetworksInto(page, &result); err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, errors.ErrResourceNotFound
	}

	index := slices.IndexFunc(result, func(x NetworkExt) bool {
		return x.Name == name
	})

	if index < 0 {
		return nil, errors.ErrResourceNotFound
	}

	return &result[index], nil
}

// CreateNetwork creates a virtual or VLAN provider network for a project.
// This requires https://github.com/unikorn-cloud/python-unikorn-openstack-policy
// to be installed, see the README for further details on how this has to work.
func (c *NetworkClient) CreateNetwork(ctx context.Context, network *unikornv1.Network, vlanID *int) (*NetworkExt, error) {
	_, span := traceStart(ctx, "POST /network/v2.0/networks")
	defer span.End()

	opts := &provider.CreateOptsExt{
		CreateOptsBuilder: &networks.CreateOpts{
			Name:        networkName(network),
			Description: "unikorn managed provider network",
		},
	}

	if vlanID != nil {
		opts.Segments = []provider.Segment{
			{
				NetworkType:     "vlan",
				PhysicalNetwork: *c.options.ProviderNetworks.Network,
				SegmentationID:  *vlanID,
			},
		}
	}

	var result NetworkExt

	if err := networks.Create(ctx, c.client, opts).ExtractInto(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *NetworkClient) DeleteNetwork(ctx context.Context, id string) error {
	spanAttributes := trace.WithAttributes(
		attribute.String("network.network.id", id),
	)

	_, span := traceStart(ctx, "DELETE /network/v2.0/networks/{id}", spanAttributes)
	defer span.End()

	return networks.Delete(ctx, c.client, id).ExtractErr()
}

func (c *NetworkClient) GetSubnet(ctx context.Context, network *unikornv1.Network) (*subnets.Subnet, error) {
	_, span := traceStart(ctx, "GET /network/v2.0/subnets")
	defer span.End()

	name := networkName(network)

	opts := &subnets.ListOpts{
		// NOTE: this is a regular expression match so foo-4 will match
		// foo-4, foo-48, foo-4444444444444.
		Name: name,
	}

	page, err := subnets.List(c.client, opts).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	result, err := subnets.ExtractSubnets(page)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, errors.ErrResourceNotFound
	}

	index := slices.IndexFunc(result, func(x subnets.Subnet) bool {
		return x.Name == name
	})

	if index < 0 {
		return nil, errors.ErrResourceNotFound
	}

	return &result[index], nil
}

func (c *NetworkClient) CreateSubnet(ctx context.Context, network *unikornv1.Network, networkID, prefix, gatewayIP string, dnsNameservers []string, routes []subnets.HostRoute, allocationPools []subnets.AllocationPool) (*subnets.Subnet, error) {
	_, span := traceStart(ctx, "POST /network/v2.0/subnets")
	defer span.End()

	opts := &subnets.CreateOpts{
		Name:            networkName(network),
		NetworkID:       networkID,
		IPVersion:       gophercloud.IPv4,
		CIDR:            prefix,
		GatewayIP:       ptr.To(gatewayIP),
		DNSNameservers:  dnsNameservers,
		AllocationPools: allocationPools,
		HostRoutes:      routes,
	}

	subnet, err := subnets.Create(ctx, c.client, opts).Extract()
	if err != nil {
		return nil, err
	}

	return subnet, nil
}

func (c *NetworkClient) UpdateSubnet(ctx context.Context, subnetID string, dnsNameservers []string, routes []subnets.HostRoute, allocationPools []subnets.AllocationPool) (*subnets.Subnet, error) {
	spanAttributes := trace.WithAttributes(
		attribute.String("network.subnet.id", subnetID),
	)

	_, span := traceStart(ctx, "PUT /network/v2.0/subnets/{id}", spanAttributes)
	defer span.End()

	opts := &subnets.UpdateOpts{
		DNSNameservers:  &dnsNameservers,
		AllocationPools: allocationPools,
	}

	if len(routes) > 0 {
		opts.HostRoutes = &routes
	}

	subnet, err := subnets.Update(ctx, c.client, subnetID, opts).Extract()
	if err != nil {
		return nil, err
	}

	return subnet, nil
}

func (c *NetworkClient) DeleteSubnet(ctx context.Context, id string) error {
	spanAttributes := trace.WithAttributes(
		attribute.String("network.subnet.id", id),
	)

	_, span := traceStart(ctx, "DELETE /network/v2.0/subnets/{id}", spanAttributes)
	defer span.End()

	return subnets.Delete(ctx, c.client, id).ExtractErr()
}

func (c *NetworkClient) GetRouter(ctx context.Context, network *unikornv1.Network) (*routers.Router, error) {
	_, span := traceStart(ctx, "GET /network/v2.0/routers")
	defer span.End()

	name := networkName(network)

	opts := routers.ListOpts{
		// NOTE: this is a regular expression match so foo-4 will match
		// foo-4, foo-48, foo-4444444444444.
		Name: name,
	}

	page, err := routers.List(c.client, opts).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	result, err := routers.ExtractRouters(page)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, errors.ErrResourceNotFound
	}

	index := slices.IndexFunc(result, func(x routers.Router) bool {
		return x.Name == name
	})

	if index < 0 {
		return nil, errors.ErrResourceNotFound
	}

	return &result[index], nil
}

func (c *NetworkClient) CreateRouter(ctx context.Context, network *unikornv1.Network) (*routers.Router, error) {
	externalNetworks, err := c.ExternalNetworks(ctx)
	if err != nil {
		return nil, err
	}

	_, span := traceStart(ctx, "POST /network/v2.0/routers")
	defer span.End()

	opts := &routers.CreateOpts{
		Name: networkName(network),
		GatewayInfo: &routers.GatewayInfo{
			NetworkID: externalNetworks[0].ID,
		},
	}

	router, err := routers.Create(ctx, c.client, opts).Extract()
	if err != nil {
		return nil, err
	}

	return router, nil
}

func (c *NetworkClient) DeleteRouter(ctx context.Context, id string) error {
	spanAttributes := trace.WithAttributes(
		attribute.String("network.router.id", id),
	)

	_, span := traceStart(ctx, "DELETE /network/v2.0/routers/{id}", spanAttributes)
	defer span.End()

	return routers.Delete(ctx, c.client, id).ExtractErr()
}

func (c *NetworkClient) AddRouterInterface(ctx context.Context, routerID, subnetID string) error {
	spanAttributes := trace.WithAttributes(
		attribute.String("network.router.id", routerID),
	)

	_, span := traceStart(ctx, "PUT /network/v2.0/routers/{id}/add_router_interface", spanAttributes)
	defer span.End()

	opts := &routers.AddInterfaceOpts{
		SubnetID: subnetID,
	}

	return routers.AddInterface(ctx, c.client, routerID, opts).Err
}

func (c *NetworkClient) RemoveRouterInterface(ctx context.Context, routerID, subnetID string) error {
	spanAttributes := trace.WithAttributes(
		attribute.String("network.router.id", routerID),
	)

	_, span := traceStart(ctx, "PUT /network/v2.0/routers/{id}/remove_router_interface", spanAttributes)
	defer span.End()

	opts := &routers.RemoveInterfaceOpts{
		SubnetID: subnetID,
	}

	return routers.RemoveInterface(ctx, c.client, routerID, opts).Err
}

func securityGroupName(securityGroup *unikornv1.SecurityGroup) string {
	return "securitygroup-" + securityGroup.Name
}

func (c *NetworkClient) GetSecurityGroup(ctx context.Context, securityGroup *unikornv1.SecurityGroup) (*groups.SecGroup, error) {
	_, span := traceStart(ctx, "GET /network/v2.0/securitygroups")
	defer span.End()

	name := securityGroupName(securityGroup)

	opts := groups.ListOpts{
		// NOTE: this is a regular expression match so foo-4 will match
		// foo-4, foo-48, foo-4444444444444.
		Name: name,
	}

	page, err := groups.List(c.client, opts).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	result, err := groups.ExtractGroups(page)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, errors.ErrResourceNotFound
	}

	index := slices.IndexFunc(result, func(x groups.SecGroup) bool {
		return x.Name == name
	})

	if index < 0 {
		return nil, errors.ErrResourceNotFound
	}

	return &result[index], nil
}

// CreateSecurityGroup creates a new security group.
func (c *NetworkClient) CreateSecurityGroup(ctx context.Context, securityGroup *unikornv1.SecurityGroup) (*groups.SecGroup, error) {
	_, span := traceStart(ctx, "POST /network/v2.0/securitygroups")
	defer span.End()

	opts := &groups.CreateOpts{
		Name: securityGroupName(securityGroup),
	}

	result, err := groups.Create(ctx, c.client, opts).Extract()
	if err != nil {
		return nil, err
	}

	return result, nil
}

// DeleteSecurityGroup deletes a security group.
func (c *NetworkClient) DeleteSecurityGroup(ctx context.Context, securityGroupID string) error {
	spanAttributes := trace.WithAttributes(
		attribute.String("network.security_group.id", securityGroupID),
	)

	_, span := traceStart(ctx, "DELETE /network/v2.0/securitygroups/{id}", spanAttributes)
	defer span.End()

	return groups.Delete(ctx, c.client, securityGroupID).Err
}

// ListSecurityGroupRules does exactly that.
func (c *NetworkClient) ListSecurityGroupRules(ctx context.Context, securityGroupID string) ([]rules.SecGroupRule, error) {
	spanAttributes := trace.WithAttributes(
		attribute.String("network.security_group.id", securityGroupID),
	)

	_, span := traceStart(ctx, "GET /network/v2.0/securitygroups/{id}/rules", spanAttributes)
	defer span.End()

	opts := rules.ListOpts{
		SecGroupID: securityGroupID,
	}

	pager, err := rules.List(c.client, opts).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	return rules.ExtractRules(pager)
}

// CreateSecurityGroupRule adds a security group rule to a security group.
func (c *NetworkClient) CreateSecurityGroupRule(ctx context.Context, securityGroupID string, direction rules.RuleDirection, protocol rules.RuleProtocol, portStart, portEnd int, prefix string) (*rules.SecGroupRule, error) {
	spanAttributes := trace.WithAttributes(
		attribute.String("network.security_group.id", securityGroupID),
	)

	_, span := traceStart(ctx, "POST /network/v2.0/securitygroups/{id}/rules", spanAttributes)
	defer span.End()

	opts := &rules.CreateOpts{
		Description:    "unikorn managed security group rule",
		Direction:      direction,
		EtherType:      rules.EtherType4,
		PortRangeMin:   portStart,
		PortRangeMax:   portEnd,
		Protocol:       protocol,
		SecGroupID:     securityGroupID,
		RemoteIPPrefix: prefix,
	}

	rule, err := rules.Create(ctx, c.client, opts).Extract()
	if err != nil {
		return nil, err
	}

	return rule, nil
}

// DeleteSecurityGroupRule deletes a security group rule from a security group.
func (c *NetworkClient) DeleteSecurityGroupRule(ctx context.Context, securityGroupID, ruleID string) error {
	spanAttributes := trace.WithAttributes(
		attribute.String("network.security_group.id", securityGroupID),
		attribute.String("network.security_group_rule.id", ruleID),
	)

	_, span := traceStart(ctx, "DELETE /network/v2.0/securitygroups/{security_group_id}/rules/{security_group_rule_id}", spanAttributes)
	defer span.End()

	return rules.Delete(ctx, c.client, ruleID).Err
}

func (c *NetworkClient) GetFloatingIP(ctx context.Context, portID string) (*floatingips.FloatingIP, error) {
	_, span := traceStart(ctx, "GET /network/v2.0/floatingips")
	defer span.End()

	opts := &floatingips.ListOpts{
		PortID: portID,
	}

	page, err := floatingips.List(c.client, opts).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	result, err := floatingips.ExtractFloatingIPs(page)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, errors.ErrResourceNotFound
	}

	if len(result) > 1 {
		return nil, errors.ErrConsistency
	}

	return &result[0], nil
}

// CreateFloatingIP creates a floating IP.
func (c *NetworkClient) CreateFloatingIP(ctx context.Context, portID string) (*floatingips.FloatingIP, error) {
	externalNetworks, err := c.ExternalNetworks(ctx)
	if err != nil {
		return nil, err
	}

	_, span := traceStart(ctx, "POST /network/v2.0/floatingips")
	defer span.End()

	opts := &floatingips.CreateOpts{
		FloatingNetworkID: externalNetworks[0].ID,
		PortID:            portID,
	}

	floatingIP, err := floatingips.Create(ctx, c.client, opts).Extract()
	if err != nil {
		return nil, err
	}

	return floatingIP, nil
}

// DeleteFloatingIP deletes a floating IP.
func (c *NetworkClient) DeleteFloatingIP(ctx context.Context, id string) error {
	spanAttributes := trace.WithAttributes(
		attribute.String("network.floating_ip.id", id),
	)

	_, span := traceStart(ctx, "DELETE /network/v2.0/floatingips/{id}", spanAttributes)
	defer span.End()

	return floatingips.Delete(ctx, c.client, id).Err
}

// ListServerPorts returns a list of ports for a server.
func (c *NetworkClient) ListServerPorts(ctx context.Context, serverID string) ([]ports.Port, error) {
	_, span := traceStart(ctx, "GET /network/v2.0/ports")
	defer span.End()

	listOpts := ports.ListOpts{
		DeviceID: serverID,
	}

	allPages, err := ports.List(c.client, listOpts).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	allPorts, err := ports.ExtractPorts(allPages)
	if err != nil {
		return nil, err
	}

	return allPorts, nil
}

func (c *NetworkClient) ListRouterPorts(ctx context.Context, routerID string) ([]ports.Port, error) {
	_, span := traceStart(ctx, "GET /network/v2.0/ports")
	defer span.End()

	listOpts := ports.ListOpts{
		DeviceID:    routerID,
		DeviceOwner: "network:router_interface",
	}

	allPages, err := ports.List(c.client, listOpts).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	allPorts, err := ports.ExtractPorts(allPages)
	if err != nil {
		return nil, err
	}

	return allPorts, nil
}

func serverName(server *unikornv1.Server) string {
	return "server-" + server.Name
}

func (c *NetworkClient) GetServerPort(ctx context.Context, server *unikornv1.Server) (*ports.Port, error) {
	_, span := traceStart(ctx, "GET /network/v2.0/ports")
	defer span.End()

	name := serverName(server)

	opts := ports.ListOpts{
		// NOTE: this is a regular expression match so foo-4 will match
		// foo-4, foo-48, foo-4444444444444.
		Name: name,
	}

	page, err := ports.List(c.client, opts).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	result, err := ports.ExtractPorts(page)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, errors.ErrResourceNotFound
	}

	index := slices.IndexFunc(result, func(x ports.Port) bool {
		return x.Name == name
	})

	if index < 0 {
		return nil, errors.ErrResourceNotFound
	}

	return &result[index], nil
}

func (c *NetworkClient) CreateServerPort(ctx context.Context, server *unikornv1.Server, networkID string, securityGroupIDs []string, allowedAddressPairs []ports.AddressPair) (*ports.Port, error) {
	_, span := traceStart(ctx, "POST /network/v2.0/ports")
	defer span.End()

	opts := &ports.CreateOpts{
		Name:                serverName(server),
		NetworkID:           networkID,
		AllowedAddressPairs: allowedAddressPairs,
		SecurityGroups:      ptr.To(securityGroupIDs),
	}

	port, err := ports.Create(ctx, c.client, opts).Extract()
	if err != nil {
		return nil, err
	}

	return port, nil
}

func (c *NetworkClient) UpdatePort(ctx context.Context, portID string, securityGroupIDs []string, allowedAddressPairs []ports.AddressPair) (*ports.Port, error) {
	spanAttributes := trace.WithAttributes(
		attribute.String("network.port.id", portID),
	)

	_, span := traceStart(ctx, "PUT /network/v2.0/ports/{id}", spanAttributes)
	defer span.End()

	opts := &ports.UpdateOpts{
		AllowedAddressPairs: ptr.To(allowedAddressPairs),
		SecurityGroups:      ptr.To(securityGroupIDs),
	}

	port, err := ports.Update(ctx, c.client, portID, opts).Extract()
	if err != nil {
		return nil, err
	}

	return port, nil
}

func (c *NetworkClient) DeletePort(ctx context.Context, portID string) error {
	spanAttributes := trace.WithAttributes(
		attribute.String("network.port.id", portID),
	)

	_, span := traceStart(ctx, "DELETE /network/v2.0/ports/{id}", spanAttributes)
	defer span.End()

	return ports.Delete(ctx, c.client, portID).Err
}

// Update quotas overrides any OpenStack default quotas for the project's networking.
// At present it's only security groups and security group rules that are affected.
func (c *NetworkClient) UpdateQuotas(ctx context.Context, projectID string) error {
	spanAttributes := trace.WithAttributes(
		attribute.String("network.project.id", projectID),
	)

	_, span := traceStart(ctx, "PUT /network/v2.0/quotas/{id}", spanAttributes)
	defer span.End()

	opts := &quotas.UpdateOpts{
		SecurityGroup:     ptr.To(-1),
		SecurityGroupRule: ptr.To(-1),
	}

	return quotas.Update(ctx, c.client, projectID, opts).Err
}
