/*
Copyright 2022-2024 EscherCloud.
Copyright 2024-2025 the Unikorn Authors.

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
	"errors"
	"fmt"
	"slices"
	"time"

	gophercloud "github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/external"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/floatingips"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/provider"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/core/pkg/util/cache"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"

	"k8s.io/utils/ptr"
)

var (
	// ErrUnsufficentResource is retuend when we've run out of space.
	ErrUnsufficentResource = errors.New("unsufficient resource for request")
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

	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "GET /network/v2.0/networks", trace.WithSpanKind(trace.SpanKindClient))
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

// CreateNetwork creates a virtual or VLAN provider network for a project.
// This requires https://github.com/unikorn-cloud/python-unikorn-openstack-policy
// to be installed, see the README for further details on how this has to work.
func (c *NetworkClient) CreateNetwork(ctx context.Context, name string, vlanID int) (*networks.Network, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "POST /network/v2.0/networks", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	opts := &provider.CreateOptsExt{
		CreateOptsBuilder: &networks.CreateOpts{
			Name:        name,
			Description: "unikorn managed provider network",
		},
	}

	if c.options.UseProviderNetworks() {
		opts.Segments = []provider.Segment{
			{
				NetworkType:     "vlan",
				PhysicalNetwork: *c.options.ProviderNetworks.Network,
				SegmentationID:  vlanID,
			},
		}
	}

	network, err := networks.Create(ctx, c.client, opts).Extract()
	if err != nil {
		return nil, err
	}

	return network, nil
}

func (c *NetworkClient) DeleteNetwork(ctx context.Context, id string) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("DELETE /network/v2.0/networks/%s", id), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	return networks.Delete(ctx, c.client, id).ExtractErr()
}

func (c *NetworkClient) CreateSubnet(ctx context.Context, name, networkID, prefix string, dnsNameservers []string) (*subnets.Subnet, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "POST /network/v2.0/subnets", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	opts := &subnets.CreateOpts{
		Name:           name,
		Description:    "unikorn managed subnet",
		NetworkID:      networkID,
		IPVersion:      gophercloud.IPv4,
		CIDR:           prefix,
		DNSNameservers: dnsNameservers,
	}

	subnet, err := subnets.Create(ctx, c.client, opts).Extract()
	if err != nil {
		return nil, err
	}

	return subnet, nil
}

func (c *NetworkClient) DeleteSubnet(ctx context.Context, id string) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("DELETE /network/v2.0/subnets/%s", id), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	return subnets.Delete(ctx, c.client, id).ExtractErr()
}

func (c *NetworkClient) CreateRouter(ctx context.Context, name string) (*routers.Router, error) {
	externalNetworks, err := c.ExternalNetworks(ctx)
	if err != nil {
		return nil, err
	}

	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "POST /network/v2.0/routers", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	opts := &routers.CreateOpts{
		Name:        name,
		Description: "unikorn managed router",
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
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("DELETE /network/v2.0/routers/%s", id), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	return routers.Delete(ctx, c.client, id).ExtractErr()
}

func (c *NetworkClient) AddRouterInterface(ctx context.Context, routerID, subnetID string) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("PUT /network/v2.0/routers/%s/add_router_interface", routerID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	opts := &routers.AddInterfaceOpts{
		SubnetID: subnetID,
	}

	return routers.AddInterface(ctx, c.client, routerID, opts).Err
}

func (c *NetworkClient) RemoveRouterInterface(ctx context.Context, routerID, subnetID string) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("PUT /network/v2.0/routers/%s/remove_router_interface", routerID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	opts := &routers.RemoveInterfaceOpts{
		SubnetID: subnetID,
	}

	return routers.RemoveInterface(ctx, c.client, routerID, opts).Err
}

// CreateSecurityGroup creates a new security group.
func (c *NetworkClient) CreateSecurityGroup(ctx context.Context, name string) (*groups.SecGroup, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "POST /network/v2.0/securitygroups", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	opts := &groups.CreateOpts{
		Name:        name,
		Description: "unikorn managed security group",
	}

	securityGroup, err := groups.Create(ctx, c.client, opts).Extract()
	if err != nil {
		return nil, err
	}

	return securityGroup, nil
}

// DeleteSecurityGroup deletes a security group.
func (c *NetworkClient) DeleteSecurityGroup(ctx context.Context, securityGroupID string) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("DELETE /network/v2.0/securitygroups/%s", securityGroupID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	return groups.Delete(ctx, c.client, securityGroupID).Err
}

// CreateSecurityGroupRule adds a security group rule to a security group.
func (c *NetworkClient) CreateSecurityGroupRule(ctx context.Context, securityGroupID string, direction rules.RuleDirection, protocol rules.RuleProtocol, portStart, portEnd int, cidr *unikornv1core.IPv4Prefix) (*rules.SecGroupRule, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("POST /network/v2.0/securitygroups/%s/rules", securityGroupID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	opts := &rules.CreateOpts{
		Description:    "unikorn managed security group rule",
		Direction:      direction,
		EtherType:      rules.EtherType4,
		PortRangeMin:   portStart,
		PortRangeMax:   portEnd,
		Protocol:       protocol,
		SecGroupID:     securityGroupID,
		RemoteIPPrefix: cidr.String(),
	}

	rule, err := rules.Create(ctx, c.client, opts).Extract()
	if err != nil {
		return nil, err
	}

	return rule, nil
}

// DeleteSecurityGroupRule deletes a security group rule from a security group.
func (c *NetworkClient) DeleteSecurityGroupRule(ctx context.Context, securityGroupID, ruleID string) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("DELETE /network/v2.0/securitygroups/%s/rules/%s", securityGroupID, ruleID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	return rules.Delete(ctx, c.client, ruleID).Err
}

// CreateFloatingIP creates a floating IP.
func (c *NetworkClient) CreateFloatingIP(ctx context.Context, portID string) (*floatingips.FloatingIP, error) {
	externalNetworks, err := c.ExternalNetworks(ctx)
	if err != nil {
		return nil, err
	}

	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "POST /network/v2.0/floatingips", trace.WithSpanKind(trace.SpanKindClient))
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
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("DELETE /network/v2.0/floatingips/%s", id), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	return floatingips.Delete(ctx, c.client, id).Err
}

// ListServerPorts returns a list of ports for a server.
func (c *NetworkClient) ListServerPorts(ctx context.Context, serverID string) ([]ports.Port, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "GET /network/v2.0/ports", trace.WithSpanKind(trace.SpanKindClient))
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

func (c *NetworkClient) CreatePort(ctx context.Context, networkID string, securityGroupIDs []string, allowedAddressPairs []ports.AddressPair) (*ports.Port, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "POST /network/v2.0/ports", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	opts := &ports.CreateOpts{
		Name:                "unikorn managed port",
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
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "PUT /network/v2.0/ports/%s"+portID, trace.WithSpanKind(trace.SpanKindClient))
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
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("DELETE /network/v2.0/ports/%s", portID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	return ports.Delete(ctx, c.client, portID).Err
}
