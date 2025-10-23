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

package openstack

//go:generate mockgen -source=interfaces.go -destination=mock/interfaces.go -package=mock

import (
	"context"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/remoteconsoles"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servergroups"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/floatingips"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

type ExternalNetworkInterfsce interface {
	ExternalNetworks(ctx context.Context) ([]networks.Network, error)
}

type NetworkInterface interface {
	GetNetwork(ctx context.Context, network *unikornv1.Network) (*NetworkExt, error)
	CreateNetwork(ctx context.Context, network *unikornv1.Network, vlanID *int) (*networks.Network, error)
	DeleteNetwork(ctx context.Context, id string) error
}

type SubnetInterface interface {
	GetSubnet(ctx context.Context, network *unikornv1.Network) (*subnets.Subnet, error)
	CreateSubnet(ctx context.Context, network *unikornv1.Network, networkID string, prefix, gatewayID string, dnsNameservers []string, allocationPools []subnets.AllocationPool) (*subnets.Subnet, error)
	DeleteSubnet(ctx context.Context, id string) error
}

type RouterInterface interface {
	GetRouter(ctx context.Context, network *unikornv1.Network) (*routers.Router, error)
	CreateRouter(ctx context.Context, network *unikornv1.Network) (*routers.Router, error)
	DeleteRouter(ctx context.Context, id string) error

	AddRouterInterface(ctx context.Context, routerID, subnetID string) error
	RemoveRouterInterface(ctx context.Context, routerID, subnetID string) error
}

type SecurityGroupInterface interface {
	GetSecurityGroup(ctx context.Context, securityGroup *unikornv1.SecurityGroup) (*groups.SecGroup, error)
	CreateSecurityGroup(ctx context.Context, securityGroup *unikornv1.SecurityGroup) (*groups.SecGroup, error)
	DeleteSecurityGroup(ctx context.Context, securityGroupID string) error
	ListSecurityGroupRules(ctx context.Context, securityGroupID string) ([]rules.SecGroupRule, error)
	CreateSecurityGroupRule(ctx context.Context, securityGroupID string, direction rules.RuleDirection, protocol rules.RuleProtocol, portStart, portEnd int, prefix string) (*rules.SecGroupRule, error)
	DeleteSecurityGroupRule(ctx context.Context, securityGroupID, ruleID string) error
}

type FloatingIPInterface interface {
	GetFloatingIP(ctx context.Context, portID string) (*floatingips.FloatingIP, error)
	CreateFloatingIP(ctx context.Context, portID string) (*floatingips.FloatingIP, error)
	DeleteFloatingIP(ctx context.Context, id string) error
}

type PortInterface interface {
	ListServerPorts(ctx context.Context, serverID string) ([]ports.Port, error)
	ListRouterPorts(ctx context.Context, routerID string) ([]ports.Port, error)
	GetPort(ctx context.Context, serverID string) (*ports.Port, error)
	CreatePort(ctx context.Context, networkID, serverID string, securityGroupIDs []string, allowedAddressPairs []ports.AddressPair) (*ports.Port, error)
	UpdatePort(ctx context.Context, portID string, securityGroupIDs []string, allowedAddressPairs []ports.AddressPair) (*ports.Port, error)
	DeletePort(ctx context.Context, portID string) error
}

type NetworkingInterface interface {
	ExternalNetworkInterfsce
	NetworkInterface
	SubnetInterface
	RouterInterface
	SecurityGroupInterface
	FloatingIPInterface
	PortInterface
}

type KeypairInterface interface {
	CreateKeypair(ctx context.Context, name, publicKey string) error
	DeleteKeypair(ctx context.Context, name string) error
}

type FlavorInterface interface {
	GetFlavors(ctx context.Context) ([]flavors.Flavor, error)
}

type ServerGroupInterface interface {
	CreateServerGroup(ctx context.Context, name string) (*servergroups.ServerGroup, error)
	DeleteServerGroup(ctx context.Context, id string) error
}

type ComputeQuotaInterface interface {
	UpdateQuotas(ctx context.Context, projectID string) error
}

type ServerInterface interface {
	GetServer(ctx context.Context, server *unikornv1.Server) (*servers.Server, error)
	CreateServer(ctx context.Context, server *unikornv1.Server, keyName string, networks []servers.Network, serverGroupID *string, metadata map[string]string) (*servers.Server, error)
	DeleteServer(ctx context.Context, id string) error
	RebootServer(ctx context.Context, id string, hard bool) error
	StartServer(ctx context.Context, id string) error
	StopServer(ctx context.Context, id string) error
	CreateRemoteConsole(ctx context.Context, id string) (*remoteconsoles.RemoteConsole, error)
	ShowConsoleOutput(ctx context.Context, id string, length *int) (string, error)
	CreateImageFromServer(ctx context.Context, id string, opts *servers.CreateImageOpts) (string, error)
}

type ComputeInterface interface {
	KeypairInterface
	FlavorInterface
	ServerGroupInterface
	ComputeQuotaInterface
	ServerInterface
}
