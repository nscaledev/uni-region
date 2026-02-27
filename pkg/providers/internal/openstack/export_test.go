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
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NewImageQuery makes the internal implementation of ImageQuery available for testing
// on its own.
func NewImageQuery(listFunc func(context.Context) ([]images.Image, error)) types.ImageQuery {
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
var ImageTags = imageTags

//nolint:gochecknoglobals
var CreateImageMetadata = createImageMetadata

func NewTestProvider(client client.Client, region *unikornv1.Region) *Provider {
	return &Provider{
		client:  client,
		_region: region,
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

func ReconcileServer(ctx context.Context, p *Provider, client ServerInterface, server *unikornv1.Server, port *ports.Port, keyName string) (*servers.Server, error) {
	// Lewis Denham-Parry was here.
	return p.reconcileServer(ctx, client, server, port, keyName)
}
