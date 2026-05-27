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

package openstack

import (
	"context"
	"errors"
	"fmt"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/baremetal/v1/nodes"
)

var ErrMultipleIronicNodes = errors.New("multiple ironic nodes found")

type BaremetalClient struct {
	client *gophercloud.ServiceClient
}

func NewBaremetalClient(ctx context.Context, provider CredentialProvider) (*BaremetalClient, error) {
	providerClient, err := provider.Client(ctx)
	if err != nil {
		return nil, err
	}

	client, err := openstack.NewBareMetalV1(providerClient, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}

	return &BaremetalClient{client: client}, nil
}

func (c *BaremetalClient) GetNodeByInstanceUUID(ctx context.Context, instanceUUID string) (*nodes.Node, error) {
	page, err := nodes.ListDetail(c.client, nodes.ListOpts{InstanceUUID: instanceUUID}).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	result, err := nodes.ExtractNodes(page)
	if err != nil {
		return nil, err
	}

	switch len(result) {
	case 0:
		//nolint:nilnil // A missing Ironic node is a valid queued state, not an error.
		return nil, nil
	case 1:
		return &result[0], nil
	default:
		return nil, fmt.Errorf("%w for instance_uuid %q", ErrMultipleIronicNodes, instanceUUID)
	}
}
