/*
Copyright 2022-2024 EscherCloud.
Copyright 2024 the Unikorn Authors.

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
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/external"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/provider"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/networks"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	"github.com/unikorn-cloud/core/pkg/util/cache"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
)

var (
	// ErrConfiguration is raised when a feature requires additional configuration
	// and none is provided for the region.
	ErrConfiguration = errors.New("required configuration missing")

	// ErrUnsufficentResource is retuend when we've run out of space.
	ErrUnsufficentResource = errors.New("unsufficient resource for request")
)

// NetworkClient wraps the generic client because gophercloud is unsafe.
type NetworkClient struct {
	client *gophercloud.ServiceClient

	externalNetworkCache *cache.TimeoutCache[[]networks.Network]

	options *unikornv1.RegionOpenstackNetworkSpec
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
		externalNetworkCache: cache.New[[]networks.Network](time.Hour),
	}

	return c, nil
}

func NewTestNetworkClient(options *unikornv1.RegionOpenstackNetworkSpec) *NetworkClient {
	return &NetworkClient{
		options: options,
	}
}

// ExternalNetworks returns a list of external networks.
func (c *NetworkClient) ExternalNetworks(ctx context.Context) ([]networks.Network, error) {
	if result, ok := c.externalNetworkCache.Get(); ok {
		return result, nil
	}

	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "/networking/v2.0/networks", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	affirmative := true

	page, err := networks.List(c.client, &external.ListOptsExt{ListOptsBuilder: &networks.ListOpts{}, External: &affirmative}).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	var results []networks.Network

	if err := networks.ExtractNetworksInto(page, &results); err != nil {
		return nil, err
	}

	c.externalNetworkCache.Set(results)

	return results, nil
}

// AllocateVLAN does exactly that using configured ID ranges and existing networks.
func (c *NetworkClient) AllocateVLAN(ctx context.Context) (int, error) {
	allocatable := make([]bool, 4096)

	// If no configuration is given, own all of the IDs.  If there are a list
	// of segments, only allow those.
	if c.options == nil || c.options.VLAN == nil || c.options.VLAN.Segments == nil {
		for i := 1; i < 4096; i++ {
			allocatable[i] = true
		}
	} else {
		for _, segment := range c.options.VLAN.Segments {
			for i := segment.StartID; i < segment.EndID+1; i++ {
				allocatable[i] = true
			}
		}
	}

	// TODO: Next remove the ones we know are already allocated.
	for i := range allocatable {
		if allocatable[i] {
			return i, nil
		}
	}

	return -1, ErrUnsufficentResource
}

// CreateVLANProviderNetwork creates a VLAN provider network for a project.
func (c *NetworkClient) CreateVLANProviderNetwork(ctx context.Context, name string, projectID string) (*networks.Network, error) {
	if c.options == nil || c.options.PhysicalNetwork == nil {
		return nil, ErrConfiguration
	}

	vlanID, err := c.AllocateVLAN(ctx)
	if err != nil {
		return nil, err
	}

	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "/networking/v2.0/networks", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	opts := &provider.CreateOptsExt{
		CreateOptsBuilder: &networks.CreateOpts{
			Name:        name,
			Description: "unikorn provider network",
			ProjectID:   projectID,
		},
		Segments: []provider.Segment{
			{
				NetworkType:     "vlan",
				PhysicalNetwork: *c.options.PhysicalNetwork,
				SegmentationID:  vlanID,
			},
		},
	}

	return networks.Create(ctx, c.client, opts).Extract()
}
