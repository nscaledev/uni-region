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
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/keypairs"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/quotasets"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/remoteconsoles"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servergroups"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/util/cache"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"

	"k8s.io/utils/ptr"
)

// ComputeClient wraps the generic client because gophercloud is unsafe.
type ComputeClient struct {
	options *unikornv1.RegionOpenstackComputeSpec
	client  *gophercloud.ServiceClient

	flavorCache *cache.TimeoutCache[[]flavors.Flavor]
}

// NewComputeClient provides a simple one-liner to start computing.
func NewComputeClient(ctx context.Context, provider CredentialProvider, options *unikornv1.RegionOpenstackComputeSpec) (*ComputeClient, error) {
	providerClient, err := provider.Client(ctx)
	if err != nil {
		return nil, err
	}

	client, err := openstack.NewComputeV2(providerClient, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}

	// Need at least 2.15 for soft-anti-affinity policy.
	// Need at least 2.64 for new server group interface.
	client.Microversion = "2.90"

	c := &ComputeClient{
		options:     options,
		client:      client,
		flavorCache: cache.New[[]flavors.Flavor](time.Hour),
	}

	return c, nil
}

// CreateKeypair creates a new keypair.
// NOTE: while OpenStack can generate one for us, we have far more control doing it ourselves
// thus allowing us to impose stricter security, and it's more provider agnostic that way.
func (c *ComputeClient) CreateKeypair(ctx context.Context, name, publicKey string) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "POST /compute/v2/os-keypairs", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	opts := &keypairs.CreateOpts{
		Name:      name,
		Type:      "ssh",
		PublicKey: publicKey,
	}

	return keypairs.Create(ctx, c.client, opts).Err
}

func (c *ComputeClient) DeleteKeypair(ctx context.Context, name string) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("DELETE /compute/v2/os-keypairs/%s", name), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	return keypairs.Delete(ctx, c.client, name, nil).Err
}

// mutateFlavors allows nova's view of fact to be altered...
func (c *ComputeClient) mutateFlavors(f []flavors.Flavor) {
	if c.options == nil || c.options.Flavors == nil {
		return
	}

	for _, metadata := range c.options.Flavors.Metadata {
		index := slices.IndexFunc(f, func(flavor flavors.Flavor) bool {
			return flavor.ID == metadata.ID
		})

		if index < 0 {
			continue
		}

		if metadata.CPU != nil && metadata.CPU.Count != nil {
			f[index].VCPUs = *metadata.CPU.Count
		}

		if metadata.Memory != nil {
			// Convert from bytes to MiB
			f[index].RAM = int(metadata.Memory.Value() >> 20)
		}
	}
}

// Flavors returns a list of flavors.
func (c *ComputeClient) GetFlavors(ctx context.Context) ([]flavors.Flavor, error) {
	if result, ok := c.flavorCache.Get(); ok {
		return result, nil
	}

	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "GET /compute/v2/flavors", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	page, err := flavors.ListDetail(c.client, &flavors.ListOpts{SortKey: "name"}).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	result, err := flavors.ExtractFlavors(page)
	if err != nil {
		return nil, err
	}

	// Mutate any flavors first, as this may alter their selection criteria.
	c.mutateFlavors(result)

	result = slices.DeleteFunc(result, func(flavor flavors.Flavor) bool {
		// We are admin, so see all the things, throw out private flavors.
		if !flavor.IsPublic {
			return true
		}

		if c.options == nil || c.options.Flavors == nil {
			return false
		}

		if c.options.Flavors.Selector != nil && len(c.options.Flavors.Selector.IDs) > 0 {
			if !slices.Contains(c.options.Flavors.Selector.IDs, flavor.ID) {
				return true
			}
		}

		return false
	})

	c.flavorCache.Set(result)

	return result, nil
}

// CreateServerGroup creates the named server group with the given policy and returns
// the result.
func (c *ComputeClient) CreateServerGroup(ctx context.Context, name string) (*servergroups.ServerGroup, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "POST /compute/v2/os-server-groups", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	opts := &servergroups.CreateOpts{
		Name:   name,
		Policy: "soft-anti-affinity",
	}

	if c.options != nil && c.options.ServerGroupPolicy != nil {
		opts.Policy = *c.options.ServerGroupPolicy
	}

	return servergroups.Create(ctx, c.client, opts).Extract()
}

// DeleteServerGroup removes a server group, this exists because nova does do any cleanup
// on project deletion and just orphans the resource.
func (c *ComputeClient) DeleteServerGroup(ctx context.Context, id string) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "DELETE /compute/v2/os-server-groups/"+id)
	defer span.End()

	return servergroups.Delete(ctx, c.client, id).ExtractErr()
}

func (c *ComputeClient) UpdateQuotas(ctx context.Context, projectID string) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "PUT /compute/v2/os-quota-sets")
	defer span.End()

	opts := &quotasets.UpdateOpts{
		// TODO: instances, cores and ram need to be driven by client input.
		Instances: ptr.To(-1),
		Cores:     ptr.To(-1),
		RAM:       ptr.To(-1),
	}

	return quotasets.Update(ctx, c.client, projectID, opts).Err
}

func (c *ComputeClient) GetServer(ctx context.Context, server *unikornv1.Server) (*servers.Server, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "GET /compute/v2/servers")
	defer span.End()

	name := server.Labels[coreconstants.NameLabel]

	opts := servers.ListOpts{
		Name: name,
	}

	page, err := servers.List(c.client, opts).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	result, err := servers.ExtractServers(page)
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

func (c *ComputeClient) CreateServer(ctx context.Context, server *unikornv1.Server, keyName string, networks []servers.Network, serverGroupID *string, metadata map[string]string) (*servers.Server, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "POST /compute/v2/servers/")
	defer span.End()

	schedulerHintOpts := servers.SchedulerHintOpts{}

	if serverGroupID != nil {
		schedulerHintOpts.Group = *serverGroupID
	}

	name := server.Labels[coreconstants.NameLabel]

	serverCreateOpts := servers.CreateOpts{
		Name:      name,
		ImageRef:  server.Spec.Image.ID,
		FlavorRef: server.Spec.FlavorID,
		Networks:  networks,
		Metadata:  metadata,
		UserData:  server.Spec.UserData,
	}

	createOpts := keypairs.CreateOptsExt{
		CreateOptsBuilder: serverCreateOpts,
		KeyName:           keyName,
	}

	return servers.Create(ctx, c.client, createOpts, schedulerHintOpts).Extract()
}

func (c *ComputeClient) DeleteServer(ctx context.Context, id string) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("DELETE /compute/v2/servers/%s", id))
	defer span.End()

	return servers.Delete(ctx, c.client, id).ExtractErr()
}

func (c *ComputeClient) RebootServer(ctx context.Context, id string, hard bool) error {
	rebootMethod := servers.SoftReboot
	if hard {
		rebootMethod = servers.HardReboot
	}

	action := fmt.Sprintf("%s reboot", strings.ToLower(string(rebootMethod)))

	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("POST /compute/v2/servers/%s/action (%s)", id, action))
	defer span.End()

	opts := servers.RebootOpts{
		Type: rebootMethod,
	}

	return servers.Reboot(ctx, c.client, id, opts).ExtractErr()
}

func (c *ComputeClient) StartServer(ctx context.Context, id string) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("POST /compute/v2/servers/%s/action (start)", id))
	defer span.End()

	return servers.Start(ctx, c.client, id).ExtractErr()
}

func (c *ComputeClient) StopServer(ctx context.Context, id string) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("POST /compute/v2/servers/%s/action (stop)", id))
	defer span.End()

	return servers.Stop(ctx, c.client, id).ExtractErr()
}

func (c *ComputeClient) CreateRemoteConsole(ctx context.Context, id string) (*remoteconsoles.RemoteConsole, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("POST /compute/v2/servers/%s/remote-consoles", id))
	defer span.End()

	opts := remoteconsoles.CreateOpts{
		Protocol: remoteconsoles.ConsoleProtocolVNC,
		Type:     remoteconsoles.ConsoleTypeNoVNC,
	}

	return remoteconsoles.Create(ctx, c.client, id, opts).Extract()
}

func (c *ComputeClient) ShowConsoleOutput(ctx context.Context, id string, length *int) (string, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("GET /compute/v2/servers/%s/console-output", id))
	defer span.End()

	opts := &servers.ShowConsoleOutputOpts{}

	if length != nil {
		opts.Length = *length
	}

	return servers.ShowConsoleOutput(ctx, c.client, id, opts).Extract()
}
