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
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/loadbalancers"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/monitors"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/pools"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

var errLoadBalancerUnsupported = errors.New("load balancer provider support not implemented")

// LoadBalancerClient wraps the generic client because gophercloud is unsafe.
type LoadBalancerClient struct {
	client *gophercloud.ServiceClient
}

// NewLoadBalancerClient creates an Octavia v2 client.
func NewLoadBalancerClient(ctx context.Context, provider CredentialProvider) (*LoadBalancerClient, error) {
	providerClient, err := provider.Client(ctx)
	if err != nil {
		return nil, err
	}

	client, err := openstack.NewLoadBalancerV2(providerClient, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}

	// Need at least 2.22 for PROXYV2 pool protocol support.
	client.Microversion = "2.22"

	return &LoadBalancerClient{
		client: client,
	}, nil
}

func loadBalancerName(loadBalancer *unikornv1.LoadBalancer) string {
	return "lb-" + loadBalancer.Name
}

func loadBalancerListenerName(loadBalancer *unikornv1.LoadBalancer, listener *unikornv1.LoadBalancerListener) string {
	return loadBalancerName(loadBalancer) + "-" + listener.Name + "-listener"
}

func loadBalancerPoolName(loadBalancer *unikornv1.LoadBalancer, listener *unikornv1.LoadBalancerListener) string {
	return loadBalancerName(loadBalancer) + "-" + listener.Name + "-pool"
}

func loadBalancerMonitorName(loadBalancer *unikornv1.LoadBalancer, listener *unikornv1.LoadBalancerListener) string {
	return loadBalancerName(loadBalancer) + "-" + listener.Name + "-monitor"
}

func findExactResource[T any](resources []T, expectedName, resource string, getName func(*T) string) (*T, error) {
	var result *T

	for i := range resources {
		if getName(&resources[i]) != expectedName {
			continue
		}

		if result != nil {
			return nil, fmt.Errorf("%w: found more than one %s with name %s", coreerrors.ErrConsistency, resource, expectedName)
		}

		result = &resources[i]
	}

	if result == nil {
		return nil, fmt.Errorf("%w: %s %s", coreerrors.ErrResourceNotFound, resource, expectedName)
	}

	return result, nil
}

func findExactLoadBalancer(resources []loadbalancers.LoadBalancer, name string) (*loadbalancers.LoadBalancer, error) {
	return findExactResource(resources, name, "load balancer", func(resource *loadbalancers.LoadBalancer) string {
		return resource.Name
	})
}

func findExactListener(resources []listeners.Listener, name string) (*listeners.Listener, error) {
	return findExactResource(resources, name, "load balancer listener", func(resource *listeners.Listener) string {
		return resource.Name
	})
}

func findExactPool(resources []pools.Pool, name string) (*pools.Pool, error) {
	return findExactResource(resources, name, "load balancer pool", func(resource *pools.Pool) string {
		return resource.Name
	})
}

func findExactMonitor(resources []monitors.Monitor, name string) (*monitors.Monitor, error) {
	return findExactResource(resources, name, "load balancer health monitor", func(resource *monitors.Monitor) string {
		return resource.Name
	})
}

func (c *LoadBalancerClient) ListLoadBalancers(ctx context.Context, name string) ([]loadbalancers.LoadBalancer, error) {
	_, span := traceStart(ctx, "GET /load-balancer/v2.0/lbaas/loadbalancers")
	defer span.End()

	opts := loadbalancers.ListOpts{
		// NOTE: this is a regular expression match so foo-4 will match
		// foo-4, foo-48, foo-4444444444444.
		Name: name,
	}

	page, err := loadbalancers.List(c.client, opts).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	return loadbalancers.ExtractLoadBalancers(page)
}

func (c *LoadBalancerClient) GetLoadBalancer(ctx context.Context, loadBalancer *unikornv1.LoadBalancer) (*loadbalancers.LoadBalancer, error) {
	name := loadBalancerName(loadBalancer)

	result, err := c.ListLoadBalancers(ctx, name)
	if err != nil {
		return nil, err
	}

	return findExactLoadBalancer(result, name)
}

func (c *LoadBalancerClient) CreateLoadBalancer(ctx context.Context, opts loadbalancers.CreateOptsBuilder) (*loadbalancers.LoadBalancer, error) {
	_, span := traceStart(ctx, "POST /load-balancer/v2.0/lbaas/loadbalancers")
	defer span.End()

	result, err := loadbalancers.Create(ctx, c.client, opts).Extract()
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (c *LoadBalancerClient) UpdateLoadBalancer(ctx context.Context, id string, opts loadbalancers.UpdateOptsBuilder) (*loadbalancers.LoadBalancer, error) {
	spanAttributes := trace.WithAttributes(
		attribute.String("loadbalancer.load_balancer.id", id),
	)

	_, span := traceStart(ctx, "PUT /load-balancer/v2.0/lbaas/loadbalancers/{id}", spanAttributes)
	defer span.End()

	result, err := loadbalancers.Update(ctx, c.client, id, opts).Extract()
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (c *LoadBalancerClient) DeleteLoadBalancer(ctx context.Context, id string, cascade bool) error {
	spanAttributes := trace.WithAttributes(
		attribute.String("loadbalancer.load_balancer.id", id),
	)

	_, span := traceStart(ctx, "DELETE /load-balancer/v2.0/lbaas/loadbalancers/{id}", spanAttributes)
	defer span.End()

	var opts loadbalancers.DeleteOptsBuilder

	if cascade {
		opts = loadbalancers.DeleteOpts{
			Cascade: true,
		}
	}

	return loadbalancers.Delete(ctx, c.client, id, opts).ExtractErr()
}

func (c *LoadBalancerClient) ListListeners(ctx context.Context, loadBalancerID, name string) ([]listeners.Listener, error) {
	_, span := traceStart(ctx, "GET /load-balancer/v2.0/lbaas/listeners")
	defer span.End()

	opts := listeners.ListOpts{
		// NOTE: this is a regular expression match so foo-4 will match
		// foo-4, foo-48, foo-4444444444444.
		Name:           name,
		LoadbalancerID: loadBalancerID,
	}

	page, err := listeners.List(c.client, opts).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	return listeners.ExtractListeners(page)
}

func (c *LoadBalancerClient) GetListener(ctx context.Context, loadBalancerID string, loadBalancer *unikornv1.LoadBalancer, listener *unikornv1.LoadBalancerListener) (*listeners.Listener, error) {
	name := loadBalancerListenerName(loadBalancer, listener)

	result, err := c.ListListeners(ctx, loadBalancerID, name)
	if err != nil {
		return nil, err
	}

	return findExactListener(result, name)
}

func (c *LoadBalancerClient) CreateListener(ctx context.Context, opts listeners.CreateOptsBuilder) (*listeners.Listener, error) {
	_, span := traceStart(ctx, "POST /load-balancer/v2.0/lbaas/listeners")
	defer span.End()

	result, err := listeners.Create(ctx, c.client, opts).Extract()
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (c *LoadBalancerClient) UpdateListener(ctx context.Context, id string, opts listeners.UpdateOptsBuilder) (*listeners.Listener, error) {
	spanAttributes := trace.WithAttributes(
		attribute.String("loadbalancer.listener.id", id),
	)

	_, span := traceStart(ctx, "PUT /load-balancer/v2.0/lbaas/listeners/{id}", spanAttributes)
	defer span.End()

	result, err := listeners.Update(ctx, c.client, id, opts).Extract()
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (c *LoadBalancerClient) DeleteListener(ctx context.Context, id string) error {
	spanAttributes := trace.WithAttributes(
		attribute.String("loadbalancer.listener.id", id),
	)

	_, span := traceStart(ctx, "DELETE /load-balancer/v2.0/lbaas/listeners/{id}", spanAttributes)
	defer span.End()

	return listeners.Delete(ctx, c.client, id).ExtractErr()
}

func (c *LoadBalancerClient) ListPools(ctx context.Context, loadBalancerID, name string) ([]pools.Pool, error) {
	_, span := traceStart(ctx, "GET /load-balancer/v2.0/lbaas/pools")
	defer span.End()

	opts := pools.ListOpts{
		// NOTE: this is a regular expression match so foo-4 will match
		// foo-4, foo-48, foo-4444444444444.
		Name:           name,
		LoadbalancerID: loadBalancerID,
	}

	page, err := pools.List(c.client, opts).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	return pools.ExtractPools(page)
}

func (c *LoadBalancerClient) GetPool(ctx context.Context, loadBalancerID string, loadBalancer *unikornv1.LoadBalancer, listener *unikornv1.LoadBalancerListener) (*pools.Pool, error) {
	name := loadBalancerPoolName(loadBalancer, listener)

	result, err := c.ListPools(ctx, loadBalancerID, name)
	if err != nil {
		return nil, err
	}

	return findExactPool(result, name)
}

func (c *LoadBalancerClient) CreatePool(ctx context.Context, opts pools.CreateOptsBuilder) (*pools.Pool, error) {
	_, span := traceStart(ctx, "POST /load-balancer/v2.0/lbaas/pools")
	defer span.End()

	result, err := pools.Create(ctx, c.client, opts).Extract()
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (c *LoadBalancerClient) UpdatePool(ctx context.Context, id string, opts pools.UpdateOptsBuilder) (*pools.Pool, error) {
	spanAttributes := trace.WithAttributes(
		attribute.String("loadbalancer.pool.id", id),
	)

	_, span := traceStart(ctx, "PUT /load-balancer/v2.0/lbaas/pools/{id}", spanAttributes)
	defer span.End()

	result, err := pools.Update(ctx, c.client, id, opts).Extract()
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (c *LoadBalancerClient) DeletePool(ctx context.Context, id string) error {
	spanAttributes := trace.WithAttributes(
		attribute.String("loadbalancer.pool.id", id),
	)

	_, span := traceStart(ctx, "DELETE /load-balancer/v2.0/lbaas/pools/{id}", spanAttributes)
	defer span.End()

	return pools.Delete(ctx, c.client, id).ExtractErr()
}

func (c *LoadBalancerClient) ListMembers(ctx context.Context, poolID string) ([]pools.Member, error) {
	spanAttributes := trace.WithAttributes(
		attribute.String("loadbalancer.pool.id", poolID),
	)

	_, span := traceStart(ctx, "GET /load-balancer/v2.0/lbaas/pools/{id}/members", spanAttributes)
	defer span.End()

	page, err := pools.ListMembers(c.client, poolID, nil).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	return pools.ExtractMembers(page)
}

func (c *LoadBalancerClient) BatchUpdateMembers(ctx context.Context, poolID string, opts []pools.BatchUpdateMemberOpts) error {
	spanAttributes := trace.WithAttributes(
		attribute.String("loadbalancer.pool.id", poolID),
	)

	_, span := traceStart(ctx, "PUT /load-balancer/v2.0/lbaas/pools/{id}/members", spanAttributes)
	defer span.End()

	return pools.BatchUpdateMembers(ctx, c.client, poolID, opts).ExtractErr()
}

func (c *LoadBalancerClient) ListMonitors(ctx context.Context, poolID, name string) ([]monitors.Monitor, error) {
	_, span := traceStart(ctx, "GET /load-balancer/v2.0/lbaas/healthmonitors")
	defer span.End()

	opts := monitors.ListOpts{
		// NOTE: this is a regular expression match so foo-4 will match
		// foo-4, foo-48, foo-4444444444444.
		Name:   name,
		PoolID: poolID,
	}

	page, err := monitors.List(c.client, opts).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	return monitors.ExtractMonitors(page)
}

func (c *LoadBalancerClient) GetMonitor(ctx context.Context, poolID string, loadBalancer *unikornv1.LoadBalancer, listener *unikornv1.LoadBalancerListener) (*monitors.Monitor, error) {
	name := loadBalancerMonitorName(loadBalancer, listener)

	result, err := c.ListMonitors(ctx, poolID, name)
	if err != nil {
		return nil, err
	}

	return findExactMonitor(result, name)
}

func (c *LoadBalancerClient) CreateMonitor(ctx context.Context, opts monitors.CreateOptsBuilder) (*monitors.Monitor, error) {
	_, span := traceStart(ctx, "POST /load-balancer/v2.0/lbaas/healthmonitors")
	defer span.End()

	result, err := monitors.Create(ctx, c.client, opts).Extract()
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (c *LoadBalancerClient) UpdateMonitor(ctx context.Context, id string, opts monitors.UpdateOptsBuilder) (*monitors.Monitor, error) {
	spanAttributes := trace.WithAttributes(
		attribute.String("loadbalancer.health_monitor.id", id),
	)

	_, span := traceStart(ctx, "PUT /load-balancer/v2.0/lbaas/healthmonitors/{id}", spanAttributes)
	defer span.End()

	result, err := monitors.Update(ctx, c.client, id, opts).Extract()
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (c *LoadBalancerClient) DeleteMonitor(ctx context.Context, id string) error {
	spanAttributes := trace.WithAttributes(
		attribute.String("loadbalancer.health_monitor.id", id),
	)

	_, span := traceStart(ctx, "DELETE /load-balancer/v2.0/lbaas/healthmonitors/{id}", spanAttributes)
	defer span.End()

	return monitors.Delete(ctx, c.client, id).ExtractErr()
}
