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

package openstack_test

import (
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/loadbalancers"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/monitors"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/pools"
	"github.com/stretchr/testify/require"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func loadBalancerFixture() *regionv1.LoadBalancer {
	return &regionv1.LoadBalancer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
	}
}

func loadBalancerListenerFixture() *regionv1.LoadBalancerListener {
	return &regionv1.LoadBalancerListener{
		Name: "http",
	}
}

func TestLoadBalancerNames(t *testing.T) {
	t.Parallel()

	loadBalancer := loadBalancerFixture()
	listener := loadBalancerListenerFixture()

	require.Equal(t, "lb-test", openstack.LoadBalancerName(loadBalancer))
	require.Equal(t, "lb-test-http-listener", openstack.LoadBalancerListenerName(loadBalancer, listener))
	require.Equal(t, "lb-test-http-pool", openstack.LoadBalancerPoolName(loadBalancer, listener))
	require.Equal(t, "lb-test-http-monitor", openstack.LoadBalancerMonitorName(loadBalancer, listener))
}

func TestFindExactLoadBalancer(t *testing.T) {
	t.Parallel()

	name := openstack.LoadBalancerName(loadBalancerFixture())

	result, err := openstack.FindExactLoadBalancer([]loadbalancers.LoadBalancer{
		{
			ID:   "partial",
			Name: name + "-extra",
		},
		{
			ID:   "match",
			Name: name,
		},
	}, name)

	require.NoError(t, err)
	require.Equal(t, "match", result.ID)

	_, err = openstack.FindExactLoadBalancer([]loadbalancers.LoadBalancer{
		{
			ID:   "partial",
			Name: name + "-extra",
		},
	}, name)

	require.ErrorIs(t, err, coreerrors.ErrResourceNotFound)

	_, err = openstack.FindExactLoadBalancer([]loadbalancers.LoadBalancer{
		{
			ID:   "first",
			Name: name,
		},
		{
			ID:   "second",
			Name: name,
		},
	}, name)

	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}

func TestFindExactListener(t *testing.T) {
	t.Parallel()

	name := openstack.LoadBalancerListenerName(loadBalancerFixture(), loadBalancerListenerFixture())

	result, err := openstack.FindExactListener([]listeners.Listener{
		{
			ID:   "partial",
			Name: name + "-extra",
		},
		{
			ID:   "match",
			Name: name,
		},
	}, name)

	require.NoError(t, err)
	require.Equal(t, "match", result.ID)

	_, err = openstack.FindExactListener(nil, name)
	require.ErrorIs(t, err, coreerrors.ErrResourceNotFound)

	_, err = openstack.FindExactListener([]listeners.Listener{
		{
			ID:   "first",
			Name: name,
		},
		{
			ID:   "second",
			Name: name,
		},
	}, name)

	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}

func TestFindExactPool(t *testing.T) {
	t.Parallel()

	name := openstack.LoadBalancerPoolName(loadBalancerFixture(), loadBalancerListenerFixture())

	result, err := openstack.FindExactPool([]pools.Pool{
		{
			ID:   "partial",
			Name: name + "-extra",
		},
		{
			ID:   "match",
			Name: name,
		},
	}, name)

	require.NoError(t, err)
	require.Equal(t, "match", result.ID)

	_, err = openstack.FindExactPool(nil, name)
	require.ErrorIs(t, err, coreerrors.ErrResourceNotFound)

	_, err = openstack.FindExactPool([]pools.Pool{
		{
			ID:   "first",
			Name: name,
		},
		{
			ID:   "second",
			Name: name,
		},
	}, name)

	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}

func TestFindExactMonitor(t *testing.T) {
	t.Parallel()

	name := openstack.LoadBalancerMonitorName(loadBalancerFixture(), loadBalancerListenerFixture())

	result, err := openstack.FindExactMonitor([]monitors.Monitor{
		{
			ID:   "partial",
			Name: name + "-extra",
		},
		{
			ID:   "match",
			Name: name,
		},
	}, name)

	require.NoError(t, err)
	require.Equal(t, "match", result.ID)

	_, err = openstack.FindExactMonitor(nil, name)
	require.ErrorIs(t, err, coreerrors.ErrResourceNotFound)

	_, err = openstack.FindExactMonitor([]monitors.Monitor{
		{
			ID:   "first",
			Name: name,
		},
		{
			ID:   "second",
			Name: name,
		},
	}, name)

	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}
