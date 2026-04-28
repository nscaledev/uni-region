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

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

var errLoadBalancerUnsupported = errors.New("load balancer provider support not implemented")

func (p *Provider) CreateLoadBalancer(_ context.Context, _ *unikornv1.Identity, _ *unikornv1.LoadBalancer) error {
	return errLoadBalancerUnsupported
}

func (p *Provider) DeleteLoadBalancer(_ context.Context, _ *unikornv1.Identity, _ *unikornv1.LoadBalancer) error {
	return errLoadBalancerUnsupported
}
