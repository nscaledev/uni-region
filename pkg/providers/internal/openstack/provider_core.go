/*
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

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type core struct {
	// client is the Kubernetes API client.
	client client.Client

	// openstack has the OpenStack service clients.
	openstack *openStackClients
}

func newCore(cli client.Client, region *unikornv1.Region) core {
	return core{
		client: cli,
		openstack: &openStackClients{
			client:  cli,
			_region: region,
		},
	}
}

func (c core) GetOpenstackIdentity(ctx context.Context, identity *unikornv1.Identity) (*unikornv1.OpenstackIdentity, error) {
	var result unikornv1.OpenstackIdentity

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: identity.Namespace, Name: identity.Name}, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// getProviderFromServicePrincipalData creates a generic provider client from ephemeral
// per-service principal credentials.
func (c core) getProviderFromServicePrincipalData(identity *unikornv1.OpenstackIdentity) (CredentialProvider, error) {
	if identity.Spec.UserID == nil {
		return nil, fmt.Errorf("%w: service principal user ID not set", coreerrors.ErrConsistency)
	}

	if identity.Spec.Password == nil {
		return nil, fmt.Errorf("%w: service principal password not set", coreerrors.ErrConsistency)
	}

	if identity.Spec.ProjectID == nil {
		return nil, fmt.Errorf("%w: service principal project not set", coreerrors.ErrConsistency)
	}

	region, _ := c.openstack.regionSnapshot()

	return NewPasswordProvider(region.Spec.Openstack.Endpoint, *identity.Spec.UserID, *identity.Spec.Password, *identity.Spec.ProjectID), nil
}

// computeFromServicePrincipalData gets a compute client scoped to the service principal data.
func (c core) computeFromServicePrincipalData(ctx context.Context, identity *unikornv1.OpenstackIdentity) (ComputeInterface, error) {
	provider, err := c.getProviderFromServicePrincipalData(identity)
	if err != nil {
		return nil, err
	}

	region, _ := c.openstack.regionSnapshot()

	client, err := NewComputeClient(ctx, provider, region.Spec.Openstack.Compute)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// getProviderFromServicePrincipal takes a service principal and returns a generic
// provider client for it.
func (c core) getProviderFromServicePrincipal(ctx context.Context, identity *unikornv1.Identity) (CredentialProvider, error) {
	openstackIdentity, err := c.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return nil, err
	}

	return c.getProviderFromServicePrincipalData(openstackIdentity)
}

// getPrivilegedProviderFromServicePrincipal binds itself to the service principal's project
// but uses the provider's top level admin credentials.
func (c core) getPrivilegedProviderFromServicePrincipal(ctx context.Context, identity *unikornv1.Identity) (CredentialProvider, error) {
	openstackIdentity, err := c.GetOpenstackIdentity(ctx, identity)
	if err != nil {
		return nil, err
	}

	if openstackIdentity.Spec.ProjectID == nil {
		return nil, fmt.Errorf("%w: service principal project not set", coreerrors.ErrConsistency)
	}

	region, credentials := c.openstack.regionSnapshot()

	return NewPasswordProvider(region.Spec.Openstack.Endpoint, credentials.userID, credentials.password, *openstackIdentity.Spec.ProjectID), nil
}

// computeFromServicePrincipal gets a compute client scoped to the service principal.
func (c core) computeFromServicePrincipal(ctx context.Context, identity *unikornv1.Identity) (ComputeInterface, error) {
	provider, err := c.getProviderFromServicePrincipal(ctx, identity)
	if err != nil {
		return nil, err
	}

	region, _ := c.openstack.regionSnapshot()

	client, err := NewComputeClient(ctx, provider, region.Spec.Openstack.Compute)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// networkFromServicePrincipal gets a network client scoped to the service principal.
func (c core) networkFromServicePrincipal(ctx context.Context, identity *unikornv1.Identity) (NetworkingInterface, error) {
	provider, err := c.getProviderFromServicePrincipal(ctx, identity)
	if err != nil {
		return nil, err
	}

	region, _ := c.openstack.regionSnapshot()

	client, err := NewNetworkClient(ctx, provider, region.Spec.Openstack.Network)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// privilegedNetworkFromServicePrincipal gets a network client scoped to the service principal's
// project but with "manager" credentials.
func (c core) privilegedNetworkFromServicePrincipal(ctx context.Context, identity *unikornv1.Identity) (NetworkingInterface, error) {
	provider, err := c.getPrivilegedProviderFromServicePrincipal(ctx, identity)
	if err != nil {
		return nil, err
	}

	region, _ := c.openstack.regionSnapshot()

	client, err := NewNetworkClient(ctx, provider, region.Spec.Openstack.Network)
	if err != nil {
		return nil, err
	}

	return client, nil
}
