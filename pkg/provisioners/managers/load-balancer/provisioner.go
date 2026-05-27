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

package loadbalancer

import (
	"context"
	"fmt"

	"github.com/spf13/pflag"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/provisioners/internal/base"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Options allows access to CLI options in the provisioner.
type Options struct {
	// identityOptions allow the identity host and CA to be set.
	identityOptions *identityclient.Options
	// clientOptions give access to client certificate information for controller-to-API calls.
	clientOptions coreclient.HTTPClientOptions
}

func (o *Options) AddFlags(f *pflag.FlagSet) {
	if o.identityOptions == nil {
		o.identityOptions = identityclient.NewOptions()
	}

	o.identityOptions.AddFlags(f)
	o.clientOptions.AddFlags(f)
}

// Provisioner encapsulates control plane provisioning.
type Provisioner struct {
	provisioners.Metadata
	// loadbalancer is the load balancer we're provisioning.
	loadbalancer *unikornv1.LoadBalancer
	// options are documented for the type.
	options *Options

	// WithIdentity gives this type methods for providers and identity service access.
	base.WithIdentity
}

// New returns a new initialized provisioner object.
func New(options manager.ControllerOptions, providers providers.Providers) provisioners.ManagerProvisioner {
	o, _ := options.(*Options)

	return &Provisioner{
		loadbalancer: &unikornv1.LoadBalancer{},
		options:      o,
		WithIdentity: base.WithIdentity{
			Base: base.Base{
				Providers: providers,
			},
			IdentityClients: base.NewIdentityClientFactory(o.identityOptions, &o.clientOptions),
		},
	}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.loadbalancer
}

// network resolves the Network referenced by constants.NetworkLabel.
func (p *Provisioner) network(ctx context.Context) (*unikornv1.Network, error) {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	networkID, ok := p.loadbalancer.Labels[constants.NetworkLabel]
	if !ok || networkID == "" {
		return nil, fmt.Errorf("%w: load balancer %s missing network label", coreerrors.ErrConsistency, p.loadbalancer.Name)
	}

	network := &unikornv1.Network{}
	if err := cli.Get(ctx, client.ObjectKey{Namespace: p.loadbalancer.Namespace, Name: networkID}, network); err != nil {
		return nil, err
	}

	return network, nil
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	provider, identity, err := p.ProviderAndIdentity(ctx, p.loadbalancer)
	if err != nil {
		return err
	}

	network, err := p.network(ctx)
	if err != nil {
		return err
	}

	if err := manager.ResourceReady(ctx, network); err != nil {
		return err
	}

	if err := manager.ResourceReady(ctx, identity); err != nil {
		return err
	}

	return provider.CreateLoadBalancer(ctx, identity, p.loadbalancer)
}

// Deprovision implements the Provision interface.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	provider, identity, err := p.ProviderAndIdentity(ctx, p.loadbalancer)
	if err != nil {
		return err
	}

	if err := provider.DeleteLoadBalancer(ctx, identity, p.loadbalancer); err != nil {
		return err
	}

	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	api, err := p.IdentityClient(ctx, p.loadbalancer)
	if err != nil {
		return err
	}

	return identityclient.NewAllocations(cli, api).Delete(ctx, p.loadbalancer)
}
