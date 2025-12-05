/*
Copyright 2024-2025 the Unikorn Authors.

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

package network

import (
	"context"

	"github.com/spf13/pflag"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/provisioners/internal/base"
)

// Options allows access to CLI options in the provisioner.
type Options struct {
	// identityOptions allow the identity host and CA to be set.
	identityOptions *identityclient.Options
	// clientOptions give access to client certificate information as
	// we need to talk to identity to get a token, and then to region
	// to ensure cloud identities and networks are provisioned, as well
	// as deptovisioning them.
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
	// network is the network we're provisioning.
	network *unikornv1.Network
	// options are documented for the type.
	options *Options
}

// New returns a new initialized provisioner object.
func New(options manager.ControllerOptions) provisioners.ManagerProvisioner {
	o, _ := options.(*Options)

	return &Provisioner{
		network: &unikornv1.Network{},
		options: o,
	}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.network
}

func (p *Provisioner) identityClient(ctx context.Context) (identityapi.ClientWithResponsesInterface, error) {
	client, err := coreclient.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	issuer := identityclient.NewTokenIssuer(client, p.options.identityOptions, &p.options.clientOptions, constants.ServiceDescriptor())

	return identityclient.New(client, p.options.identityOptions, &p.options.clientOptions).ControllerClient(ctx, issuer, p.network)
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	provider, identity, err := base.ProviderAndIdentity(ctx, p.network)
	if err != nil {
		return err
	}

	// Inhibit provisioning until the identity is ready, as we may need the identity information
	// to create the physical network e.g. the project ID in the case of OpenStack.
	if err := manager.ResourceReady(ctx, identity); err != nil {
		return err
	}

	if err := provider.CreateNetwork(ctx, identity, p.network); err != nil {
		return err
	}

	return nil
}

// Deprovision implements the Provision interface.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	provider, identity, err := base.ProviderAndIdentity(ctx, p.network)
	if err != nil {
		return err
	}

	if err := provider.DeleteNetwork(ctx, identity, p.network); err != nil {
		return err
	}

	// Temporary hack, V1 networks don't have a discrete network allocation,
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	if v, ok := p.network.Labels[constants.ResourceAPIVersionLabel]; ok && v == constants.MarshalAPIVersion(2) {
		api, err := p.identityClient(ctx)
		if err != nil {
			return err
		}

		if err := identityclient.NewAllocations(cli, api).Delete(ctx, p.network); err != nil {
			return err
		}
	}

	return nil
}
