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

package network

import (
	"context"

	"github.com/spf13/pflag"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers"
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

	// WithIdentity gives us methods for providers and identity service access.
	base.WithIdentity
}

// New returns a new initialized provisioner object.
func New(options manager.ControllerOptions, providers providers.Providers) provisioners.ManagerProvisioner {
	o, _ := options.(*Options)

	return &Provisioner{
		network: &unikornv1.Network{},
		options: o,
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
	return p.network
}

func identityReady(identity *unikornv1.Identity) bool {
	condition, err := identity.StatusConditionRead(unikornv1core.ConditionAvailable)
	if err != nil {
		return false
	}

	return condition.Reason == unikornv1core.ConditionReasonProvisioned
}

func providerResourceIDsRecorded(network *unikornv1.Network) bool {
	if network.Status.Openstack == nil {
		return false
	}

	return network.Status.Openstack.NetworkID != nil ||
		network.Status.Openstack.SubnetID != nil ||
		network.Status.Openstack.VlanID != nil
}

func needsProviderDelete(identity *unikornv1.Identity, network *unikornv1.Network) bool {
	// A v2 network can be deleted after the API has created its identity-side
	// allocation but before provisioning has waited for Identity readiness and
	// recorded provider resource IDs. In that window there is nothing for the
	// provider to delete, and waiting for Identity readiness would leak the
	// allocation.
	return identityReady(identity) || providerResourceIDsRecorded(network)
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	provider, identity, err := p.ProviderAndIdentity(ctx, p.network)
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
	provider, identity, err := p.ProviderAndIdentity(ctx, p.network)
	if err != nil {
		return err
	}

	if needsProviderDelete(identity, p.network) {
		if err := provider.DeleteNetwork(ctx, identity, p.network); err != nil {
			return err
		}
	}

	// Temporary hack, V1 networks don't have a discrete network allocation,
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	if v, ok := p.network.Labels[constants.ResourceAPIVersionLabel]; ok && v == constants.MarshalAPIVersion(2) {
		api, err := p.IdentityClient(ctx, p.network)
		if err != nil {
			return err
		}

		if err := identityclient.NewAllocations(cli, api).Delete(ctx, p.network); err != nil {
			return err
		}
	}

	return nil
}
