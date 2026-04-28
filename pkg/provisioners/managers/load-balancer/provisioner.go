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

	"github.com/spf13/pflag"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/provisioners/internal/base"

	"sigs.k8s.io/controller-runtime/pkg/log"
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

	// Base gives this type methods for getting identities and providers.
	base.Base
}

// New returns a new initialized provisioner object.
func New(options manager.ControllerOptions, providers providers.Providers) provisioners.ManagerProvisioner {
	o, _ := options.(*Options)

	return &Provisioner{
		loadbalancer: &unikornv1.LoadBalancer{},
		options:      o,
		Base: base.Base{
			Providers: providers,
		},
	}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.loadbalancer
}

func (p *Provisioner) identityClient(ctx context.Context) (identityapi.ClientWithResponsesInterface, error) {
	client, err := coreclient.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	return identityclient.New(client, p.options.identityOptions, &p.options.clientOptions).ControllerClient(ctx, p.loadbalancer)
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	log.FromContext(ctx).Info("load balancer provision (scaffold, no-op)", "name", p.loadbalancer.Name, "namespace", p.loadbalancer.Namespace)

	return provisioners.ErrYield
}

// Deprovision implements the Provision interface.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	log.FromContext(ctx).Info("load balancer deprovision (release quota allocation)", "name", p.loadbalancer.Name, "namespace", p.loadbalancer.Namespace)

	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	api, err := p.identityClient(ctx)
	if err != nil {
		return err
	}

	if err := identityclient.NewAllocations(cli, api).Delete(ctx, p.loadbalancer); err != nil {
		return err
	}

	return nil
}
