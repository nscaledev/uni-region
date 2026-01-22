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

package identity

import (
	"context"

	"github.com/spf13/pflag"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coremanager "github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers/types"
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
	o.identityOptions = identityclient.NewOptions()

	o.identityOptions.AddFlags(f)
	o.clientOptions.AddFlags(f)
}

// Provisioner encapsulates control plane provisioning.
type Provisioner struct {
	provisioners.Metadata
	// identity is the identity we're provisioning.
	identity *unikornv1.Identity

	// options are CLI options.
	options *Options
}

// New returns a new initialized provisioner object.
func New(options coremanager.ControllerOptions) provisioners.ManagerProvisioner {
	return &Provisioner{
		identity: &unikornv1.Identity{},
		//nolint:forcetypeassert
		options: options.(*Options),
	}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.identity
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	if err := identityclient.NewReferences(constants.ServiceDescriptor(), p.options.identityOptions, &p.options.clientOptions).AddReferenceToProject(ctx, p.identity); err != nil {
		return err
	}

	provider, err := base.Provider[types.Identity](ctx, p.identity)
	if err != nil {
		return err
	}

	if err := provider.CreateIdentity(ctx, p.identity); err != nil {
		return err
	}

	return nil
}

// Deprovision implements the Provision interface.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	provider, err := base.Provider[types.Identity](ctx, p.identity)
	if err != nil {
		return err
	}

	if err := provider.DeleteIdentity(ctx, p.identity); err != nil {
		return err
	}

	if err := identityclient.NewReferences(constants.ServiceDescriptor(), p.options.identityOptions, &p.options.clientOptions).RemoveReferenceFromProject(ctx, p.identity); err != nil {
		// FIXME: Temporary workaround to prevent errors if the project has already been deleted.
		// Ideally, the server should prevent deletion of projects that are still referenced.
		if errors.IsHTTPNotFound(err) {
			return nil
		}

		return err
	}

	return nil
}
