/*
Copyright 2024 the Unikorn Authors.

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

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coremanager "github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/region"
)

// Provisioner encapsulates control plane provisioning.
type Provisioner struct {
	provisioners.Metadata

	// identity is the identity we're provisioning.
	identity *unikornv1.Identity
}

// New returns a new initialized provisioner object.
func New(_ coremanager.ControllerOptions) provisioners.ManagerProvisioner {
	return &Provisioner{
		identity: &unikornv1.Identity{},
	}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.identity
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	cli, err := coreclient.ProvisionerClientFromContext(ctx)
	if err != nil {
		return err
	}

	provider, err := region.NewClient(cli, p.identity.Namespace).Provider(ctx, p.identity.Labels[constants.RegionLabel])
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
	cli, err := coreclient.ProvisionerClientFromContext(ctx)
	if err != nil {
		return err
	}

	provider, err := region.NewClient(cli, p.identity.Namespace).Provider(ctx, p.identity.Labels[constants.RegionLabel])
	if err != nil {
		return err
	}

	if err := provider.DeleteIdentity(ctx, p.identity); err != nil {
		return err
	}

	return nil
}
