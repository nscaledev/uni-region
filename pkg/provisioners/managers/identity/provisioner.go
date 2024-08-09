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
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/region"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Provisioner encapsulates control plane provisioning.
type Provisioner struct {
	provisioners.Metadata

	// identity is the identity we're provisioning.
	identity *unikornv1.Identity
}

// New returns a new initialized provisioner object.
func New() provisioners.ManagerProvisioner {
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

	object := p.identity.DeepCopy()

	// Always try to update the resource as that carries state that allows us to
	// be idempotent.
	// TODO: most all of this mess goes away if we create a separate CR that can
	// be updated by the controller independently of the identity.
	update := func() {
		log := log.FromContext(ctx)

		// This unfortunately will trigger another reconcile, but experience has told us
		// that carrying infromation in the status is a bad idea, first as some backup
		// solutions won't restore the status, and second we cannot re-geenrate things
		// like passwords and secrets that are only available once.
		if err := cli.Patch(ctx, object, client.MergeFrom(p.identity)); err != nil {
			log.Error(err, "failed to update resource")
		}

		// Update the object that the core controller refers to so that the resource
		// version is up to date when it updates the status.  This doesn't always work
		// either!
		p.identity = object
	}

	defer update()

	if err := provider.CreateIdentity(ctx, object); err != nil {
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
