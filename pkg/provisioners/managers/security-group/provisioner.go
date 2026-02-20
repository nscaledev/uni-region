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

package securitygroup

import (
	"context"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/provisioners/internal/base"
)

// Provisioner encapsulates control plane provisioning.
type Provisioner struct {
	provisioners.Metadata
	// securitygroup is the security group we're provisioning.
	securitygroup *unikornv1.SecurityGroup

	// Base gives this type methods for getting identities and providers.
	base.Base
}

// New returns a new initialized provisioner object.
func New(_ manager.ControllerOptions, providers providers.Providers) provisioners.ManagerProvisioner {
	return &Provisioner{
		securitygroup: &unikornv1.SecurityGroup{},
		Base: base.Base{
			Providers: providers,
		},
	}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.securitygroup
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	provider, identity, err := p.ProviderAndIdentity(ctx, p.securitygroup)
	if err != nil {
		return err
	}

	// Inhibit provisioning until the identity is ready, as we may need the identity information
	// to create the security group e.g. the project ID in the case of OpenStack.
	if err := manager.ResourceReady(ctx, identity); err != nil {
		return err
	}

	if err := provider.CreateSecurityGroup(ctx, identity, p.securitygroup); err != nil {
		return err
	}

	return nil
}

// Deprovision implements the Provision interface.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	provider, identity, err := p.ProviderAndIdentity(ctx, p.securitygroup)
	if err != nil {
		return err
	}

	if err := provider.DeleteSecurityGroup(ctx, identity, p.securitygroup); err != nil {
		return err
	}

	return nil
}
