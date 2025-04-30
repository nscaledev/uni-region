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

package securitygrouprule

import (
	"context"
	"errors"
	"fmt"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coremanager "github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/region"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	ErrResouceDependency = errors.New("resource dependency error")
)

// Provisioner encapsulates control plane provisioning.
type Provisioner struct {
	provisioners.Metadata

	// securitygrouprule is the security group we're provisioning.
	securitygrouprule *unikornv1.SecurityGroupRule
}

// New returns a new initialized provisioner object.
func New(_ coremanager.ControllerOptions) provisioners.ManagerProvisioner {
	return &Provisioner{
		securitygrouprule: &unikornv1.SecurityGroupRule{},
	}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.securitygrouprule
}

func (p *Provisioner) getIdentity(ctx context.Context, cli client.Client) (*unikornv1.Identity, error) {
	identity := &unikornv1.Identity{}

	if err := cli.Get(ctx, client.ObjectKey{Namespace: p.securitygrouprule.Namespace, Name: p.securitygrouprule.Labels[constants.IdentityLabel]}, identity); err != nil {
		return nil, err
	}

	return identity, nil
}

func (p *Provisioner) getSecurityGroup(ctx context.Context, cli client.Client) (*unikornv1.SecurityGroup, error) {
	securitygroup := &unikornv1.SecurityGroup{}

	if err := cli.Get(ctx, client.ObjectKey{Namespace: p.securitygrouprule.Namespace, Name: p.securitygrouprule.Labels[constants.SecurityGroupLabel]}, securitygroup); err != nil {
		return nil, err
	}

	return securitygroup, nil
}

func (p *Provisioner) validateResourceStatus(ctx context.Context, resource unikornv1core.ManagableResourceInterface) error {
	log := log.FromContext(ctx)

	// Inhibit provisioning until resource is ready
	status, err := resource.StatusConditionRead(unikornv1core.ConditionAvailable)
	if err != nil {
		log.Info("waiting for resource status update")

		return provisioners.ErrYield
	}

	//nolint:exhaustive
	switch status.Reason {
	case unikornv1core.ConditionReasonProvisioned:
		break
	case unikornv1core.ConditionReasonProvisioning:
		return provisioners.ErrYield
	default:
		return fmt.Errorf("%w: resource in unexpected condition %v", ErrResouceDependency, status.Reason)
	}

	return nil
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	cli, err := coreclient.ProvisionerClientFromContext(ctx)
	if err != nil {
		return err
	}

	provider, err := region.NewClient(cli, p.securitygrouprule.Namespace).Provider(ctx, p.securitygrouprule.Labels[constants.RegionLabel])
	if err != nil {
		return err
	}

	identity, err := p.getIdentity(ctx, cli)
	if err != nil {
		return err
	}

	if err := p.validateResourceStatus(ctx, identity); err != nil {
		return err
	}

	securitygroup, err := p.getSecurityGroup(ctx, cli)
	if err != nil {
		return err
	}

	if err := p.validateResourceStatus(ctx, securitygroup); err != nil {
		return err
	}

	if err := provider.CreateSecurityGroupRule(ctx, identity, securitygroup, p.securitygrouprule); err != nil {
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

	provider, err := region.NewClient(cli, p.securitygrouprule.Namespace).Provider(ctx, p.securitygrouprule.Labels[constants.RegionLabel])
	if err != nil {
		return err
	}

	identity, err := p.getIdentity(ctx, cli)
	if err != nil {
		return err
	}

	securitygroup, err := p.getSecurityGroup(ctx, cli)
	if err != nil {
		return err
	}

	if err := provider.DeleteSecurityGroupRule(ctx, identity, securitygroup, p.securitygrouprule); err != nil {
		return err
	}

	return nil
}
