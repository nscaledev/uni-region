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

package securitygroup

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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	ErrResouceDependency = errors.New("resource dependency error")
)

// Provisioner encapsulates control plane provisioning.
type Provisioner struct {
	provisioners.Metadata

	// securitygroup is the security group we're provisioning.
	securitygroup *unikornv1.SecurityGroup
}

// New returns a new initialized provisioner object.
func New(_ coremanager.ControllerOptions) provisioners.ManagerProvisioner {
	return &Provisioner{
		securitygroup: &unikornv1.SecurityGroup{},
	}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.securitygroup
}

func (p *Provisioner) getIdentity(ctx context.Context, cli client.Client) (*unikornv1.Identity, error) {
	identity := &unikornv1.Identity{}

	if err := cli.Get(ctx, client.ObjectKey{Namespace: p.securitygroup.Namespace, Name: p.securitygroup.Labels[constants.IdentityLabel]}, identity); err != nil {
		return nil, err
	}

	return identity, nil
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	log := log.FromContext(ctx)

	cli, err := coreclient.ProvisionerClientFromContext(ctx)
	if err != nil {
		return err
	}

	provider, err := region.NewClient(cli, p.securitygroup.Namespace).Provider(ctx, p.securitygroup.Labels[constants.RegionLabel])
	if err != nil {
		return err
	}

	identity, err := p.getIdentity(ctx, cli)
	if err != nil {
		return err
	}

	// Inhibit provisioning until the identity is ready, as we may need the identity information
	// to create the security group e.g. the project ID in the case of OpenStack.
	status, err := identity.StatusConditionRead(unikornv1core.ConditionAvailable)
	if err != nil {
		log.Info("waiting for identity status update")

		return provisioners.ErrYield
	}

	switch status.Reason {
	case unikornv1core.ConditionReasonProvisioned:
		break
	case unikornv1core.ConditionReasonProvisioning:
		return provisioners.ErrYield
	default:
		return fmt.Errorf("%w: identity in unexpected condition %v", ErrResouceDependency, status.Reason)
	}

	if err := provider.CreateSecurityGroup(ctx, identity, p.securitygroup); err != nil {
		return err
	}

	return nil
}

// Deprovision implements the Provision interface.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	// Wait for any owned resources to be cleaned up first.
	if controllerutil.ContainsFinalizer(p.securitygroup, metav1.FinalizerDeleteDependents) {
		return provisioners.ErrYield
	}

	cli, err := coreclient.ProvisionerClientFromContext(ctx)
	if err != nil {
		return err
	}

	identity, err := p.getIdentity(ctx, cli)
	if err != nil {
		return err
	}

	provider, err := region.NewClient(cli, p.securitygroup.Namespace).Provider(ctx, p.securitygroup.Labels[constants.RegionLabel])
	if err != nil {
		return err
	}

	if err := provider.DeleteSecurityGroup(ctx, identity, p.securitygroup); err != nil {
		return err
	}

	return nil
}
