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

package server

import (
	"context"
	"fmt"
	"slices"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/region"

	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Provisioner encapsulates control plane provisioning.
type Provisioner struct {
	provisioners.Metadata

	// server is the server we're provisioning.
	server *unikornv1.Server
}

// New returns a new initialized provisioner object.
func New(_ manager.ControllerOptions) provisioners.ManagerProvisioner {
	return &Provisioner{
		server: &unikornv1.Server{},
	}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.server
}

func (p *Provisioner) securityGroupIDs() []string {
	securityGroupIDs := make([]string, len(p.server.Spec.SecurityGroups))

	// TODO: ensure the API rejects repeats.
	for i := range p.server.Spec.SecurityGroups {
		securityGroupIDs[i] = p.server.Spec.SecurityGroups[i].ID
	}

	return securityGroupIDs
}

func (p *Provisioner) securityGroupSelector() labels.Selector {
	selector := map[string]string{
		constants.IdentityLabel: p.server.Labels[constants.IdentityLabel],
	}

	return labels.SelectorFromSet(selector)
}

// listSecurityGroupsForIdentity lists all security groups that may be used by the server.
func (p *Provisioner) listSecurityGroupsForIdentity(ctx context.Context, cli client.Client) (map[string]*unikornv1.SecurityGroup, error) {
	securityGroups := &unikornv1.SecurityGroupList{}

	options := &client.ListOptions{
		Namespace:     p.server.Namespace,
		LabelSelector: p.securityGroupSelector(),
	}

	if err := cli.List(ctx, securityGroups, options); err != nil {
		return nil, err
	}

	out := map[string]*unikornv1.SecurityGroup{}

	for i := range securityGroups.Items {
		securityGroup := &securityGroups.Items[i]

		out[securityGroup.Name] = securityGroup
	}

	return out, nil
}

// addSecurityGroupReferences adds references to security groups that are in use
// by the server.
func (p *Provisioner) addSecurityGroupReferences(ctx context.Context, cli client.Client, securityGroups map[string]*unikornv1.SecurityGroup, reference string) error {
	securityGroupIDs := p.securityGroupIDs()

	// Find all security groups that are linked to the cluster and ensure they have an reference.
	for _, id := range securityGroupIDs {
		securityGroup, ok := securityGroups[id]
		if !ok {
			// This should not happen and should be caught at the API layer.
			return fmt.Errorf("%w: server references unknown security group %s", errors.ErrConsistency, id)
		}

		if updated := controllerutil.AddFinalizer(securityGroup, reference); !updated {
			continue
		}

		if err := cli.Update(ctx, securityGroup); err != nil {
			return err
		}
	}

	return nil
}

// removeSecurityGroupReferences removes references to security groups that aren't
// in use by the server.
func (p *Provisioner) removeSecurityGroupReferences(ctx context.Context, cli client.Client, securityGroups map[string]*unikornv1.SecurityGroup, reference string) error {
	securityGroupIDs := p.securityGroupIDs()

	// Find any security groups we no longer reference and remove any references.
	for id, securityGroup := range securityGroups {
		if slices.Contains(securityGroupIDs, id) {
			continue
		}

		if updated := controllerutil.RemoveFinalizer(securityGroup, reference); !updated {
			continue
		}

		if err := cli.Update(ctx, securityGroup); err != nil {
			return err
		}
	}

	return nil
}

func (p *Provisioner) removeAllSecurityGroupReferences(ctx context.Context, cli client.Client) error {
	reference, err := manager.GenerateResourceReference(cli, p.server)
	if err != nil {
		return err
	}

	options := &client.ListOptions{
		Namespace:     p.server.Namespace,
		LabelSelector: p.securityGroupSelector(),
	}

	return manager.ClearResourceReferences(ctx, cli, &unikornv1.SecurityGroupList{}, options, reference)
}

// Provision implements the Provision interface.
//
//nolint:cyclop
func (p *Provisioner) Provision(ctx context.Context) error {
	log := log.FromContext(ctx)

	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	reference, err := manager.GenerateResourceReference(cli, p.server)
	if err != nil {
		return err
	}

	securityGroups, err := p.listSecurityGroupsForIdentity(ctx, cli)
	if err != nil {
		return err
	}

	// Ensure any references to security groups are added before we create the server.
	if err := p.addSecurityGroupReferences(ctx, cli, securityGroups, reference); err != nil {
		return err
	}

	provider, err := region.NewClient(cli, p.server.Namespace).Provider(ctx, p.server.Labels[constants.RegionLabel])
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

	//nolint:exhaustive
	switch status.Reason {
	case unikornv1core.ConditionReasonProvisioned:
		break
	case unikornv1core.ConditionReasonProvisioning:
		return provisioners.ErrYield
	default:
		return fmt.Errorf("%w: identity in unexpected condition %v", errors.ErrConsistency, status.Reason)
	}

	if err := provider.CreateServer(ctx, identity, p.server); err != nil {
		return err
	}

	// Release any references to security groups that are no longer attached to the
	// server.
	if err := p.removeSecurityGroupReferences(ctx, cli, securityGroups, reference); err != nil {
		return err
	}

	return nil
}

// Deprovision implements the Provision interface.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	provider, err := region.NewClient(cli, p.server.Namespace).Provider(ctx, p.server.Labels[constants.RegionLabel])
	if err != nil {
		return err
	}

	identity, err := p.getIdentity(ctx, cli)
	if err != nil {
		return err
	}

	if err := provider.DeleteServer(ctx, identity, p.server); err != nil {
		return err
	}

	// Once we know the server is gone, allow deletion of the security group.
	if err := p.removeAllSecurityGroupReferences(ctx, cli); err != nil {
		return err
	}

	return nil
}

func (p *Provisioner) getIdentity(ctx context.Context, cli client.Client) (*unikornv1.Identity, error) {
	identity := &unikornv1.Identity{}

	if err := cli.Get(ctx, client.ObjectKey{Namespace: p.server.Namespace, Name: p.server.Labels[constants.IdentityLabel]}, identity); err != nil {
		return nil, err
	}

	return identity, nil
}
