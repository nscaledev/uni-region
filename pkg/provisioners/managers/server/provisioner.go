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

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/region"

	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
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

func (p *Provisioner) securityGroupListOptions() *client.ListOptions {
	selector := map[string]string{
		constants.IdentityLabel: p.server.Labels[constants.IdentityLabel],
	}

	return &client.ListOptions{
		Namespace:     p.server.Namespace,
		LabelSelector: labels.SelectorFromSet(selector),
	}
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	// Add references to any resources we consume.
	reference, err := manager.GenerateResourceReference(cli, p.server)
	if err != nil {
		return err
	}

	if err := manager.AddResourceReferences(ctx, cli, &unikornv1.SecurityGroupList{}, p.securityGroupListOptions(), reference, p.securityGroupIDs()); err != nil {
		return fmt.Errorf("%w: failed to add security group references", err)
	}

	provider, err := region.NewClient(cli, p.server.Namespace).Provider(ctx, p.server.Labels[constants.RegionLabel])
	if err != nil {
		return err
	}

	// Inhibit provisioning until consumed resources are ready.
	identity, err := p.getIdentity(ctx, cli)
	if err != nil {
		return err
	}

	if err := manager.ResourceReady(ctx, identity); err != nil {
		return err
	}

	// Do the provisioning.
	if err := provider.CreateServer(ctx, identity, p.server); err != nil {
		return err
	}

	// Release any references to any resources we no longer consume.
	if err := manager.RemoveResourceReferences(ctx, cli, &unikornv1.SecurityGroupList{}, p.securityGroupListOptions(), reference, p.securityGroupIDs()); err != nil {
		return fmt.Errorf("%w: failed to remove security group references", err)
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
	reference, err := manager.GenerateResourceReference(cli, p.server)
	if err != nil {
		return err
	}

	if err := manager.ClearResourceReferences(ctx, cli, &unikornv1.SecurityGroupList{}, p.securityGroupListOptions(), reference); err != nil {
		return fmt.Errorf("%w: failed to clear security group references", err)
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
