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

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

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

	identityRequirement, err := labels.NewRequirement(constants.IdentityLabel, selection.Equals, []string{p.identity.Name})
	if err != nil {
		return err
	}

	selector := labels.NewSelector()
	selector = selector.Add(*identityRequirement)

	// Block identity deletion until all owned resources are deleted, we cannot guarantee
	// the underlying cloud implementation will not just orphan them and leak resources.
	if err := p.triggerServerDeletion(ctx, cli, selector); err != nil {
		return err
	}

	if err := p.triggerSecurityGroupDeletion(ctx, cli, selector); err != nil {
		return err
	}

	if err := p.triggerNetworkDeletion(ctx, cli, selector); err != nil {
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

func (p *Provisioner) triggerNetworkDeletion(ctx context.Context, cli client.Client, selector labels.Selector) error {
	log := log.FromContext(ctx)

	var networks unikornv1.NetworkList

	if err := cli.List(ctx, &networks, &client.ListOptions{Namespace: p.identity.Namespace, LabelSelector: selector}); err != nil {
		return err
	}

	if len(networks.Items) != 0 {
		for i := range networks.Items {
			resource := &networks.Items[i]

			if resource.DeletionTimestamp != nil {
				log.Info("awaiting physical network deletion", "physical network", resource.Name)
				continue
			}

			log.Info("triggering network deletion", "physical network", resource.Name)

			if err := cli.Delete(ctx, resource); err != nil {
				return err
			}
		}

		return provisioners.ErrYield
	}

	return nil
}

func (p *Provisioner) triggerSecurityGroupDeletion(ctx context.Context, cli client.Client, selector labels.Selector) error {
	log := log.FromContext(ctx)

	var securityGroups unikornv1.SecurityGroupList

	if err := cli.List(ctx, &securityGroups, &client.ListOptions{Namespace: p.identity.Namespace, LabelSelector: selector}); err != nil {
		return err
	}

	if len(securityGroups.Items) != 0 {
		for i := range securityGroups.Items {
			resource := &securityGroups.Items[i]

			if resource.DeletionTimestamp != nil {
				log.Info("awaiting security group deletion", "security group", resource.Name)
				continue
			}

			log.Info("triggering security group deletion", "security group", resource.Name)

			if err := cli.Delete(ctx, resource); err != nil {
				return err
			}
		}

		return provisioners.ErrYield
	}

	return nil
}

func (p *Provisioner) triggerServerDeletion(ctx context.Context, cli client.Client, selector labels.Selector) error {
	log := log.FromContext(ctx)

	var servers unikornv1.ServerList

	if err := cli.List(ctx, &servers, &client.ListOptions{Namespace: p.identity.Namespace, LabelSelector: selector}); err != nil {
		return err
	}

	if len(servers.Items) != 0 {
		for i := range servers.Items {
			resource := &servers.Items[i]

			if resource.DeletionTimestamp != nil {
				log.Info("awaiting server deletion", "server", resource.Name)
				continue
			}

			log.Info("triggering server deletion", "server", resource.Name)

			if err := cli.Delete(ctx, resource); err != nil {
				return err
			}
		}

		return provisioners.ErrYield
	}

	return nil
}
