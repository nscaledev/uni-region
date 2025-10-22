/*
Copyright 2025 the Unikorn Authors.

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

package network

import (
	"context"
	"time"

	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"

	"github.com/unikorn-cloud/core/pkg/manager/options"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/managers/temp"

	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

//nolint:cyclop,gocognit
func (*Factory) Upgrade(ctx context.Context, cli client.Client, options *options.Options) error {
	log := log.FromContext(ctx)

	log.Info("running upgrade action")

	// Start caches...
	time.Sleep(5 * time.Second)

	resources := &unikornv1.OpenstackNetworkList{}

	if err := cli.List(ctx, resources); err != nil {
		return err
	}

	for i := range resources.Items {
		resource := &resources.Items[i]

		log.Info("upgrading network", "id", resource.Name)

		networking, err := temp.GetNetworkClient(ctx, cli, resource)
		if err != nil {
			return err
		}

		networkName := "network-" + resource.Name

		if resource.Spec.NetworkID != nil {
			id := *resource.Spec.NetworkID

			log.Info("upgrading openstack network", "id", id)

			t, err := networks.Get(ctx, networking, id).Extract()
			if err != nil {
				return err
			}

			if t.Name == networkName {
				log.Info("already has correct name")
				continue
			}

			log.Info("renaming resource")

			opts := &networks.UpdateOpts{
				Name: ptr.To(networkName),
			}

			if _, err := networks.Update(ctx, networking, id, opts).Extract(); err != nil {
				return err
			}
		}

		if resource.Spec.SubnetID != nil {
			id := *resource.Spec.SubnetID

			log.Info("upgrading openstack subnet", "id", id)

			t, err := subnets.Get(ctx, networking, id).Extract()
			if err != nil {
				return err
			}

			if t.Name == networkName {
				log.Info("already has correct name")
				continue
			}

			log.Info("renaming resource")

			opts := &subnets.UpdateOpts{
				Name: ptr.To(networkName),
			}

			if _, err := subnets.Update(ctx, networking, id, opts).Extract(); err != nil {
				return err
			}
		}

		if resource.Spec.RouterID != nil {
			id := *resource.Spec.RouterID

			log.Info("upgrading openstack router", "id", id)

			t, err := routers.Get(ctx, networking, id).Extract()
			if err != nil {
				return err
			}

			if t.Name == networkName {
				log.Info("already has correct name")
				continue
			}

			log.Info("renaming resource")

			opts := &routers.UpdateOpts{
				Name: networkName,
			}

			if _, err := routers.Update(ctx, networking, id, opts).Extract(); err != nil {
				return err
			}
		}

		if err := cli.Delete(ctx, resource); err != nil {
			return err
		}
	}

	return nil
}
