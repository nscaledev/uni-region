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

package server

import (
	"context"
	"fmt"
	"time"

	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"

	"github.com/unikorn-cloud/core/pkg/manager/options"
	"github.com/unikorn-cloud/core/pkg/util/retry"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/managers/temp"

	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

//nolint:cyclop
func (*Factory) Upgrade(ctx context.Context, cli client.Client, options *options.Options) error {
	log := log.FromContext(ctx)

	log.Info("running upgrade action")

	// Start caches...
	time.Sleep(5 * time.Second)

	_ = retry.Forever().Do(func() error {
		resources := &unikornv1.OpenstackSecurityGroupList{}

		if err := cli.List(ctx, resources); err != nil {
			log.Error(err, "failed to poll security groups")
			return err
		}

		if len(resources.Items) > 0 {
			log.Info("awaiting security group upgrade", "left", len(resources.Items))

			//nolint:err113
			return fmt.Errorf("wait error")
		}

		return nil
	})

	resources := &unikornv1.OpenstackServerList{}

	if err := cli.List(ctx, resources); err != nil {
		return err
	}

	for i := range resources.Items {
		resource := &resources.Items[i]

		log.Info("upgrading server", "id", resource.Name)

		networking, err := temp.GetNetworkClient(ctx, cli, resource)
		if err != nil {
			return err
		}

		serverName := "server-" + resource.Name

		for _, id := range resource.Spec.PortIDs {
			log.Info("upgrading openstack port", "id", id)

			t, err := ports.Get(ctx, networking, id).Extract()
			if err != nil {
				return err
			}

			if t.Name == serverName {
				log.Info("already has correct name")
				continue
			}

			log.Info("renaming resource")

			opts := &ports.UpdateOpts{
				Name: ptr.To(serverName),
			}

			if _, err := ports.Update(ctx, networking, id, opts).Extract(); err != nil {
				return err
			}
		}

		if err := cli.Delete(ctx, resource); err != nil {
			return err
		}
	}

	return nil
}
