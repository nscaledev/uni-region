/*
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

package openstack

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/gophercloud/gophercloud/v2/openstack/baremetal/v1/nodes"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

func baremetalBuildProvisioningStatus(node *nodes.Node) coreapi.ResourceProvisioningStatus {
	if node == nil {
		return coreapi.ResourceProvisioningStatusQueued
	}

	// Any state not listed deliberately falls through to the conservative
	// queued default rather than claiming deploy progress that isn't real.
	//nolint:exhaustive
	switch nodes.ProvisionState(node.ProvisionState) {
	case nodes.Available, nodes.Manageable, nodes.Enroll, nodes.Cleaning, nodes.CleanWait, nodes.Verifying, nodes.Inspecting,
		nodes.InspectWait, nodes.Adopting, nodes.CleanFail, nodes.CleanHold, nodes.InspectFail, nodes.AdoptFail:
		return coreapi.ResourceProvisioningStatusQueued
	case nodes.Deploying, nodes.DeployWait, nodes.DeployHold, nodes.Active:
		return coreapi.ResourceProvisioningStatusProvisioning
	// A failed deploy is reported as an error rather than silent progress; if Nova
	// reschedules onto another node the instance_uuid lookup self-corrects on the
	// next poll, and if Nova gives up the instance-level ERROR override takes over.
	case nodes.DeployFail, nodes.Error:
		return coreapi.ResourceProvisioningStatusError
	default:
		return coreapi.ResourceProvisioningStatusQueued
	}
}

func shouldCallIronicForProvisioningStatus(server servers.Server, baremetal bool) bool {
	return server.Status == "BUILD" && baremetal
}

func isBaremetalFlavor(region *unikornv1.Region, flavorID string) bool {
	if region == nil || region.Spec.Openstack == nil || region.Spec.Openstack.Compute == nil || region.Spec.Openstack.Compute.Flavors == nil {
		return false
	}

	for i := range region.Spec.Openstack.Compute.Flavors.Metadata {
		metadata := &region.Spec.Openstack.Compute.Flavors.Metadata[i]
		if metadata.ID == flavorID {
			return metadata.Baremetal
		}
	}

	return false
}

type ironicNodeLookup func(ctx context.Context, instanceUUID string) (*nodes.Node, error)

func updateServerProviderProvisioningStatus(
	ctx context.Context,
	log logr.Logger,
	server *unikornv1.Server,
	openstackServer *servers.Server,
	baremetal bool,
	lookup ironicNodeLookup,
) {
	server.Status.ProviderProvisioningStatus = nil

	// A Nova ERROR instance never reached its Available condition's happy state,
	// but condition-derived status still reads "provisioned" once the controller's
	// reconcile has finished. Override with error so the API tells the truth.
	if openstackServer.Status == "ERROR" {
		errorStatus := coreapi.ResourceProvisioningStatusError
		server.Status.ProviderProvisioningStatus = &errorStatus

		return
	}

	if !shouldCallIronicForProvisioningStatus(*openstackServer, baremetal) {
		return
	}

	if lookup == nil {
		log.Info("skipping baremetal provisioning status lookup because ironic client is unavailable", "instance_uuid", openstackServer.ID)
		return
	}

	node, err := lookup(ctx, openstackServer.ID)
	if err != nil {
		log.Error(err, "failed to get ironic node for server", "instance_uuid", openstackServer.ID)
		return
	}

	derivedStatus := baremetalBuildProvisioningStatus(node)
	server.Status.ProviderProvisioningStatus = &derivedStatus
}
