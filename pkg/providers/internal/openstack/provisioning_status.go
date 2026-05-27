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

	switch node.ProvisionState {
	case "available", "manageable", "enroll", "cleaning", "clean wait", "verifying", "inspecting", "inspect wait", "adopting",
		"clean failed", "clean hold", "inspect failed", "adopt failed":
		return coreapi.ResourceProvisioningStatusQueued
	case "deploying", "wait call-back", "deploy hold", "deploy failed", "active", "error":
		return coreapi.ResourceProvisioningStatusProvisioning
	default:
		return coreapi.ResourceProvisioningStatusQueued
	}
}

func deriveProviderProvisioningStatusInput(server servers.Server, baremetal bool) (*coreapi.ResourceProvisioningStatus, bool) {
	if server.Status == "BUILD" {
		return nil, baremetal
	}

	return nil, false
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

	status, callIronic := deriveProviderProvisioningStatusInput(*openstackServer, baremetal)
	if status != nil {
		server.Status.ProviderProvisioningStatus = status
		return
	}

	if !callIronic {
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
