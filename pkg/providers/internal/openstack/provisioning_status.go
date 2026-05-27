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
	"github.com/gophercloud/gophercloud/v2/openstack/baremetal/v1/nodes"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
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
	switch server.Status {
	case "ACTIVE":
		status := coreapi.ResourceProvisioningStatusProvisioned
		return &status, false
	case "ERROR":
		status := coreapi.ResourceProvisioningStatusError
		return &status, false
	case "BUILD":
		return nil, baremetal
	default:
		return nil, false
	}
}
