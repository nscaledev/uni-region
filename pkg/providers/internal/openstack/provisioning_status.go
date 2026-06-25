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

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

// baremetalBuildPhase maps an Ironic node's provision_state onto the Server CR's
// lifecycle Phase. Used only while Nova reports BUILD for a baremetal flavor;
// other cases are handled by the Nova-side branches of setServerPhase.
//
// Buckets:
//   - pre-deploy (node not yet picked up / cleaning / inspecting / adopting) → Queued
//   - deploy (Ironic actively writing the node, including failure states) → Building
//
// Failures (CleanFail / InspectFail / AdoptFail / DeployFail) and the sticky
// post-deploy Error state are reported as Building rather than a distinct
// error phase. Error is acknowledged to be sticky — a node that hits Error
// without operator intervention will keep reporting Building until it is
// deleted — but the alternative (a separate phase, or returning to Queued/
// Pending) duplicates one concept across two axes. The failure signal lives
// on the Healthy condition (written by setServerHealthStatus from Nova
// state), which is the right axis for "is this node broken"; Phase is the
// right axis for "where is this node in its build pipeline", and a node in
// Error is still operationally in that pipeline until it is torn down. If we
// ever introduce an explicit terminal-failure phase, Error is the
// motivating case to revisit.
func baremetalBuildPhase(node *nodes.Node) unikornv1.InstanceLifecyclePhase {
	if node == nil {
		return unikornv1.InstanceLifecyclePhaseQueued
	}

	//nolint:exhaustive
	switch nodes.ProvisionState(node.ProvisionState) {
	case nodes.Available, nodes.Manageable, nodes.Enroll, nodes.Cleaning, nodes.CleanWait, nodes.Verifying, nodes.Inspecting,
		nodes.InspectWait, nodes.Adopting, nodes.CleanHold:
		return unikornv1.InstanceLifecyclePhaseQueued
	case nodes.Deploying, nodes.DeployWait, nodes.DeployHold, nodes.Active,
		nodes.CleanFail, nodes.InspectFail, nodes.AdoptFail, nodes.DeployFail, nodes.Error:
		return unikornv1.InstanceLifecyclePhaseBuilding
	default:
		// Any unrecognised state is conservatively reported as Queued rather
		// than claiming deploy progress that may not be real.
		return unikornv1.InstanceLifecyclePhaseQueued
	}
}

// shouldCallIronicForPhase decides whether the Phase derivation needs an Ironic
// lookup for this server. Only baremetal servers in Nova BUILD use Ironic;
// everything else uses Nova state alone.
func shouldCallIronicForPhase(server servers.Server, baremetal bool) bool {
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
