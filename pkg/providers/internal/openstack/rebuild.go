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
	"fmt"
	"net/http"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	regionids "github.com/unikorn-cloud/region/pkg/ids"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// The park messages. Provisioning reasons are a closed, generic vocabulary that
// the API projects through a switch, so a parked attempt reports the generic
// Errored reason and carries its specificity here, in the message.
const (
	rebuildParkMessageErrored    = "the server entered an error state after a rebuild was issued; select another image or replace the server"
	rebuildParkMessageNotApplied = "the provider reports the new image but the machine has not applied it; select another image or replace the server"
	rebuildParkMessageSuperseded = "the server's image moved outside this rebuild, which can no longer converge; select another image or replace the server"
)

// rebuildProviderImage reads the provider's current image ref, normalised
// through the ID parser so it compares equal to the spec and marker refs. An
// absent or unparseable ref returns the empty string, which the decision
// procedure reads as "cannot decide" — never as a difference to act on.
func rebuildProviderImage(openstackServer *servers.Server) string {
	value, ok := openstackServer.Image["id"].(string)
	if !ok {
		return ""
	}

	imageID, err := regionids.ParseImageID(value)
	if err != nil {
		return ""
	}

	return imageID.String()
}

// rebuildProviderOp classifies a fresh Nova read for the decision procedure.
// task_state is the busy signal for the rebuild window: non-empty throughout it,
// empty at rest.
//
// Idle is an allow-list, not a fallback. It means "a rebuild is admissible right
// now", and Nova admits one from only a few vm_states: VERIFY_RESIZE, PAUSED,
// SUSPENDED and SHELVED_OFFLOADED are all stable and taskless but reject a
// rebuild with a 409, so reading them as idle would make the pass POST into that
// rejection on every pass, forever, for a request that cannot succeed until an
// external actor confirms the resize or wakes the server. They classify as busy
// — "not actionable right now" — so the pass waits and requeues instead. REBUILD
// and BUILD fall outside the allow-list on the same grounds.
//
// ERROR is tested first. Nova's error vm_state is sticky and carries the
// operator-actionable failure, so it must reach the park rather than be held
// off it indefinitely by a task_state that is itself stuck.
func rebuildProviderOp(openstackServer *servers.Server) providerOp {
	if openstackServer.Status == novaStatusError {
		return providerErrored
	}

	if openstackServer.TaskState != "" {
		return providerBusy
	}

	switch openstackServer.Status {
	case novaStatusActive, novaStatusShutoff:
		return providerIdle
	default:
		return providerBusy
	}
}

// rebuildParkMessage names the fresh evidence that justifies parking, which is
// what an operator sees on the Available condition. One branch per park row of
// rebuildDecision, so a marker is always present.
func rebuildParkMessage(in rebuildInputs) string {
	if in.ProviderOp == providerErrored {
		return rebuildParkMessageErrored
	}

	if in.ProviderImage == in.Marker.TargetImageID.String() {
		return rebuildParkMessageNotApplied
	}

	return rebuildParkMessageSuperseded
}

// callServerRebuild issues the Nova rebuild for an attempt whose acceptance is
// already durable. A 409 is pre-acceptance — another operation holds the server
// — so it retries quietly rather than reporting a failure to the user.
func callServerRebuild(ctx context.Context, client ServerInterface, server *unikornv1.Server, openstackServer *servers.Server) (*servers.Server, error) {
	rebuilt, err := client.RebuildServer(ctx, openstackServer.ID, server.Status.Rebuild.TargetImageID)
	if err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusConflict) {
			log.FromContext(ctx).Info("server rebuild refused pending another operation",
				"server", server.Name, "novaServerID", openstackServer.ID)

			return openstackServer, fmt.Errorf("%w: server rebuild refused pending another operation", provisioners.ErrYield)
		}

		return nil, err
	}

	if rebuilt == nil {
		return openstackServer, nil
	}

	return rebuilt, nil
}

// reconcileServerRebuild converges the server onto its desired image, taking
// exactly one protocol action per pass from rebuildDecision. applied is the
// deploy layer's answer to "what is actually running", nil where no second
// channel applies.
//
// The pass that commits to a rebuild records the acceptance and returns without
// calling the provider; a later pass, having read that record back durable,
// makes the call. Collapsing the two lets a pass interrupted between the call
// and the status write lose the record and destroy a second root disk for one
// user request.
//
//nolint:cyclop // one arm per protocol action, plus the outstanding-attempt requeue.
func reconcileServerRebuild(ctx context.Context, client ServerInterface, server *unikornv1.Server, openstackServer *servers.Server, applied *string) (*servers.Server, error) {
	log := log.FromContext(ctx)

	// Nothing to converge toward, so no attempt can be outstanding.
	if server.Spec.Image == nil {
		server.Status.Rebuild = nil

		return openstackServer, nil
	}

	in := rebuildInputs{
		DesiredImageID:   server.Spec.Image.ID.String(),
		Marker:           server.Status.Rebuild,
		ProviderImage:    rebuildProviderImage(openstackServer),
		ProviderOp:       rebuildProviderOp(openstackServer),
		ProviderLaunched: !openstackServer.LaunchedAt.IsZero(),
		AppliedImage:     applied,
	}

	switch rebuildDecision(in) {
	case rebuildArm:
		server.Status.Rebuild = &unikornv1.ServerRebuildStatus{
			TargetImageID:  server.Spec.Image.ID,
			PreArmImageRef: in.ProviderImage,
		}

		log.Info("arming a server rebuild", "server", server.Name, "novaServerID", openstackServer.ID)
	case rebuildCommit:
		server.Status.Rebuild.Accepted = true

		log.Info("recording the server rebuild acceptance", "server", server.Name, "novaServerID", openstackServer.ID)
	case rebuildCall:
		rebuilt, err := callServerRebuild(ctx, client, server, openstackServer)
		if err != nil {
			return rebuilt, err
		}

		openstackServer = rebuilt

		log.Info("issued the server rebuild", "server", server.Name, "novaServerID", openstackServer.ID)
	case rebuildClear:
		server.Status.Rebuild = nil

		log.Info("clearing the settled server rebuild", "server", server.Name, "novaServerID", openstackServer.ID)

		// Retiring the marker takes away the trailing requeue, so it is reissued
		// here. A spec edit made while the settled attempt was in flight may have
		// coalesced into the very requeue that ran this pass, and the status write
		// below is generation-filtered: without this the new target would never be
		// armed, leaving the machine on the old image with no pending work. The
		// cost is one extra pass per completed rebuild.
		return openstackServer, fmt.Errorf("%w: server rebuild settled", provisioners.ErrYield)
	case rebuildPark:
		server.Status.Rebuild.Parked = true

		log.Info("parking the server rebuild", "server", server.Name, "novaServerID", openstackServer.ID)
	case rebuildUnpark:
		server.Status.Rebuild = nil

		log.Info("releasing the parked server rebuild", "server", server.Name, "novaServerID", openstackServer.ID)

		// The retarget leaves work to do and the spec edit that woke us is spent,
		// so the arming pass has to be requeued from here.
		return openstackServer, fmt.Errorf("%w: server rebuild retargeted", provisioners.ErrYield)
	case rebuildNoop:
	}

	marker := server.Status.Rebuild
	if marker == nil {
		return openstackServer, nil
	}

	// Reported on every parked pass, not just the parking one, and derived fresh
	// each time rather than stamped on the marker: the evidence is durable, and a
	// one-shot report would decay to provisioned on the next pass.
	if marker.Parked {
		return openstackServer, provisioners.UserActionRequired(unikornv1core.ConditionReasonErrored, rebuildParkMessage(in))
	}

	// The Server watch is generation-filtered, so the status write that records a
	// commitment enqueues nothing: an outstanding attempt has to carry its own
	// liveness. A parked one must not — its only exit is a spec edit, which does
	// change the generation.
	return openstackServer, fmt.Errorf("%w: server rebuild outstanding", provisioners.ErrYield)
}
