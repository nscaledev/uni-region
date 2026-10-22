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
	"time"

	"github.com/gophercloud/gophercloud/v2/openstack/baremetal/v1/nodes"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

// serverFaultReadTimeout bounds the per-ID fault read taken on the error edge.
const serverFaultReadTimeout = 10 * time.Second

// serverAlreadyErrored reports whether the server's lifecycle condition already
// says Errored, so the fault detail is logged once per edge and not per pass.
func serverAlreadyErrored(server *unikornv1.Server) bool {
	active, err := unikornv1.GetActiveCondition(server)
	if err != nil {
		return false
	}

	return active.Reason == unikornv1.ActiveConditionReasonError
}

// projectServerState projects one fresh provider read onto the server's status:
// health, MAC, and live lifecycle state.  Takes the read so both callers project
// the same observation; see the README's Server Observation section.
func (p *Provider) projectServerState(
	ctx context.Context,
	identity *unikornv1.Identity,
	server *unikornv1.Server,
	openstackServer *servers.Server,
	serverClient ServerObservationInterface,
	baremetalForPhase func(context.Context, *unikornv1.Identity) (BaremetalInterface, error),
) {
	// Read before the projection overwrites it, so the error edge is decided
	// from what this pass found rather than from a stored marker.
	entersError := openstackServer.Status == novaStatusError && !serverAlreadyErrored(server)

	setServerHealthStatus(server, openstackServer)
	setServerMACAddress(ctx, server, openstackServer)

	if entersError {
		// Bounded so a hung Nova read cannot stall the pass.
		faultCtx, cancel := context.WithTimeout(ctx, serverFaultReadTimeout)
		defer cancel()

		logServerFault(faultCtx, serverClient, server, openstackServer)
	}

	region, _ := p.openstack.regionSnapshot()
	baremetal := isBaremetalFlavor(region, server.Spec.FlavorID.String())

	var ironicNode *nodes.Node

	if shouldCallIronicForPhase(*openstackServer, baremetal) {
		ironicNode = p.lookupIronicNodeForPhase(ctx, identity, server, openstackServer, baremetalForPhase)
	}

	setServerActive(ctx, server, openstackServer, ironicNode)
}
