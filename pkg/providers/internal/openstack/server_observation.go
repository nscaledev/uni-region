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

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/types"
)

// projectServerState projects an already-read provider server onto the resource.
// Every caller reaches the same derivation, whether it read one server or the
// whole project.
func (p *Provider) projectServerState(
	ctx context.Context,
	identity *unikornv1.Identity,
	server *unikornv1.Server,
	openstackServer *servers.Server,
	serverClient ServerObservationInterface,
	baremetalForPhase func(context.Context, *unikornv1.Identity) (BaremetalInterface, error),
) {
	setServerHealthStatus(server, openstackServer)
	setServerMACAddress(ctx, server, openstackServer)

	if enteredError := setServerObservedStatus(server, openstackServer); enteredError {
		// The enrichment is best-effort and bounded so a hung Nova read cannot
		// stall the whole poll cycle.
		faultCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
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

// serverObserver holds one unfiltered read of an identity's project, indexed by
// name. Observation only: nothing here may authorise an action against the
// provider, which is why the create path keeps its own per-server GetServer.
type serverObserver struct {
	provider *Provider
	identity *unikornv1.Identity
	client   ServerObservationInterface
	servers  map[string]*servers.Server
}

// Observe projects the held provider state onto server.
func (o *serverObserver) Observe(ctx context.Context, server *unikornv1.Server) error {
	openstackServer, ok := o.servers[server.Labels[coreconstants.NameLabel]]
	if !ok {
		// Identical to the absent path in updateServerStateWithClients: stamp the
		// observation so a caller that persists it fires the observed wake, then
		// surface the absence.
		recordAbsentServerObservation(server)

		return coreerrors.ErrResourceNotFound
	}

	o.provider.projectServerState(ctx, o.identity, server, openstackServer, o.client, o.provider.baremetalForPhase)

	return nil
}

// newServerObserver indexes one project read by name.
func (p *Provider) newServerObserver(identity *unikornv1.Identity, client ServerObservationInterface, list []servers.Server) *serverObserver {
	// First exact match wins, as GetServer's post-filter does today. Names are
	// unique within a project in practice; this only fixes which row is chosen
	// if they are not.
	index := make(map[string]*servers.Server, len(list))

	for i := range list {
		if _, ok := index[list[i].Name]; !ok {
			index[list[i].Name] = &list[i]
		}
	}

	return &serverObserver{
		provider: p,
		identity: identity,
		client:   client,
		servers:  index,
	}
}

// ObserveServers takes one provider read of the identity's whole project.
func (p *Provider) ObserveServers(ctx context.Context, identity *unikornv1.Identity) (types.ServerObserver, error) {
	compute, err := p.computeFromServicePrincipal(ctx, identity)
	if err != nil {
		return nil, err
	}

	list, err := compute.ListServers(ctx)
	if err != nil {
		return nil, err
	}

	return p.newServerObserver(identity, compute, list), nil
}
