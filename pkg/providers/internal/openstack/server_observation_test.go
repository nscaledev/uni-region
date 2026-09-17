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

//nolint:testpackage
package openstack

import (
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/require"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// observerFlavor is the flavor every fixture here uses.
const observerFlavor = "11111111-1111-4111-a111-111111111111"

// observerProvider is a Provider with just enough region configuration for the
// projection: a non-baremetal flavor, so nothing reaches for Ironic.
func observerProvider() *Provider {
	return &Provider{
		openstack: &openStackClients{
			_region: &unikornv1.Region{
				Spec: unikornv1.RegionSpec{
					Openstack: &unikornv1.RegionOpenstackSpec{
						Compute: &unikornv1.RegionOpenstackComputeSpec{
							Flavors: &unikornv1.OpenstackFlavorsSpec{
								Metadata: []unikornv1.FlavorMetadata{{ID: observerFlavor, Baremetal: false}},
							},
						},
					},
				},
			},
		},
	}
}

func observedServer(name string) *unikornv1.Server {
	return &unikornv1.Server{
		Spec: unikornv1.ServerSpec{
			FlavorID: idstest.MustParseFlavorID(observerFlavor),
		},
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{coreconstants.NameLabel: name}},
	}
}

// TestServerObserverResolvesByName pins that each server is projected from its
// own row of the batch, not from whichever row happened to be first.
func TestServerObserverResolvesByName(t *testing.T) {
	t.Parallel()

	provider := observerProvider()

	observer := provider.newServerObserver(&unikornv1.Identity{}, &stubComputeClient{}, []servers.Server{
		{ID: "id-a", Name: "server-a", Status: "ACTIVE", PowerState: servers.RUNNING},
		{ID: "id-b", Name: "server-b", Status: "ERROR"},
		{ID: "id-c", Name: "server-c", Status: "SHUTOFF", PowerState: servers.SHUTDOWN},
	})

	for name, want := range map[string]unikornv1.ActiveConditionReason{
		"server-a": unikornv1.ActiveConditionReasonRunning,
		"server-b": unikornv1.ActiveConditionReasonError,
		"server-c": unikornv1.ActiveConditionReasonStopped,
	} {
		server := observedServer(name)

		require.NoError(t, observer.Observe(t.Context(), server))

		active, err := unikornv1.GetActiveCondition(server)
		require.NoError(t, err)
		require.Equal(t, want, active.Reason, "server %s projected from the wrong row", name)
	}
}

// TestServerObserverFirstDuplicateNameWins pins the tie-break, which is the
// behaviour GetServer's exact-match post-filter had: Nova's first matching row.
func TestServerObserverFirstDuplicateNameWins(t *testing.T) {
	t.Parallel()

	provider := observerProvider()

	observer := provider.newServerObserver(&unikornv1.Identity{}, &stubComputeClient{}, []servers.Server{
		{ID: "first", Name: "server-a", Status: "ACTIVE", PowerState: servers.RUNNING},
		{ID: "second", Name: "server-a", Status: "SHUTOFF", PowerState: servers.SHUTDOWN},
	})

	server := observedServer("server-a")

	require.NoError(t, observer.Observe(t.Context(), server))

	active, err := unikornv1.GetActiveCondition(server)
	require.NoError(t, err)
	require.Equal(t, unikornv1.ActiveConditionReasonRunning, active.Reason,
		"expected the first duplicate row, got the last")
}

// TestServerObserverAbsentRecordsObservation pins the not-found contract: the
// absent observation is stamped before the error surfaces, because the monitor
// persists it to fire the observed wake.
func TestServerObserverAbsentRecordsObservation(t *testing.T) {
	t.Parallel()

	provider := observerProvider()

	observer := provider.newServerObserver(&unikornv1.Identity{}, &stubComputeClient{}, []servers.Server{
		{ID: "id-a", Name: "server-a", Status: "ACTIVE"},
	})

	server := observedServer("server-missing")
	server.Generation = 7
	server.Status.Observed = &unikornv1.ServerObservedStatus{Errored: true}

	err := observer.Observe(t.Context(), server)

	require.ErrorIs(t, err, coreerrors.ErrResourceNotFound)
	require.NotNil(t, server.Status.Observed)
	require.False(t, server.Status.Observed.Errored, "absence is not a provider error")
	require.Equal(t, int64(7), server.Status.Observed.Generation)
}

// TestServerObserverEmptyNameIsAbsent pins that a server with no name label
// cannot match a row, exactly as the old filtered read could not.
func TestServerObserverEmptyNameIsAbsent(t *testing.T) {
	t.Parallel()

	provider := observerProvider()

	observer := provider.newServerObserver(&unikornv1.Identity{}, &stubComputeClient{}, []servers.Server{
		{ID: "id-a", Name: "server-a", Status: "ACTIVE", PowerState: servers.RUNNING},
	})

	server := &unikornv1.Server{
		Spec: unikornv1.ServerSpec{
			FlavorID: idstest.MustParseFlavorID(observerFlavor),
		},
	}

	require.ErrorIs(t, observer.Observe(t.Context(), server), coreerrors.ErrResourceNotFound)
}

// TestServerObserverNeedsNoProviderCall pins that projecting from the batch
// costs nothing further: the stub records every call it is asked for, and a
// healthy server must not provoke one.
func TestServerObserverNeedsNoProviderCall(t *testing.T) {
	t.Parallel()

	provider := observerProvider()
	stub := &stubComputeClient{}

	observer := provider.newServerObserver(&unikornv1.Identity{}, stub, []servers.Server{
		{ID: "id-a", Name: "server-a", Status: "ACTIVE", PowerState: servers.RUNNING},
	})

	require.NoError(t, observer.Observe(t.Context(), observedServer("server-a")))
	require.Zero(t, stub.listReads, "the batch is already held")
	require.Zero(t, stub.faultReads, "a healthy server has no fault to read")
}
