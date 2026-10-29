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

//nolint:testpackage // Tests cover the unexported monitor-side observation directly.
package openstack

import (
	"context"
	"errors"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/require"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"
)

var (
	errFaultReadFailed = errors.New("fault read failed")
	errServerRead      = errors.New("nova unavailable")
)

// TestObserveServerFetchesFaultOnErrorTransition pins the plumb:
// the poll already holds the compute client, and that same client serves the
// one-off fault read on the transition into error.
func TestObserveServerFetchesFaultOnErrorTransition(t *testing.T) {
	t.Parallel()

	compute := &stubComputeClient{server: &servers.Server{
		ID:     "nova-id",
		Status: novaStatusError,
	}}
	identity := &unikornv1.Identity{}
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{
		FlavorID: idstest.MustParseFlavorID("11111111-1111-4111-a111-111111111111"),
	}}

	provider := &Provider{
		openstack: &openStackClients{
			_region: &unikornv1.Region{},
		},
	}

	_, err := provider.observeServer(t.Context(), identity, server, compute,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return nil, errIronicUnavailable
		})

	require.NoError(t, err)
	require.Equal(t, unikornv1.ActiveConditionReasonError, activeReason(t, server))
	require.Equal(t, 1, compute.faultReads)
}

// TestObserveServerDoesNotRefetchFaultWhenAlreadyErrored pins
// the edge gate at the caller: the fault read fires only on the false→true
// transition, not on every poll of an already-errored server, so a steady-state
// errored server pays no per-poll Nova fault read.
func TestObserveServerDoesNotRefetchFaultWhenAlreadyErrored(t *testing.T) {
	t.Parallel()

	compute := &stubComputeClient{server: &servers.Server{
		ID:     "nova-id",
		Status: novaStatusError,
	}}
	identity := &unikornv1.Identity{}
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{
		FlavorID: idstest.MustParseFlavorID("11111111-1111-4111-a111-111111111111"),
	}}
	server.SetActiveCondition(unikornv1.ActiveConditionReasonError)

	provider := &Provider{
		openstack: &openStackClients{
			_region: &unikornv1.Region{},
		},
	}

	_, err := provider.observeServer(t.Context(), identity, server, compute,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return nil, errIronicUnavailable
		})

	require.NoError(t, err)
	require.Equal(t, unikornv1.ActiveConditionReasonError, activeReason(t, server))
	require.Zero(t, compute.faultReads, "an already-errored server must not refetch the fault")
}

// TestObserveServerNoFaultFetchOnAbsent pins that an absent
// Nova server never triggers a fault fetch — there is no server to read one for.
func TestObserveServerNoFaultFetchOnAbsent(t *testing.T) {
	t.Parallel()

	compute := &stubComputeClient{serverErr: errServerRead}
	identity := &unikornv1.Identity{}
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{
		FlavorID: idstest.MustParseFlavorID("11111111-1111-4111-a111-111111111111"),
	}}

	provider := &Provider{
		openstack: &openStackClients{
			_region: &unikornv1.Region{},
		},
	}

	_, _ = provider.observeServer(t.Context(), identity, server, compute,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return nil, errIronicUnavailable
		})

	require.Zero(t, compute.faultReads, "a read failure that aborts the poll must not fetch a fault")
}

// TestObserveServerFaultFetch404DoesNotBlockStatus pins that a
// server deleted between the list and the per-ID fault read still records the
// errored marker — the fetch is best-effort, so a 404 during it cannot block the
// status write the marker decision already made.
func TestObserveServerFaultFetch404DoesNotBlockStatus(t *testing.T) {
	t.Parallel()

	compute := &stubComputeClient{
		server: &servers.Server{
			ID:     "nova-id",
			Status: novaStatusError,
		},
		faultErr: coreerrors.ErrResourceNotFound,
	}
	identity := &unikornv1.Identity{}
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{
		FlavorID: idstest.MustParseFlavorID("11111111-1111-4111-a111-111111111111"),
	}}

	provider := &Provider{
		openstack: &openStackClients{
			_region: &unikornv1.Region{},
		},
	}

	_, err := provider.observeServer(t.Context(), identity, server, compute,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return nil, errIronicUnavailable
		})

	require.NoError(t, err)
	require.Equal(t, unikornv1.ActiveConditionReasonError, activeReason(t, server), "a 404 during the fault fetch must not lose the errored state")
	require.Equal(t, 1, compute.faultReads)
}

// TestObserveServerFaultFetchFailureDoesNotBlockStatus pins that
// a failed fault read (not a 404) still records the errored marker — the fetch is
// best-effort, so no failure of it may block the status update.
func TestObserveServerFaultFetchFailureDoesNotBlockStatus(t *testing.T) {
	t.Parallel()

	compute := &stubComputeClient{
		server: &servers.Server{
			ID:     "nova-id",
			Status: novaStatusError,
		},
		faultErr: errFaultReadFailed,
	}
	identity := &unikornv1.Identity{}
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{
		FlavorID: idstest.MustParseFlavorID("11111111-1111-4111-a111-111111111111"),
	}}

	provider := &Provider{
		openstack: &openStackClients{
			_region: &unikornv1.Region{},
		},
	}

	_, err := provider.observeServer(t.Context(), identity, server, compute,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return nil, errIronicUnavailable
		})

	require.NoError(t, err)
	require.Equal(t, unikornv1.ActiveConditionReasonError, activeReason(t, server), "a failed fault fetch must not lose the errored state")
	require.Equal(t, 1, compute.faultReads)
}

// TestObserveServerZeroValuedFaultCompletes pins the zero-valued
// fault branch: GetServerFault returns a value-struct pointer, so an errored
// server without fault detail yields a zero struct (code 0, empty message). The
// code path must complete without panic and still record the marker; the
// zero-filled detail line is suppressed in favour of a no-detail info log.
func TestObserveServerZeroValuedFaultCompletes(t *testing.T) {
	t.Parallel()

	compute := &stubComputeClient{
		server: &servers.Server{
			ID:     "nova-id",
			Status: novaStatusError,
		},
		fault: &servers.Fault{},
	}
	identity := &unikornv1.Identity{}
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{
		FlavorID: idstest.MustParseFlavorID("11111111-1111-4111-a111-111111111111"),
	}}

	provider := &Provider{
		openstack: &openStackClients{
			_region: &unikornv1.Region{},
		},
	}

	_, err := provider.observeServer(t.Context(), identity, server, compute,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return nil, errIronicUnavailable
		})

	require.NoError(t, err)
	require.Equal(t, unikornv1.ActiveConditionReasonError, activeReason(t, server))
	require.Equal(t, 1, compute.faultReads)
}

// TestObserveServerSurfacesNonNotFound pins the negative half of
// the not-found branch: any other GetServer error still returns that error and
// leaves the projected status untouched, so a transient read failure cannot
// silently lose the errored state.
func TestObserveServerSurfacesNonNotFound(t *testing.T) {
	t.Parallel()

	compute := &stubComputeClient{serverErr: errServerRead}
	identity := &unikornv1.Identity{}
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{
		FlavorID: idstest.MustParseFlavorID("11111111-1111-4111-a111-111111111111"),
	}}
	server.SetActiveCondition(unikornv1.ActiveConditionReasonError)

	provider := &Provider{
		openstack: &openStackClients{
			_region: &unikornv1.Region{},
		},
	}

	_, err := provider.observeServer(t.Context(), identity, server, compute,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return nil, errIronicUnavailable
		})

	require.ErrorIs(t, err, errServerRead)
	require.Equal(t, unikornv1.ActiveConditionReasonError, activeReason(t, server), "a non-not-found error must not lose the errored state")
	require.Zero(t, compute.faultReads, "no fault fetch happens on a read failure that aborts the poll")
}
