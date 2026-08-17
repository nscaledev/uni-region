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
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"
)

const (
	observedImageID    = "33333333-3333-4333-a333-333333333333"
	observedOldImageID = "44444444-4444-4444-a444-444444444444"
)

var (
	errFaultReadFailed = errors.New("fault read failed")
	errServerRead      = errors.New("nova unavailable")
)

func observedImagePointer(s string) *regionids.ImageID {
	id := idstest.MustParseImageID(s)

	return &id
}

// TestSetServerObservedImage tables the image read rules: a readable ref is
// recorded and overwrites, and an unreadable one preserves whatever was there.
// Preserving matters because the alternative — clearing — lets a single bad read
// erase a known image, which a reader cannot distinguish from "never observed".
func TestSetServerObservedImage(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		priorImage *regionids.ImageID
		novaImage  map[string]any
		want       *regionids.ImageID
	}{
		"readable ref is recorded": {
			novaImage: map[string]any{"id": observedImageID},
			want:      observedImagePointer(observedImageID),
		},
		"readable ref overwrites a previous image": {
			priorImage: observedImagePointer(observedOldImageID),
			novaImage:  map[string]any{"id": observedImageID},
			want:       observedImagePointer(observedImageID),
		},
		"absent ref preserves the previous image": {
			priorImage: observedImagePointer(observedOldImageID),
			novaImage:  nil,
			want:       observedImagePointer(observedOldImageID),
		},
		"empty ref preserves the previous image": {
			priorImage: observedImagePointer(observedOldImageID),
			novaImage:  map[string]any{"id": ""},
			want:       observedImagePointer(observedOldImageID),
		},
		"unparseable ref preserves the previous image": {
			priorImage: observedImagePointer(observedOldImageID),
			novaImage:  map[string]any{"id": "not-a-uuid"},
			want:       observedImagePointer(observedOldImageID),
		},
		"absent ref with no previous image records nothing": {
			novaImage: nil,
			want:      nil,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := &unikornv1.Server{}

			if testCase.priorImage != nil {
				server.Status.Observed = &unikornv1.ServerObservedStatus{Image: testCase.priorImage}
			}

			setServerObservedStatus(server, &servers.Server{
				ID:     "server-1",
				Status: novaStatusActive,
				Image:  testCase.novaImage,
			})

			require.NotNil(t, server.Status.Observed, "a successful poll always records an observation")
			require.Equal(t, testCase.want, server.Status.Observed.Image)
		})
	}
}

// TestSetServerObservedErrored tables the error projection rules. Errored is a
// neutral presence marker — the provider's fault detail goes to the observation
// log, never to status — and it is live state, not a latch: it clears on an
// authoritative non-error read. That is safe only because an unreachable
// provider aborts the poll before this is called. It is gated on the provider's
// status alone. The projection is pure: it performs no I/O and returns whether
// errored transitioned false→true on this call, leaving the fault fetch (a
// dedicated per-ID read, only on that transition — a list response can omit it,
// and every-read enrichment doubles the Nova reads for errored servers exactly
// when Nova is degraded) to the caller, where it can be bounded and made
// best-effort so no failure of it may block the status update.
func TestSetServerObservedErrored(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		priorErrored   bool
		novaStatus     string
		want           bool
		wantEnteredErr bool
	}{
		"error status records the marker and signals the transition": {
			novaStatus:     novaStatusError,
			want:           true,
			wantEnteredErr: true,
		},
		"already errored does not signal a transition": {
			priorErrored:   true,
			novaStatus:     novaStatusError,
			want:           true,
			wantEnteredErr: false,
		},
		"non-error status clears a previously recorded marker without a transition": {
			priorErrored:   true,
			novaStatus:     novaStatusActive,
			want:           false,
			wantEnteredErr: false,
		},
		"non-error status records nothing and signals no transition": {
			novaStatus:     novaStatusActive,
			want:           false,
			wantEnteredErr: false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := &unikornv1.Server{}

			if testCase.priorErrored {
				server.Status.Observed = &unikornv1.ServerObservedStatus{Errored: true}
			}

			enteredError := setServerObservedStatus(server, &servers.Server{
				ID:     "server-1",
				Status: testCase.novaStatus,
			})

			require.NotNil(t, server.Status.Observed)
			require.Equal(t, testCase.want, server.Status.Observed.Errored)
			require.Equal(t, testCase.wantEnteredErr, enteredError,
				"the transition signal belongs to the false→true edge alone")
		})
	}
}

// TestUpdateServerStateWithClientsRecordsObservedStatus pins the observation into
// the monitor's poll path, so the subtree is populated by the same provider read
// that drives health, MAC and phase rather than needing a second one.
func TestUpdateServerStateWithClientsRecordsObservedStatus(t *testing.T) {
	t.Parallel()

	compute := &stubComputeClient{server: &servers.Server{
		ID:     "nova-id",
		Status: novaStatusActive,
		Image:  map[string]any{"id": observedImageID},
	}}
	identity := &unikornv1.Identity{}
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{
		FlavorID: idstest.MustParseFlavorID("11111111-1111-4111-a111-111111111111"),
	}}
	server.Generation = 4

	provider := &Provider{
		openstack: &openStackClients{
			_region: &unikornv1.Region{},
		},
	}

	err := provider.updateServerStateWithClients(t.Context(), identity, server, compute,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return nil, errIronicUnavailable
		})

	require.NoError(t, err)
	require.NotNil(t, server.Status.Observed)
	require.Equal(t, int64(4), server.Status.Observed.Generation)
	require.Equal(t, observedImagePointer(observedImageID), server.Status.Observed.Image)
	require.False(t, server.Status.Observed.Errored)
	require.Zero(t, compute.faultReads, "a healthy poll must not pay a fault read")
}

// TestUpdateServerStateWithClientsFetchesFaultOnErrorTransition pins the plumb:
// the poll already holds the compute client, and that same client serves the
// one-off fault read on the transition into error.
func TestUpdateServerStateWithClientsFetchesFaultOnErrorTransition(t *testing.T) {
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

	err := provider.updateServerStateWithClients(t.Context(), identity, server, compute,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return nil, errIronicUnavailable
		})

	require.NoError(t, err)
	require.NotNil(t, server.Status.Observed)
	require.True(t, server.Status.Observed.Errored)
	require.Equal(t, 1, compute.faultReads)
}

// TestUpdateServerStateWithClientsDoesNotRefetchFaultWhenAlreadyErrored pins
// the edge gate at the caller: the fault read fires only on the false→true
// transition, not on every poll of an already-errored server, so a steady-state
// errored server pays no per-poll Nova fault read.
func TestUpdateServerStateWithClientsDoesNotRefetchFaultWhenAlreadyErrored(t *testing.T) {
	t.Parallel()

	compute := &stubComputeClient{server: &servers.Server{
		ID:     "nova-id",
		Status: novaStatusError,
	}}
	identity := &unikornv1.Identity{}
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{
		FlavorID: idstest.MustParseFlavorID("11111111-1111-4111-a111-111111111111"),
	}}
	server.Status.Observed = &unikornv1.ServerObservedStatus{Errored: true}

	provider := &Provider{
		openstack: &openStackClients{
			_region: &unikornv1.Region{},
		},
	}

	err := provider.updateServerStateWithClients(t.Context(), identity, server, compute,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return nil, errIronicUnavailable
		})

	require.NoError(t, err)
	require.True(t, server.Status.Observed.Errored)
	require.Zero(t, compute.faultReads, "an already-errored server must not refetch the fault")
}

// TestUpdateServerStateWithClientsNoFaultFetchOnAbsent pins that an absent
// Nova server never triggers a fault fetch — there is no server to read one for.
func TestUpdateServerStateWithClientsNoFaultFetchOnAbsent(t *testing.T) {
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

	_ = provider.updateServerStateWithClients(t.Context(), identity, server, compute,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return nil, errIronicUnavailable
		})

	require.Zero(t, compute.faultReads, "a read failure that aborts the poll must not fetch a fault")
}

// TestUpdateServerStateWithClientsFaultFetch404DoesNotBlockStatus pins that a
// server deleted between the list and the per-ID fault read still records the
// errored marker — the fetch is best-effort, so a 404 during it cannot block the
// status write the marker decision already made.
func TestUpdateServerStateWithClientsFaultFetch404DoesNotBlockStatus(t *testing.T) {
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

	err := provider.updateServerStateWithClients(t.Context(), identity, server, compute,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return nil, errIronicUnavailable
		})

	require.NoError(t, err)
	require.NotNil(t, server.Status.Observed)
	require.True(t, server.Status.Observed.Errored, "a 404 during the fault fetch must not clear the marker")
	require.Equal(t, 1, compute.faultReads)
}

// TestUpdateServerStateWithClientsFaultFetchFailureDoesNotBlockStatus pins that
// a failed fault read (not a 404) still records the errored marker — the fetch is
// best-effort, so no failure of it may block the status update.
func TestUpdateServerStateWithClientsFaultFetchFailureDoesNotBlockStatus(t *testing.T) {
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

	err := provider.updateServerStateWithClients(t.Context(), identity, server, compute,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return nil, errIronicUnavailable
		})

	require.NoError(t, err)
	require.NotNil(t, server.Status.Observed)
	require.True(t, server.Status.Observed.Errored, "a failed fault fetch must not clear the marker")
	require.Equal(t, 1, compute.faultReads)
}

// TestUpdateServerStateWithClientsZeroValuedFaultCompletes pins the zero-valued
// fault branch: GetServerFault returns a value-struct pointer, so an errored
// server without fault detail yields a zero struct (code 0, empty message). The
// code path must complete without panic and still record the marker; the
// zero-filled detail line is suppressed in favour of a no-detail info log.
func TestUpdateServerStateWithClientsZeroValuedFaultCompletes(t *testing.T) {
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

	err := provider.updateServerStateWithClients(t.Context(), identity, server, compute,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return nil, errIronicUnavailable
		})

	require.NoError(t, err)
	require.NotNil(t, server.Status.Observed)
	require.True(t, server.Status.Observed.Errored)
	require.Equal(t, 1, compute.faultReads)
}

// TestUpdateServerStateWithClientsRecordsAbsentOnNotFound pins the not-found
// branch: a GetServer failure of coreerrors.ErrResourceNotFound records an absent
// observation (errored cleared, generation stamped from metadata.generation, image
// preserved as the last-known value) and still surfaces the error — the
// create-retry provisioner's "confirmed gone" gate depends on it. The observation
// is recorded for callers that choose to persist status anyway (the monitor does).
// No fault fetch happens — there is no server to read one for — so the observation
// client is never touched on this path.
func TestUpdateServerStateWithClientsRecordsAbsentOnNotFound(t *testing.T) {
	t.Parallel()

	compute := &stubComputeClient{serverErr: coreerrors.ErrResourceNotFound}
	identity := &unikornv1.Identity{}
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{
		FlavorID: idstest.MustParseFlavorID("11111111-1111-4111-a111-111111111111"),
	}}
	server.Generation = 4
	server.Status.Observed = &unikornv1.ServerObservedStatus{
		Generation: 3,
		Image:      observedImagePointer(observedImageID),
		Errored:    true,
	}

	provider := &Provider{
		openstack: &openStackClients{
			_region: &unikornv1.Region{},
		},
	}

	err := provider.updateServerStateWithClients(t.Context(), identity, server, compute,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return nil, errIronicUnavailable
		})

	require.ErrorIs(t, err, coreerrors.ErrResourceNotFound, "the error must surface for the create-retry confirmed-gone gate")
	require.NotNil(t, server.Status.Observed)
	require.False(t, server.Status.Observed.Errored, "absence is not a provider error, so the marker must clear")
	require.Equal(t, int64(4), server.Status.Observed.Generation, "generation must be stamped from metadata.generation as on every successful read")
	require.Equal(t, observedImagePointer(observedImageID), server.Status.Observed.Image, "the last-known image is sticky on the absent path")
	require.Zero(t, compute.faultReads, "no fault fetch happens when there is no server to read one for")
}

// TestUpdateServerStateWithClientsSurfacesNonNotFound pins the negative half of
// the not-found branch: any other GetServer error still returns that error and
// leaves the observed subtree untouched, so a transient read failure cannot
// silently clear the errored marker or stamp a fresh generation over a stale one.
func TestUpdateServerStateWithClientsSurfacesNonNotFound(t *testing.T) {
	t.Parallel()

	compute := &stubComputeClient{serverErr: errServerRead}
	identity := &unikornv1.Identity{}
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{
		FlavorID: idstest.MustParseFlavorID("11111111-1111-4111-a111-111111111111"),
	}}
	server.Generation = 4
	server.Status.Observed = &unikornv1.ServerObservedStatus{
		Generation: 3,
		Image:      observedImagePointer(observedImageID),
		Errored:    true,
	}

	provider := &Provider{
		openstack: &openStackClients{
			_region: &unikornv1.Region{},
		},
	}

	err := provider.updateServerStateWithClients(t.Context(), identity, server, compute,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return nil, errIronicUnavailable
		})

	require.ErrorIs(t, err, errServerRead)
	require.Equal(t, int64(3), server.Status.Observed.Generation, "a non-not-found error must not stamp the generation")
	require.Equal(t, observedImagePointer(observedImageID), server.Status.Observed.Image, "a non-not-found error must not touch the image")
	require.True(t, server.Status.Observed.Errored, "a non-not-found error must not clear the errored marker")
	require.Zero(t, compute.faultReads, "no fault fetch happens on a read failure that aborts the poll")
}

// TestSetServerObservedGeneration pins the freshness stamp. Without it an
// observation cannot be told apart from one taken before a spec edit.
func TestSetServerObservedGeneration(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}
	server.Generation = 7

	setServerObservedStatus(server, &servers.Server{
		ID:     "server-1",
		Status: novaStatusActive,
		Image:  map[string]any{"id": observedImageID},
	})

	require.Equal(t, int64(7), server.Status.Observed.Generation)
}

// TestSetServerObservedStatusStampsGenerationWithoutFacts pins that a poll which
// read the provider but could record nothing still creates the subtree. A present
// subtree with no image means "polled, image unreadable"; an absent one means
// "never successfully polled". Readers depend on the difference.
func TestSetServerObservedStatusStampsGenerationWithoutFacts(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}
	server.Generation = 3

	setServerObservedStatus(server, &servers.Server{
		ID:     "server-1",
		Status: novaStatusActive,
	})

	require.NotNil(t, server.Status.Observed)
	require.Equal(t, int64(3), server.Status.Observed.Generation)
	require.Nil(t, server.Status.Observed.Image)
	require.False(t, server.Status.Observed.Errored)
}
