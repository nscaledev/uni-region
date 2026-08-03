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

package openstack_test

import (
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack/mock"

	corev1 "k8s.io/api/core/v1"
)

// The three images the protocol distinguishes: what the provider was running
// when the attempt was armed, what the user asked for, and a third the user can
// move on to.
const (
	rebuildImagePre    = "11111111-1111-4111-a111-111111111111"
	rebuildImageTarget = "22222222-2222-4222-a222-222222222222"
	rebuildImageOther  = "33333333-3333-4333-a333-333333333333"
)

// serverWithRebuildMarker is a CR whose spec wants target and whose status
// already carries an attempt marker for it, armed at the pre image.
func serverWithRebuildMarker(t *testing.T, accepted bool) *unikornv1.Server {
	t.Helper()

	server := serverWantingTargetImage()
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{
		TargetImageID:  idstest.MustParseImageID(rebuildImageTarget),
		PreArmImageRef: rebuildImagePre,
		Accepted:       accepted,
	}

	return server
}

// serverWantingTargetImage is a CR with no attempt marker, wanting the target
// image. Tests that need a different desired image reassign Spec.Image.ID.
func serverWantingTargetImage() *unikornv1.Server {
	return &unikornv1.Server{
		Spec: unikornv1.ServerSpec{
			Image: &unikornv1.ServerImage{ID: idstest.MustParseImageID(rebuildImageTarget)},
		},
	}
}

// openstackServerAt is a Nova read of a booted server at the given image, with
// the given task_state: empty is at rest, anything else is an operation in
// flight.
func openstackServerAt(image, taskState string) *servers.Server {
	return &servers.Server{
		ID:         "server-id",
		Status:     "ACTIVE",
		Image:      map[string]any{"id": image},
		TaskState:  taskState,
		LaunchedAt: time.Now().Add(-time.Hour),
	}
}

// openstackServerUnlaunchedAt is a Nova read of a server that has never booted,
// for which the image is still a create parameter.
func openstackServerUnlaunchedAt(image string) *servers.Server {
	openstackServer := openstackServerAt(image, "")
	openstackServer.LaunchedAt = time.Time{}

	return openstackServer
}

// openstackServerPreArmInState is a taskless Nova read still at the pre-arm
// image, in the given vm_state: these cases turn on rebuild-admissibility, not
// on which image the provider holds.
func openstackServerPreArmInState(status string) *servers.Server {
	openstackServer := openstackServerAt(rebuildImagePre, "")
	openstackServer.Status = status

	return openstackServer
}

// openstackServerErroredAt is a Nova read in the sticky error vm_state.
func openstackServerErroredAt(image, taskState string) *servers.Server {
	openstackServer := openstackServerAt(image, taskState)
	openstackServer.Status = "ERROR"

	return openstackServer
}

// The pass that records a commitment must not call the provider: the record has
// to be durable first, and the framework persists status at end of pass.
func TestRebuildCommitPassCallsNothing(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock.NewMockServerInterface(ctrl)
	// No RebuildServer expectation: any call fails the test.

	server := serverWithRebuildMarker(t, false)

	_, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
		openstackServerAt(rebuildImagePre, ""), nil)

	require.ErrorIs(t, err, provisioners.ErrYield)
	require.NotNil(t, server.Status.Rebuild)
	assert.True(t, server.Status.Rebuild.Accepted)
	assert.Equal(t, idstest.MustParseImageID(rebuildImageTarget), server.Status.Rebuild.TargetImageID)
	assert.Equal(t, rebuildImagePre, server.Status.Rebuild.PreArmImageRef)
}

// The call happens on a later pass, from a durable marker.
func TestRebuildCallPassCallsProviderOnce(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock.NewMockServerInterface(ctrl)
	client.EXPECT().
		RebuildServer(gomock.Any(), "server-id", idstest.MustParseImageID(rebuildImageTarget)).
		Return(openstackServerAt(rebuildImageTarget, "rebuilding"), nil).
		Times(1)

	server := serverWithRebuildMarker(t, true)

	openstackServer, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
		openstackServerAt(rebuildImagePre, ""), nil)

	require.ErrorIs(t, err, provisioners.ErrYield)
	require.NotNil(t, server.Status.Rebuild)
	assert.True(t, server.Status.Rebuild.Accepted)
	assert.False(t, server.Status.Rebuild.Parked)
	assert.Equal(t, "rebuilding", openstackServer.TaskState)
}

// An accepted attempt whose rebuild is already in flight reads busy, never idle
// at the pre-arm image, so the provider is not asked a second time.
func TestRebuildInFlightAttemptIsNotReissued(t *testing.T) {
	t.Parallel()

	for _, taskState := range []string{"rebuilding", "rebuild_spawning"} {
		t.Run(taskState, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			client := mock.NewMockServerInterface(ctrl)
			// No RebuildServer expectation: any call fails the test.

			server := serverWithRebuildMarker(t, true)

			_, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
				openstackServerAt(rebuildImagePre, taskState), nil)

			require.ErrorIs(t, err, provisioners.ErrYield)
			assert.False(t, server.Status.Rebuild.Parked)
		})
	}
}

// An outstanding, unparked marker keeps the object enqueued. Without this the
// deferred call never happens: the Server watch is generation-filtered, so the
// status write that records the commitment enqueues nothing. A parked marker
// must NOT yield, or a parked server spins forever.
func TestRebuildOutstandingMarkerYields(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// A committed marker calls; an armed one only records the commitment.
		accepted bool
		calls    int
	}{
		{"armed", false, 0},
		{"committed", true, 1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			client := mock.NewMockServerInterface(ctrl)
			client.EXPECT().RebuildServer(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(openstackServerAt(rebuildImageTarget, "rebuilding"), nil).
				Times(c.calls)

			server := serverWithRebuildMarker(t, c.accepted)

			_, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
				openstackServerAt(rebuildImagePre, ""), nil)

			require.ErrorIs(t, err, provisioners.ErrYield)
		})
	}
}

func TestRebuildParkedMarkerDoesNotYield(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock.NewMockServerInterface(ctrl)

	server := serverWithRebuildMarker(t, true)
	server.Status.Rebuild.Parked = true

	_, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
		openstackServerAt(rebuildImagePre, ""), nil)

	require.NotErrorIs(t, err, provisioners.ErrYield)
	require.ErrorIs(t, err, provisioners.ErrUserActionRequired)
	require.NotNil(t, server.Status.Rebuild)
	assert.True(t, server.Status.Rebuild.Parked)
}

// A park must report a reason core's API projection recognises. Provisioning
// reasons are a closed vocabulary projected through a switch whose default is
// "provisioning", and a park is terminal and never requeued — so an unrecognised
// reason leaves the server reporting as still provisioning forever. Asserted
// through the real projection, because the symptom only appears there.
func TestRebuildParkReportsAReasonTheAPIProjects(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock.NewMockServerInterface(ctrl)

	server := serverWithRebuildMarker(t, true)
	server.Status.Rebuild.Parked = true

	_, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
		openstackServerAt(rebuildImagePre, ""), nil)
	require.ErrorIs(t, err, provisioners.ErrUserActionRequired)

	var perr *provisioners.Error

	require.ErrorAs(t, err, &perr)
	assert.Equal(t, unikornv1core.ConditionReasonErrored, perr.Reason())

	// Exactly what core's reconciler writes onto the object from this error.
	server.SetProvisioningCondition(corev1.ConditionFalse, perr.Reason(), perr.Message())

	metadata := conversion.ResourceReadMetadata(server, nil)
	assert.Equal(t, coreopenapi.ResourceProvisioningStatusError, metadata.ProvisioningStatus,
		"a parked rebuild must project to error, not a permanent provisioning spinner")

	require.NotNil(t, metadata.ProvisioningStatusDetail)
	assert.EqualValues(t, unikornv1core.ConditionReasonErrored, metadata.ProvisioningStatusDetail.Reason)
	assert.Equal(t, openstack.RebuildParkMessageSuperseded, metadata.ProvisioningStatusDetail.Message)
}

// Before first boot the image is a create parameter, not something to converge:
// nothing may be armed, and nothing may be asked of the provider.
func TestRebuildNotLaunchedActsOnNothing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		server *unikornv1.Server
		// Nothing to arm means nothing to requeue for. A marker that predates the
		// launch gate has to keep its wake channel: first boot does not bump the
		// generation, so only the requeue gets the deferred call made.
		wantYield bool
	}{
		{"no marker", serverWantingTargetImage(), false},
		{"committed marker at the pre-arm image", serverWithRebuildMarker(t, true), true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			client := mock.NewMockServerInterface(ctrl)
			// No RebuildServer expectation: any call fails the test.

			markerBefore := c.server.Status.Rebuild.DeepCopy()

			_, err := openstack.ReconcileServerRebuild(t.Context(), client, c.server,
				openstackServerUnlaunchedAt(rebuildImagePre), nil)

			if c.wantYield {
				require.ErrorIs(t, err, provisioners.ErrYield)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, markerBefore, c.server.Status.Rebuild, "the marker must be left exactly as it was")
		})
	}
}

// The launch gate withholds only the two acting rows: a marker that already
// exists must still be able to settle and to retarget, or a pre-boot attempt
// would report a terminal failure that no spec edit could clear.
func TestRebuildNotLaunchedStillRetiresMarkers(t *testing.T) {
	t.Parallel()

	t.Run("settles", func(t *testing.T) {
		t.Parallel()

		client := mock.NewMockServerInterface(gomock.NewController(t))
		server := serverWithRebuildMarker(t, true)

		_, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
			openstackServerUnlaunchedAt(rebuildImageTarget), nil)

		require.ErrorIs(t, err, provisioners.ErrYield)
		assert.Nil(t, server.Status.Rebuild)
	})

	t.Run("retargets", func(t *testing.T) {
		t.Parallel()

		client := mock.NewMockServerInterface(gomock.NewController(t))
		server := serverWithRebuildMarker(t, true)
		server.Status.Rebuild.Parked = true
		server.Spec.Image.ID = idstest.MustParseImageID(rebuildImageOther)

		_, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
			openstackServerUnlaunchedAt(rebuildImagePre), nil)

		require.ErrorIs(t, err, provisioners.ErrYield)
		assert.Nil(t, server.Status.Rebuild)
	})
}

// Arming records the intent and the image the provider held at the time, which
// is what later distinguishes a provider we have not asked yet from one
// something else has rebuilt. No provider call.
func TestRebuildArmRecordsIntentOnly(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock.NewMockServerInterface(ctrl)
	// No RebuildServer expectation: any call fails the test.

	server := serverWantingTargetImage()

	_, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
		openstackServerAt(rebuildImagePre, ""), nil)

	require.ErrorIs(t, err, provisioners.ErrYield)
	require.NotNil(t, server.Status.Rebuild)
	assert.Equal(t, idstest.MustParseImageID(rebuildImageTarget), server.Status.Rebuild.TargetImageID)
	assert.Equal(t, rebuildImagePre, server.Status.Rebuild.PreArmImageRef)
	assert.False(t, server.Status.Rebuild.Accepted)
	assert.False(t, server.Status.Rebuild.Parked)
}

// Settlement retires the marker and requeues. Retiring the marker takes away the
// trailing requeue, so clear has to reissue it.
func TestRebuildClearRetiresSettledMarkerAndRequeues(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock.NewMockServerInterface(ctrl)

	server := serverWithRebuildMarker(t, true)

	_, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
		openstackServerAt(rebuildImageTarget, ""), nil)

	require.ErrorIs(t, err, provisioners.ErrYield)
	assert.Nil(t, server.Status.Rebuild)
}

// The coalesced-retarget sequence: the rebuild to the target settled, but the user
// had already moved the spec on to a third image and that generation event
// coalesced into this very pass. Clearing without requeueing would leave the spec
// naming one image, the machine running another, and no pending work — permanent
// silent divergence.
func TestRebuildClearRequeuesForACoalescedRetarget(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock.NewMockServerInterface(ctrl)
	// No RebuildServer expectation: settling and arming are separate passes.

	server := serverWithRebuildMarker(t, true)
	server.Spec.Image.ID = idstest.MustParseImageID(rebuildImageOther)

	_, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
		openstackServerAt(rebuildImageTarget, ""), nil)

	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Nil(t, server.Status.Rebuild, "the settled attempt is retired")

	// The requeued pass is the one that arms the new target.
	_, err = openstack.ReconcileServerRebuild(t.Context(), client, server,
		openstackServerAt(rebuildImageTarget, ""), nil)

	require.ErrorIs(t, err, provisioners.ErrYield)
	require.NotNil(t, server.Status.Rebuild)
	assert.Equal(t, idstest.MustParseImageID(rebuildImageOther), server.Status.Rebuild.TargetImageID)
}

// Nova admits a rebuild from only a few vm_states. The rest are stable and
// taskless but reject it with a 409, so nothing may be armed and nothing asked —
// otherwise the pass POSTs into that rejection on every pass, forever.
func TestRebuildNonAdmissibleStatesActOnNothing(t *testing.T) {
	t.Parallel()

	for _, status := range []string{"VERIFY_RESIZE", "PAUSED", "SUSPENDED", "SHELVED_OFFLOADED"} {
		t.Run(status, func(t *testing.T) {
			t.Parallel()

			t.Run("arms nothing", func(t *testing.T) {
				t.Parallel()

				client := mock.NewMockServerInterface(gomock.NewController(t))
				server := serverWantingTargetImage()

				_, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
					openstackServerPreArmInState(status), nil)

				require.NoError(t, err)
				assert.Nil(t, server.Status.Rebuild)
			})

			t.Run("calls nothing", func(t *testing.T) {
				t.Parallel()

				// No RebuildServer expectation: any call fails the test.
				client := mock.NewMockServerInterface(gomock.NewController(t))
				server := serverWithRebuildMarker(t, true)

				_, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
					openstackServerPreArmInState(status), nil)

				require.ErrorIs(t, err, provisioners.ErrYield)
				assert.False(t, server.Status.Rebuild.Parked, "waiting for an admissible state is not a failure")
			})
		})
	}
}

// Rebuilding a stopped server is legitimate and must not regress with the
// admissibility allow-list.
func TestRebuildStoppedServerStillArmsAndCalls(t *testing.T) {
	t.Parallel()

	t.Run("arms", func(t *testing.T) {
		t.Parallel()

		client := mock.NewMockServerInterface(gomock.NewController(t))
		server := serverWantingTargetImage()

		_, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
			openstackServerPreArmInState("SHUTOFF"), nil)

		require.ErrorIs(t, err, provisioners.ErrYield)
		require.NotNil(t, server.Status.Rebuild)
		assert.Equal(t, idstest.MustParseImageID(rebuildImageTarget), server.Status.Rebuild.TargetImageID)
	})

	t.Run("calls", func(t *testing.T) {
		t.Parallel()

		client := mock.NewMockServerInterface(gomock.NewController(t))
		client.EXPECT().
			RebuildServer(gomock.Any(), "server-id", idstest.MustParseImageID(rebuildImageTarget)).
			Return(openstackServerAt(rebuildImageTarget, "rebuilding"), nil).
			Times(1)

		server := serverWithRebuildMarker(t, true)

		_, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
			openstackServerPreArmInState("SHUTOFF"), nil)

		require.ErrorIs(t, err, provisioners.ErrYield)
	})
}

// A terminally errored server whose image ref is unreadable must park, not yield
// for ever: an error is decidable evidence even where the ref is not.
func TestRebuildErroredWithUnreadableImageParks(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))

	server := serverWithRebuildMarker(t, true)

	openstackServer := openstackServerErroredAt(rebuildImagePre, "")
	openstackServer.Image = nil

	_, err := openstack.ReconcileServerRebuild(t.Context(), client, server, openstackServer, nil)

	require.ErrorIs(t, err, provisioners.ErrUserActionRequired)
	require.NotErrorIs(t, err, provisioners.ErrYield)
	require.NotNil(t, server.Status.Rebuild)
	assert.True(t, server.Status.Rebuild.Parked)
}

// Parking latches on the marker and reports the fresh evidence that justified
// it, because that message is what an operator sees.
func TestRebuildParkLatchesAndReportsEvidence(t *testing.T) {
	t.Parallel()

	appliedPreImage := rebuildImagePre

	cases := []struct {
		name            string
		openstackServer *servers.Server
		applied         *string
		message         string
	}{
		{"errored", openstackServerErroredAt(rebuildImagePre, ""), nil, openstack.RebuildParkMessageErrored},
		{"errored with a stuck task", openstackServerErroredAt(rebuildImagePre, "rebuilding"), nil, openstack.RebuildParkMessageErrored},
		{"reported converged but not applied", openstackServerAt(rebuildImageTarget, ""), &appliedPreImage, openstack.RebuildParkMessageNotApplied},
		{"superseded", openstackServerAt(rebuildImageOther, ""), nil, openstack.RebuildParkMessageSuperseded},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			client := mock.NewMockServerInterface(ctrl)
			// No RebuildServer expectation: a park must never call the provider.

			server := serverWithRebuildMarker(t, true)

			_, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
				c.openstackServer, c.applied)

			require.ErrorIs(t, err, provisioners.ErrUserActionRequired)
			require.NotErrorIs(t, err, provisioners.ErrYield)

			var perr *provisioners.Error

			require.ErrorAs(t, err, &perr)
			assert.Equal(t, c.message, perr.Message())

			require.NotNil(t, server.Status.Rebuild)
			assert.True(t, server.Status.Rebuild.Parked)
		})
	}
}

// New user intent releases the park with the marker, and requeues: the spec
// edit that woke this pass is spent, so nothing else would enqueue the arm.
func TestRebuildUnparkClearsMarkerAndRequeues(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock.NewMockServerInterface(ctrl)

	server := serverWithRebuildMarker(t, true)
	server.Status.Rebuild.Parked = true
	server.Spec.Image.ID = idstest.MustParseImageID(rebuildImageOther)

	_, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
		openstackServerAt(rebuildImagePre, ""), nil)

	require.ErrorIs(t, err, provisioners.ErrYield)
	assert.Nil(t, server.Status.Rebuild)
}

// With no desired image there is nothing to converge toward, so no attempt can
// be outstanding.
func TestRebuildWithoutDesiredImageRetiresMarker(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock.NewMockServerInterface(ctrl)

	server := serverWithRebuildMarker(t, true)
	server.Spec.Image = nil

	_, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
		openstackServerAt(rebuildImagePre, ""), nil)

	require.NoError(t, err)
	assert.Nil(t, server.Status.Rebuild)
}

// An unreadable provider image ref decides nothing: it must never read as a
// difference to act on.
func TestRebuildUnreadableProviderImageActsOnNothing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		image map[string]any
	}{
		{"absent", nil},
		{"empty", map[string]any{"id": ""}},
		{"not a string", map[string]any{"id": 42}},
		{"unparseable", map[string]any{"id": "not-a-uuid"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			client := mock.NewMockServerInterface(ctrl)

			server := serverWantingTargetImage()

			openstackServer := openstackServerAt(rebuildImagePre, "")
			openstackServer.Image = c.image

			_, err := openstack.ReconcileServerRebuild(t.Context(), client, server,
				openstackServer, nil)

			require.NoError(t, err)
			assert.Nil(t, server.Status.Rebuild)
		})
	}
}
