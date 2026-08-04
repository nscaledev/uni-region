/*
Copyright 2025 the Unikorn Authors.
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
	"net/http"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack/mock"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// requireRebuildAcceptedStamp asserts the fixed in-flight view for an accepted
// rebuild: Active Rebuilding and health Unknown, matching the monitor's REBUILD
// derivation so the two writers agree.
func requireRebuildAcceptedStamp(t *testing.T, server *unikornv1.Server) {
	t.Helper()

	active, err := server.StatusConditionRead(unikornv1core.ConditionActive)
	require.NoError(t, err)
	require.Equal(t, metav1.ConditionFalse, active.Status)
	require.Equal(t, string(unikornv1.ActiveConditionReasonRebuilding), active.Reason)

	health, err := server.StatusConditionRead(unikornv1core.ConditionHealthy)
	require.NoError(t, err)
	require.Equal(t, metav1.ConditionUnknown, health.Status)
	require.Equal(t, string(unikornv1core.ConditionReasonUnknown), health.Reason)
}

// requireNoReconcilerStamp asserts the pass left both monitor-owned conditions
// alone. Every row except an accepted rebuild must.
func requireNoReconcilerStamp(t *testing.T, server *unikornv1.Server) {
	t.Helper()

	_, activeErr := server.StatusConditionRead(unikornv1core.ConditionActive)
	require.Error(t, activeErr, "this pass must not write a synthetic Active lifecycle condition")

	_, healthErr := server.StatusConditionRead(unikornv1core.ConditionHealthy)
	require.Error(t, healthErr, "this pass must not write the monitor-owned Healthy condition")
}

const (
	rebuildOldImageID = "11111111-1111-4111-a111-111111111111"
	rebuildNewImageID = "22222222-2222-4222-a222-222222222222"
)

// Nova's rebuild_states family, plus one task state that is deliberately not a
// rebuild.
const (
	taskStateRebuilding                = "rebuilding"
	taskStateRebuildBlockDeviceMapping = "rebuild_block_device_mapping"
	taskStateRebuildSpawning           = "rebuild_spawning"
	taskStateRebooting                 = "rebooting"
)

// desiredRebuildServer is a CR wanting the new image, with no status latch.
func desiredRebuildServer() *unikornv1.Server {
	return &unikornv1.Server{
		Spec: unikornv1.ServerSpec{
			Image: &unikornv1.ServerImage{ID: idstest.MustParseImageID(rebuildNewImageID)},
		},
	}
}

// novaRebuildServer is a launched server, which the submission gate requires.
func novaRebuildServer(status, imageID string) *servers.Server {
	return &servers.Server{
		ID:         "server-1",
		Status:     status,
		Image:      map[string]any{"id": imageID},
		LaunchedAt: time.Now().Add(-time.Hour),
	}
}

// novaUnlaunchedServer is a never-booted server, so an image change must defer.
func novaUnlaunchedServer(status, imageID string) *servers.Server {
	server := novaRebuildServer(status, imageID)
	server.LaunchedAt = time.Time{}

	return server
}

// novaRebuildServerTask is a launched server with a task in flight.
func novaRebuildServerTask(status, imageID, taskState string) *servers.Server {
	server := novaRebuildServer(status, imageID)
	server.TaskState = taskState

	return server
}

func rebuildOptions() openstack.ServerRebuildOptions {
	return openstack.ServerRebuildOptions{ImageID: idstest.MustParseImageID(rebuildNewImageID)}
}

// TestReconcileServerImageSubmitsOnFirstPass pins that a quiescent server whose
// ref has not moved is rebuilt in the pass that notices, with no arming yield.
func TestReconcileServerImageSubmitsOnFirstPass(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.ErrorIs(t, err, provisioners.ErrYield, "an accepted rebuild is in flight, so the pass must not report the server settled")
	require.Nil(t, server.Status.Rebuild, "the fresh-read design persists no rebuild marker")
	requireRebuildAcceptedStamp(t, server)
}

// TestReconcileServerImageSubmitsRebuildFromErrorStatus pins the recovery path for
// a parked server whose spec image moved: R4″ must fire from ERROR just as it does
// from ACTIVE. The server is launched and quiescent (no task in flight), and its ref
// has diverged from the spec image, so the one destructive row submits the corrective
// rebuild toward the desired image. A defensive "if ERROR then yield" guard added
// above this row would wedge every parked server forever — the spec edit that moves
// the image is exactly the un-park trigger, and yielding here would strand it.
func TestReconcileServerImageSubmitsRebuildFromErrorStatus(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", rebuildOldImageID))
	require.ErrorIs(t, err, provisioners.ErrYield, "an accepted rebuild is in flight, so the pass must not report the server settled")
	requireRebuildAcceptedStamp(t, server)
}

// TestReconcileServerImageDoesNotResubmitWhileRebuilding is the no-double-wipe
// guard: a rebuild task on the desired ref must yield, never submit again.
func TestReconcileServerImageDoesNotResubmitWhileRebuilding(t *testing.T) {
	t.Parallel()

	// Every member of Nova's rebuild_states family, plus the REBUILD status Nova
	// projects from them.
	for _, taskState := range []string{taskStateRebuilding, taskStateRebuildBlockDeviceMapping, taskStateRebuildSpawning} {
		t.Run(taskState, func(t *testing.T) {
			t.Parallel()

			// No RebuildServer expectation: any call fails the test.
			client := mock.NewMockServerInterface(gomock.NewController(t))
			server := desiredRebuildServer()

			_, err := openstack.ReconcileServerImage(t.Context(), client, server,
				novaRebuildServerTask("REBUILD", rebuildNewImageID, taskState))
			require.ErrorIs(t, err, provisioners.ErrYield)
			requireRebuildAcceptedStamp(t, server)
		})
	}
}

// TestReconcileServerImageUnknownRebuildSubstateIsInFlight pins the prefix
// match: a rebuild substate this code has never heard of, presented without the
// projected REBUILD status, must still read as in flight — the alternative is
// reporting the server settled while its root disk is being rewritten.
func TestReconcileServerImageUnknownRebuildSubstateIsInFlight(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server,
		novaRebuildServerTask("ACTIVE", rebuildNewImageID, "rebuild_guest_reimage"))
	require.ErrorIs(t, err, provisioners.ErrYield)
	requireRebuildAcceptedStamp(t, server)
}

// TestReconcileServerImageConvergedIsDone pins the settled row.
func TestReconcileServerImageConvergedIsDone(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildNewImageID))
	require.NoError(t, err)
	requireNoReconcilerStamp(t, server)
}

// TestReconcileServerImageConvergedErrorParks pins that a quiesced ERROR on the
// desired image parks as user-action-required: the ref moves at accept, not on
// a successful write, so this state cannot certify the spec image was realized
// and must not read as provisioned (INST-1235). The message is ours, cause-neutral
// and actionable — it diagnoses nothing (the row also catches e.g. a failed
// live-migration with the guest still running) and never carries Nova's fault
// vocabulary.
func TestReconcileServerImageConvergedErrorParks(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", rebuildNewImageID))
	require.Error(t, err)
	require.True(t, provisioners.IsTerminal(err), "a failed rebuild must park, not retry or settle")
	require.ErrorIs(t, err, provisioners.ErrUserActionRequired,
		"the advertised remedy is a spec edit, so the park must carry the user-fixable disposition, not the operator-only ErrTerminal")
	require.ErrorContains(t, err, "the provider reports the server in an error state; select another image or replace the server")
	requireNoReconcilerStamp(t, server)
}

// TestReconcileServerImageConvergedErrorBeforeLaunchIsCreateRetrys pins the guard:
// an ERROR on the desired image before first boot is a failed create, which the
// provisioner's bounded retry machinery owns. This pass must complete without a
// park so that machinery is reached.
func TestReconcileServerImageConvergedErrorBeforeLaunchIsCreateRetrys(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaUnlaunchedServer("ERROR", rebuildNewImageID))
	require.NoError(t, err)
	requireNoReconcilerStamp(t, server)
}

// TestReconcileServerImageConvergedForeignTaskIsNotARebuild pins that a non-rebuild
// task on a converged server is not reported as rebuilding.
func TestReconcileServerImageConvergedForeignTaskIsNotARebuild(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server,
		novaRebuildServerTask("ACTIVE", rebuildNewImageID, taskStateRebooting))
	require.NoError(t, err)
	requireNoReconcilerStamp(t, server)
}

// TestReconcileServerImageForeignTaskDefersSubmission pins that a pending image
// change waits for quiescence, since Nova requires a NULL task_state.
func TestReconcileServerImageForeignTaskDefersSubmission(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server,
		novaRebuildServerTask("ACTIVE", rebuildOldImageID, taskStateRebooting))
	require.ErrorIs(t, err, provisioners.ErrYield)
	requireNoReconcilerStamp(t, server)
}

// TestReconcileServerImageDefersUntilFirstLaunch pins that a never-booted server is
// create-retry's to own.
func TestReconcileServerImageDefersUntilFirstLaunch(t *testing.T) {
	t.Parallel()

	for name, openstackServer := range map[string]*servers.Server{
		"building": novaUnlaunchedServer("BUILD", rebuildOldImageID),
		"errored":  novaUnlaunchedServer("ERROR", rebuildOldImageID),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := mock.NewMockServerInterface(gomock.NewController(t))
			server := desiredRebuildServer()

			_, err := openstack.ReconcileServerImage(t.Context(), client, server, openstackServer)
			require.ErrorIs(t, err, provisioners.ErrYield)
			requireNoReconcilerStamp(t, server)
		})
	}
}

// TestReconcileServerImageUnreadableImageParks pins that an unverifiable image ref
// never reports success and parks as user-action-required: the ref is the only proof
// the spec image was realized, so an unreadable one cannot certify convergence. The
// park is re-derived per pass, so a later readable ref un-parks it without any spec
// change. The message is ours and cause-neutral.
func TestReconcileServerImageUnreadableImageParks(t *testing.T) {
	t.Parallel()

	for name, image := range map[string]map[string]any{
		"absent":      nil,
		"empty":       {"id": ""},
		"unparseable": {"id": "not-a-uuid"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := mock.NewMockServerInterface(gomock.NewController(t))
			server := desiredRebuildServer()

			openstackServer := novaRebuildServer("ACTIVE", rebuildOldImageID)
			openstackServer.Image = image

			_, err := openstack.ReconcileServerImage(t.Context(), client, server, openstackServer)
			require.Error(t, err)
			require.True(t, provisioners.IsTerminal(err), "an unreadable image ref must park, not retry or settle")
			require.ErrorIs(t, err, provisioners.ErrUserActionRequired,
				"the only remedy is a spec edit or replacement, so the park must carry the user-fixable disposition")
			require.ErrorContains(t, err, "the provider cannot report the server's image, so the desired image cannot be verified; replace the server")
			requireNoReconcilerStamp(t, server)
		})
	}
}

// TestReconcileServerImageNoDesiredImageParks pins the no-desired-image row: a
// server with no spec image must not complete, because completing would report it
// provisioned onto no image at all. The only remedy is a spec edit, which is the
// park contract.
func TestReconcileServerImageNoDesiredImageParks(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := &unikornv1.Server{}

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.Error(t, err)
	require.True(t, provisioners.IsTerminal(err), "a server with no spec image must park, not complete")
	require.ErrorIs(t, err, provisioners.ErrUserActionRequired,
		"the only remedy is a spec edit, so the park must carry the user-fixable disposition")
	require.ErrorContains(t, err, "the server specifies no image to converge onto; set an image in the specification")
	requireNoReconcilerStamp(t, server)
}

// TestReconcileServerImageConflictYieldsSilently pins the pre-acceptance path: a
// 409 leaves the server untouched, so the pass yields and writes no status.
func TestReconcileServerImageConflictYieldsSilently(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(nil, gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusConflict})

	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.ErrorIs(t, err, provisioners.ErrYield)
	requireNoReconcilerStamp(t, server)
}

// TestReconcileServerImageRejectionSurfaces pins that a rejection which may heal
// without a spec edit (a 5xx here, but equally a 403: quota freeing bumps no
// generation, and, since the park narrowed to the image-not-found signature,
// any unrecognized 400) surfaces as a plain retried error — never a yield, and
// never a park, which would strand the server. Nothing is left for a later
// poll to observe.
func TestReconcileServerImageRejectionSurfaces(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(nil, gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusInternalServerError})

	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.Error(t, err)
	require.NotErrorIs(t, err, provisioners.ErrYield)
	require.NotErrorIs(t, err, provisioners.ErrUserActionRequired,
		"a 5xx can heal without a generation bump, so parking it would strand the server")
	require.False(t, provisioners.IsTerminal(err))
	requireNoReconcilerStamp(t, server)
}

// TestReconcileServerImageRetiresStaleMarker pins the upgrade migration: a server
// carrying a marker from the state-machine design has it cleared, so nothing is left
// that RebuildPending would report as provisioning forever.
func TestReconcileServerImageRetiresStaleMarker(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{
		TargetImageID: idstest.MustParseImageID(rebuildNewImageID),
		State:         unikornv1.ServerRebuildStateRebuilding,
	}

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildNewImageID))
	require.NoError(t, err)
	require.Nil(t, server.Status.Rebuild)
}

// TestReconcileServerImageNotFoundBadRequestParks pins that Nova's synchronous
// image-not-found rejection — and only that 400 — parks as
// user-action-required: the image is gone, no retry can resolve it, and the
// remedy is a spec edit whose generation bump un-parks it. The match is on
// Nova's fixed rejection message in the response body; the surfaced message is
// ours, never Nova's.
func TestReconcileServerImageNotFoundBadRequestParks(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(nil, gophercloud.ErrUnexpectedResponseCode{
			Actual: http.StatusBadRequest,
			Body:   []byte(`{"badRequest": {"code": 400, "message": "Cannot find image for rebuild"}}`),
		})

	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.ErrorIs(t, err, provisioners.ErrUserActionRequired)
	require.ErrorContains(t, err, "the desired image no longer exists at the provider; select a different image or replace the server")
	requireNoReconcilerStamp(t, server)
}

// TestReconcileServerImageOtherBadRequestRetries pins the narrowing's fail-safe
// half: a 400 whose body does not carry Nova's image-not-found signature
// surfaces as a plain retried error — never a park. ImageNotActive is the
// motivating case: an operator reactivating a deactivated Glance image bumps
// no generation and moves no observed field, so a park would have no recovery
// path, while a retry converges on the pass after reactivation with no spec
// edit. A stripped or reworded body degrades the same safe way.
func TestReconcileServerImageOtherBadRequestRetries(t *testing.T) {
	t.Parallel()

	testCases := map[string][]byte{
		"deactivated image":    []byte(`{"badRequest": {"code": 400, "message": "Image 22222222-2222-4222-a222-222222222222 is not active."}}`),
		"min_disk over flavor": []byte(`{"badRequest": {"code": 400, "message": "Flavor's disk is too small for requested image."}}`),
		"empty body":           nil,
	}

	for name, body := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := mock.NewMockServerInterface(gomock.NewController(t))
			client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
				Return(nil, gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusBadRequest, Body: body})

			server := desiredRebuildServer()

			_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
			require.Error(t, err)
			require.NotErrorIs(t, err, provisioners.ErrYield)
			require.NotErrorIs(t, err, provisioners.ErrUserActionRequired,
				"an unrecognized 400 may be operator-recoverable without a generation bump, so parking it would strand the server")
			require.False(t, provisioners.IsTerminal(err))
			requireNoReconcilerStamp(t, server)
		})
	}
}

// TestReconcileServerImageAcceptedStampIgnoresResponseBody pins that the accepted
// stamp is fixed: a 202 body can still describe the server as ACTIVE.
func TestReconcileServerImageAcceptedStampIgnoresResponseBody(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(novaRebuildServer("ACTIVE", rebuildOldImageID), nil)

	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.ErrorIs(t, err, provisioners.ErrYield)
	requireRebuildAcceptedStamp(t, server)
}

// TestReconcileServerRebuildOmitsGuestConfiguration pins that the rebuild carries
// only the image; Nova preserves guest configuration on an omitted field.
func TestReconcileServerRebuildOmitsGuestConfiguration(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Spec.UserData = []byte("#cloud-config\nusers: []\n")
	client.EXPECT().GetServer(gomock.Any(), server).
		Return(novaRebuildServer("ACTIVE", rebuildOldImageID), nil)
	// Only the image reaches Nova, even with user data set and a keypair in play.
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	_, err := openstack.ReconcileServer(t.Context(), nil, client, server, nil, "identity-keypair")
	require.ErrorIs(t, err, provisioners.ErrYield)
	requireRebuildAcceptedStamp(t, server)
}

// TestCreateServerCopiesFullStatusBackForAugmentedServers pins that the caller sees
// the full post-reconcile status when augmentation forces a deep copy.
func TestCreateServerCopiesFullStatusBackForAugmentedServers(t *testing.T) {
	t.Parallel()

	server := desiredRebuildServer()

	options := &types.ServerCreateOptions{UserData: []byte("#cloud-config\nssh_authorized_keys: []\n")}
	require.NotSame(t, server, openstack.ServerForCreate(server, options), "test setup requires user-data augmentation to force a deep copy")

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().GetServer(gomock.Any(), gomock.Any()).Return(novaRebuildServer("ACTIVE", rebuildOldImageID), nil)
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	err := openstack.ReconcileServerForCreate(t.Context(), nil, client, server, options, nil, "")
	require.ErrorIs(t, err, provisioners.ErrYield)

	requireRebuildAcceptedStamp(t, server)
}
