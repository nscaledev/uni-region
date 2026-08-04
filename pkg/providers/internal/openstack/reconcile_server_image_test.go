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

// TestReconcileServerImageConvergedErrorIsObserved pins that an ERROR on the desired
// image completes: it is indistinguishable from an unrelated host failure, so the
// monitor's observation owns it.
func TestReconcileServerImageConvergedErrorIsObserved(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", rebuildNewImageID))
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

// TestReconcileServerImageUnreadableImageYields pins that an unverifiable image ref
// never reports success.
func TestReconcileServerImageUnreadableImageYields(t *testing.T) {
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
			require.ErrorIs(t, err, provisioners.ErrYield)
			requireNoReconcilerStamp(t, server)
		})
	}
}

// TestReconcileServerImageNoDesiredImageIsDone pins the no-desired-image row.
func TestReconcileServerImageNoDesiredImageIsDone(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := &unikornv1.Server{}

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.NoError(t, err)
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

// TestReconcileServerImageRejectionSurfaces pins that a non-409 rejection surfaces
// as an error rather than a yield. Nothing is left for a later poll to observe.
func TestReconcileServerImageRejectionSurfaces(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(nil, gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusBadRequest})

	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.Error(t, err)
	require.NotErrorIs(t, err, provisioners.ErrYield)
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
