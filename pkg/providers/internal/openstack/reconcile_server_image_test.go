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
	"context"
	"maps"
	"net/http"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack/mock"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// requireRebuildAcceptedStamp asserts the fixed in-flight view for an accepted
// rebuild: Active Rebuilding and health Unknown, matching the projection's
// REBUILD derivation.
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

// requireTypedYield asserts a yielding row carries a reason and message. A bare
// sentinel leaves the manager nothing to lift onto the Available condition, so
// the row a server is parked on would be unobservable from the API.
//
// The reason is a parameter, not a constant: it is API surface that callers
// script against, so each row has to state the one it means rather than inherit
// whatever the helper happened to hard-code.
func requireTypedYield(t *testing.T, err error, message string) {
	t.Helper()

	require.ErrorIs(t, err, provisioners.ErrYield)

	var perr *provisioners.Error

	require.ErrorAs(t, err, &perr, "a yield must be typed so the condition can name the wait")
	require.Equal(t, unikornv1core.ConditionReasonProvisioning, perr.Reason())
	require.Contains(t, perr.Message(), message, "the condition message must say which row we are on")
}

// requireNoImageRowStamp asserts the image rows themselves write no conditions.
// Only an accepted rebuild does. The surrounding pass projects Active and
// Healthy from its own read either way, which is why these tests call
// reconcileServerImage directly rather than through reconcileServer.
func requireNoImageRowStamp(t *testing.T, server *unikornv1.Server) {
	t.Helper()

	_, activeErr := server.StatusConditionRead(unikornv1core.ConditionActive)
	require.Error(t, activeErr, "the image rows must not synthesise a lifecycle condition")

	_, healthErr := server.StatusConditionRead(unikornv1core.ConditionHealthy)
	require.Error(t, healthErr, "the image rows must not write health")
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
// It carries the user-data record of desiredRebuildServer.
func novaRebuildServer(status, imageID string) *servers.Server {
	return &servers.Server{
		ID:         "server-1",
		Status:     status,
		Image:      map[string]any{"id": imageID},
		LaunchedAt: time.Now().Add(-time.Hour),
		Metadata:   rebuildMetadata(nil),
	}
}

// withUserDataHash replaces the server's user-data record; "" removes it.
func withUserDataHash(server *servers.Server, hash string) *servers.Server {
	server.Metadata = map[string]string{}
	if hash != "" {
		server.Metadata["region:system:user_data_hash"] = hash
	}

	return server
}

// withUserDataGeneration adds the generation written with the record; "" adds
// nothing.
func withUserDataGeneration(server *servers.Server, generation string) *servers.Server {
	if generation != "" {
		server.Metadata["region:system:user_data_generation"] = generation
	}

	return server
}

// withUserDataBaseline adds a baseline record, as "<digest>/<generation it
// supersedes>"; "" adds nothing.
func withUserDataBaseline(server *servers.Server, baseline string) *servers.Server {
	if baseline != "" {
		server.Metadata["region:system:user_data_baseline_hash"] = baseline
	}

	return server
}

// requireUserDataRecorded asserts whether the pass told the provisioner that
// Nova holds the record.
func requireUserDataRecorded(t *testing.T, server *unikornv1.Server, recorded bool) {
	t.Helper()

	require.Equal(t, recorded, server.UserDataRecorded())
}

// requireUserDataRecordCurrent asserts whether the condition says Nova's
// record holds the current spec's user data, as the rollout check reads it.
func requireUserDataRecordCurrent(t *testing.T, server *unikornv1.Server, current bool) {
	t.Helper()

	condition := meta.FindStatusCondition(server.Status.Conditions, "UserDataRecorded")
	require.Equal(t, current, condition != nil && condition.Status == metav1.ConditionTrue && condition.ObservedGeneration == server.Generation)
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
	options := rebuildOptionsFor(nil)
	options.UseUserData = false

	return options
}

// rebuildOptionsFor is the rebuild of a server whose only Nova metadata is the
// user-data record.
func rebuildOptionsFor(userData []byte) openstack.ServerRebuildOptions {
	return openstack.ServerRebuildOptions{
		ImageID:     idstest.MustParseImageID(rebuildNewImageID),
		UserData:    userData,
		UseUserData: true,
		Metadata:    rebuildMetadata(userData),
	}
}

// rebuildMetadata is the Nova record of the customer user data a rebuild
// submits for a Server at generation 0. The keys are spelled out because they
// are persisted in Nova.
func rebuildMetadata(customerUserData []byte) map[string]string {
	return map[string]string{
		"region:system:user_data_hash":       types.UserDataHash(customerUserData),
		"region:system:user_data_generation": "0",
	}
}

// TestReconcileServerImageSubmitsOnFirstPass pins that a quiescent server whose
// ref has not moved is rebuilt in the pass that notices, with no arming yield.
func TestReconcileServerImageSubmitsOnFirstPass(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	server := desiredRebuildServer()

	err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.ErrorIs(t, err, provisioners.ErrYield, "an accepted rebuild is in flight, so the pass must not report the server settled")
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

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	server := desiredRebuildServer()

	err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", rebuildOldImageID))
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
			client := mock.NewMockServerObservationInterface(gomock.NewController(t))
			server := desiredRebuildServer()

			err := openstack.ReconcileServerImage(t.Context(), client, server,
				novaRebuildServerTask("REBUILD", rebuildNewImageID, taskState))
			requireTypedYield(t, err, "applying the requested changes")
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

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	err := openstack.ReconcileServerImage(t.Context(), client, server,
		novaRebuildServerTask("ACTIVE", rebuildNewImageID, "rebuild_guest_reimage"))
	require.ErrorIs(t, err, provisioners.ErrYield)
	requireRebuildAcceptedStamp(t, server)
}

// TestReconcileServerImageConvergedIsDone pins the settled row.
func TestReconcileServerImageConvergedIsDone(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildNewImageID))
	require.NoError(t, err)
	requireNoImageRowStamp(t, server)
}

// TestReconcileServerImageConvergedErrorRechecks pins that a quiesced ERROR on
// the desired image is reported and rechecked: the ref moves at accept, not on a
// successful write, so this state cannot certify the spec image was realized and
// must not read as provisioned (INST-1235). It must not park either: the
// provider can recover the server on its own, and a parked server would report
// the error until a spec edit. The message is ours, cause-neutral and actionable
// — it diagnoses nothing (the row also catches e.g. a failed live-migration with
// the guest still running) and never carries Nova's fault vocabulary.
func TestReconcileServerImageConvergedErrorRechecks(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", rebuildNewImageID))
	require.Error(t, err)
	require.ErrorIs(t, err, provisioners.ErrRecheck, "a quiesced error must be looked at again, not settled")
	require.False(t, provisioners.IsTerminal(err), "a provider recovery must clear it without a spec edit")
	require.ErrorContains(t, err, "the provider reports the server in an error state")
	requireNoImageRowStamp(t, server)
}

// TestReconcileServerImageConvergedErrorBeforeLaunchIsCreateRetrys pins the guard:
// an ERROR on the desired image before first boot is a failed create, which the
// provisioner's bounded retry machinery handles before calling the provider.
// A recorded server completes here without a park.
func TestReconcileServerImageConvergedErrorBeforeLaunchIsCreateRetrys(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	err := openstack.ReconcileServerImage(t.Context(), client, server, novaUnlaunchedServer("ERROR", rebuildNewImageID))
	require.NoError(t, err)
	requireNoImageRowStamp(t, server)
}

// TestReconcileServerImageConvergedForeignTaskIsNotARebuild pins that a non-rebuild
// task on a converged server is not reported as rebuilding.
func TestReconcileServerImageConvergedForeignTaskIsNotARebuild(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	err := openstack.ReconcileServerImage(t.Context(), client, server,
		novaRebuildServerTask("ACTIVE", rebuildNewImageID, taskStateRebooting))
	require.NoError(t, err)
	requireNoImageRowStamp(t, server)
}

// TestReconcileServerImageForeignTaskDefersSubmission pins that a pending image
// change waits for quiescence, since Nova requires a NULL task_state.
func TestReconcileServerImageForeignTaskDefersSubmission(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	err := openstack.ReconcileServerImage(t.Context(), client, server,
		novaRebuildServerTask("ACTIVE", rebuildOldImageID, taskStateRebooting))
	requireTypedYield(t, err, "another operation is in progress on the server")
	requireNoImageRowStamp(t, server)
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

			client := mock.NewMockServerObservationInterface(gomock.NewController(t))
			server := desiredRebuildServer()

			err := openstack.ReconcileServerImage(t.Context(), client, server, openstackServer)
			requireTypedYield(t, err, "once the server has booted")
			requireNoImageRowStamp(t, server)
		})
	}
}

// TestReconcileServerImageUnreadableImageRechecks pins that an unverifiable image
// ref never reports success: the ref is the only proof the spec image was
// realized, so an unreadable one cannot certify convergence. It is rechecked, not
// parked, so a later readable ref clears it without any spec change. The message
// is ours and cause-neutral.
func TestReconcileServerImageUnreadableImageRechecks(t *testing.T) {
	t.Parallel()

	for name, image := range map[string]map[string]any{
		"absent":      nil,
		"empty":       {"id": ""},
		"unparseable": {"id": "not-a-uuid"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := mock.NewMockServerObservationInterface(gomock.NewController(t))
			server := desiredRebuildServer()

			openstackServer := novaRebuildServer("ACTIVE", rebuildOldImageID)
			openstackServer.Image = image

			err := openstack.ReconcileServerImage(t.Context(), client, server, openstackServer)
			require.Error(t, err)
			require.ErrorIs(t, err, provisioners.ErrRecheck, "an unreadable image ref must be looked at again, not settled")
			require.False(t, provisioners.IsTerminal(err), "a later readable ref must clear it without a spec edit")
			require.ErrorContains(t, err, "the provider cannot report the server's image, so the desired image cannot be verified")
			requireNoImageRowStamp(t, server)
		})
	}
}

// TestReconcileServerImageNoDesiredImageParks pins the no-desired-image row: a
// server with no spec image must not complete, because completing would report it
// provisioned onto no image at all. The only remedy is a spec edit, which is the
// park contract.
func TestReconcileServerImageNoDesiredImageParks(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	server := &unikornv1.Server{}

	err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.Error(t, err)
	require.True(t, provisioners.IsTerminal(err), "a server with no spec image must park, not complete")
	require.ErrorIs(t, err, provisioners.ErrUserActionRequired,
		"the only remedy is a spec edit, so the park must carry the user-fixable disposition")
	require.ErrorContains(t, err, "the server specifies no image to converge onto; set an image in the specification")
	requireNoImageRowStamp(t, server)
}

// TestReconcileServerImageConflictRechecks pins the pre-acceptance path: a 409
// leaves the server untouched, so the pass writes no status, and the condition
// names the wait.  It is a recheck, not a yield: a locked server also answers
// 409 and is not moving, and if an operation really is running the next poll
// sees it and yields as R4' does, hence the same wording.
func TestReconcileServerImageConflictRechecks(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(nil, gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusConflict})

	server := desiredRebuildServer()

	err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	requireTypedRecheck(t, err, unikornv1core.ConditionReasonProvisioning, "another operation is in progress on the server")
	requireNoImageRowStamp(t, server)
}

// TestReconcileServerImageRejectionSurfaces pins that a rejection which may heal
// without a spec edit (a 5xx here, but equally a 403: quota freeing bumps no
// generation, and, since the park narrowed to the image-not-found signature,
// any unrecognized 400) surfaces as a plain retried error — never a yield, and
// never a park, which would strand the server. Nothing is left for a later
// poll to observe.
func TestReconcileServerImageRejectionSurfaces(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(nil, gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusInternalServerError})

	server := desiredRebuildServer()

	err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.Error(t, err)
	require.NotErrorIs(t, err, provisioners.ErrYield)
	require.NotErrorIs(t, err, provisioners.ErrUserActionRequired,
		"a 5xx can heal without a generation bump, so parking it would strand the server")
	require.False(t, provisioners.IsTerminal(err))
	requireNoImageRowStamp(t, server)
}

// TestReconcileServerImageNotFoundBadRequestRechecks pins that Nova's
// synchronous image-not-found rejection — and only that 400 — is a wait for the
// image: the spec still asks for it, so if it comes back the next poll applies
// it, and a spec edit can name another.  The match is on Nova's fixed rejection
// message in the response body; the surfaced message is ours, never Nova's.
func TestReconcileServerImageNotFoundBadRequestRechecks(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(nil, gophercloud.ErrUnexpectedResponseCode{
			Actual: http.StatusBadRequest,
			Body:   []byte(`{"badRequest": {"code": 400, "message": "Cannot find image for rebuild"}}`),
		})

	server := desiredRebuildServer()

	err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	requireTypedRecheck(t, err, unikornv1core.ConditionReasonErrored, imageUnavailableMessage)
	requireNoImageRowStamp(t, server)
}

// imageUnavailableMessage is what a server waiting on a missing image reports.
const imageUnavailableMessage = "the requested image is not available at the provider; it will be applied when it is, or select a different image"

// requireTypedRecheck asserts a row waits for the next poll and names the wait.
func requireTypedRecheck(t *testing.T, err error, reason unikornv1core.ProvisioningConditionReason, message string) {
	t.Helper()

	require.ErrorIs(t, err, provisioners.ErrRecheck)

	var perr *provisioners.Error

	require.ErrorAs(t, err, &perr)
	require.Equal(t, reason, perr.Reason())
	require.Contains(t, perr.Message(), message)
}

// TestReconcileServerImageSubmitLogsAtInfo pins that every submitted rebuild is
// logged where an operator sees it.  A rebuild wipes the disk, and under polling
// one can start with no spec edit, when an image comes back or a change made in
// the cloud is undone.
func TestReconcileServerImageSubmitLogsAtInfo(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).Return(&servers.Server{}, nil)

	sink := &infoSink{}
	ctx := logr.NewContext(t.Context(), logr.New(sink))

	_ = openstack.ReconcileServerImage(ctx, client, desiredRebuildServer(), novaRebuildServer("ACTIVE", rebuildOldImageID))

	require.Contains(t, sink.messages, "submitting server rebuild")
}

// infoSink is a logr.LogSink that records V(0) Info messages.
type infoSink struct {
	messages []string
}

func (s *infoSink) Init(logr.RuntimeInfo)          {}
func (s *infoSink) Enabled(level int) bool         { return level == 0 }
func (s *infoSink) Error(error, string, ...any)    {}
func (s *infoSink) WithValues(...any) logr.LogSink { return s }
func (s *infoSink) WithName(string) logr.LogSink   { return s }

func (s *infoSink) Info(_ int, message string, _ ...any) {
	s.messages = append(s.messages, message)
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

			client := mock.NewMockServerObservationInterface(gomock.NewController(t))
			client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
				Return(nil, gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusBadRequest, Body: body})

			server := desiredRebuildServer()

			err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
			require.Error(t, err)
			require.NotErrorIs(t, err, provisioners.ErrYield)
			require.NotErrorIs(t, err, provisioners.ErrUserActionRequired,
				"an unrecognized 400 may be operator-recoverable without a generation bump, so parking it would strand the server")
			require.False(t, provisioners.IsTerminal(err))
			requireNoImageRowStamp(t, server)
		})
	}
}

// TestReconcileServerImageAcceptedStampIgnoresResponseBody pins that the accepted
// stamp is fixed: a 202 body can still describe the server as ACTIVE.
func TestReconcileServerImageAcceptedStampIgnoresResponseBody(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(novaRebuildServer("ACTIVE", rebuildOldImageID), nil)

	server := desiredRebuildServer()

	err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.ErrorIs(t, err, provisioners.ErrYield)
	requireRebuildAcceptedStamp(t, server)
}

// observeAndConverge runs the found-server half of a pass in the order the pass
// runs it: the read and its projection, then the image rows. The order itself
// is pinned through the real pass by TestCreateServerObservesFirst.
func observeAndConverge(t *testing.T, p *openstack.Provider, client *mock.MockServerObservationInterface, server *unikornv1.Server) error {
	t.Helper()

	observed, err := openstack.ObserveServer(t.Context(), p, client, identityFixture(), server)
	require.NoError(t, err)

	return openstack.ReconcileServerImage(t.Context(), client, server, observed)
}

func TestReconcileServerRebuildRecordsUserData(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Spec.UserData = []byte("#cloud-config\nusers: []\n")
	client.EXPECT().GetServer(gomock.Any(), server).
		Return(novaRebuildServer("ACTIVE", rebuildOldImageID), nil)
	// The digest is spelled out because Nova persists it.
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", openstack.ServerRebuildOptions{
		ImageID:     idstest.MustParseImageID(rebuildNewImageID),
		UserData:    server.Spec.UserData,
		UseUserData: true,
		Metadata: map[string]string{
			"region:system:user_data_hash":       "a8cc7f5ccfcf822d62581acaa581743e4396c6487b0048fddbdc0233d2892fd2",
			"region:system:user_data_generation": "0",
		},
	}).Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

	err := observeAndConverge(t, p, client, server)
	require.ErrorIs(t, err, provisioners.ErrYield)
	requireRebuildAcceptedStamp(t, server)
}

// TestCreateServerCopiesFullStatusBackForAugmentedServers pins that the caller sees
// the full post-create status when augmentation forces a deep copy. Only a create
// takes the copy: an existing server's rows run on the server itself.
func TestCreateServerCopiesFullStatusBackForAugmentedServers(t *testing.T) {
	t.Parallel()

	server := desiredRebuildServer()
	server.Spec.UserData = []byte("#cloud-config\nusers: []\n")

	options := &types.ServerCreateOptions{UserData: []byte("#cloud-config\nssh_authorized_keys: []\n")}
	require.NotSame(t, server, openstack.ServerForCreate(server, options), "test setup requires user-data augmentation to force a deep copy")

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	client.EXPECT().CreateServer(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(novaRebuildServer("BUILD", rebuildNewImageID), nil)

	p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

	require.NoError(t, openstack.ReconcileServerForCreate(t.Context(), p, client, server, options, &ports.Port{ID: "port-1"}, ""))

	active, err := server.StatusConditionRead(unikornv1core.ConditionActive)
	require.NoError(t, err, "the create's status must reach the caller's server")
	require.Equal(t, string(unikornv1.ActiveConditionReasonBuilding), active.Reason)
}

// TestReconcileServerObservesInThePass pins that a pass holding a successful
// provider read projects it, whatever it then decides about the specification.
// The ProvisionedAt latch is the bounded create-retry guard's input, so a pass
// that skips the projection re-arms delete-and-retry on a booted server.
func TestReconcileServerObservesInThePass(t *testing.T) {
	t.Parallel()

	const observedMAC = "e0:9d:73:86:cc:18"

	network := networkFixture()

	server := desiredRebuildServer()
	server.Spec.Networks = []unikornv1.ServerNetworkSpec{{ID: idstest.MustParseNetworkID(network.Name)}}

	// Converged on the desired image and quiescent, so the image rows write
	// nothing and only the projection can account for the status below.
	observed := novaRebuildServer("ACTIVE", rebuildNewImageID)
	observed.PowerState = servers.RUNNING
	observed.Created = time.Now().Add(-2 * time.Hour)
	observed.Addresses = map[string]any{
		"network-" + network.Name: []any{map[string]any{
			"OS-EXT-IPS:type":         "fixed",
			"addr":                    "7.247.33.145",
			"version":                 float64(4),
			"OS-EXT-IPS-MAC:mac_addr": observedMAC,
		}},
	}

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	client.EXPECT().GetServer(gomock.Any(), server).Return(observed, nil)

	p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

	err := observeAndConverge(t, p, client, server)
	require.NoError(t, err)

	active, err := server.StatusConditionRead(unikornv1core.ConditionActive)
	require.NoError(t, err, "the pass must project the observed lifecycle state")
	require.Equal(t, string(unikornv1.ActiveConditionReasonRunning), active.Reason)

	health, err := server.StatusConditionRead(unikornv1core.ConditionHealthy)
	require.NoError(t, err, "the pass must project the observed health")
	require.Equal(t, metav1.ConditionTrue, health.Status)

	require.NotNil(t, server.Status.ScheduledAt)
	require.NotNil(t, server.Status.LaunchedAt)
	require.NotNil(t, server.Status.ProvisionedAt, "the create-retry guard reads this latch")
	require.Equal(t, observedMAC, ptr.Deref(server.Status.MACAddress, ""), "the MAC is projected by the pass")
}

// TestReconcileServerObservesOnARecheckRow pins the projection on a row that
// does not complete. A recheck or yielding row is where the latch matters most:
// the bounded create-retry guard reads ProvisionedAt, so a pass that skips the
// projection re-arms delete-and-retry on a server that has booted.
func TestReconcileServerObservesOnARecheckRow(t *testing.T) {
	t.Parallel()

	server := desiredRebuildServer()

	// An unreadable image reference: the pass cannot verify the image, so it
	// rechecks (R2) without reaching the converged row.
	observed := novaRebuildServer("ACTIVE", rebuildNewImageID)
	observed.Image = map[string]any{}
	observed.PowerState = servers.RUNNING

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	client.EXPECT().GetServer(gomock.Any(), server).Return(observed, nil)

	p := openstack.NewTestProvider(getClient(t, nil), regionFixture())

	err := observeAndConverge(t, p, client, server)
	require.ErrorIs(t, err, provisioners.ErrRecheck, "an unverifiable image is rechecked")

	require.NotNil(t, server.Status.LaunchedAt, "a recheck pass still projects")
	require.NotNil(t, server.Status.ProvisionedAt, "the create-retry guard reads this latch")
}

// TestReconcileServerObservesBaremetalPhase pins that the pass hands its own
// identity to the Ironic node lookup: without one the privileged client cannot
// be built, and a baremetal server in BUILD loses the Queued refinement.
func TestReconcileServerObservesBaremetalPhase(t *testing.T) {
	t.Parallel()

	const metalFlavorID = "33333333-3333-4333-a333-333333333333"

	server := desiredRebuildServer()
	server.Spec.FlavorID = idstest.MustParseFlavorID(metalFlavorID)

	region := regionFixture()
	region.Spec.Openstack.Compute = &unikornv1.RegionOpenstackComputeSpec{
		Flavors: &unikornv1.OpenstackFlavorsSpec{
			Metadata: []unikornv1.FlavorMetadata{{ID: metalFlavorID, Baremetal: true}},
		},
	}

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	client.EXPECT().GetServer(gomock.Any(), server).
		Return(novaRebuildServer("BUILD", rebuildNewImageID), nil)

	p := openstack.NewTestProvider(getClient(t, nil), region)

	// Ironic is unreachable here, so this pins only that the lookup is attempted
	// with a usable identity: a nil one panics in GetOpenstackIdentity before it
	// can degrade. Which identity is handed over is pinned by
	// TestObserveServerPassesIdentityToIronic.
	err := observeAndConverge(t, p, client, server)
	require.NoError(t, err, "an unreachable Ironic degrades to the VM default rather than failing the pass")

	active, err := server.StatusConditionRead(unikornv1core.ConditionActive)
	require.NoError(t, err)
	require.Equal(t, string(unikornv1.ActiveConditionReasonBuilding), active.Reason)
}

func TestReconcileServerImageRebuildsChangedUserData(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Spec.UserData = []byte("#cloud-config\nusers: []\n")
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptionsFor(server.Spec.UserData)).Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	err := openstack.ReconcileServerImage(t.Context(), client, server, withUserDataHash(novaRebuildServer("ACTIVE", rebuildNewImageID), "old-user-data"))
	require.ErrorIs(t, err, provisioners.ErrYield)
	requireRebuildAcceptedStamp(t, server)

	// The rebuild wrote the new record into Nova.
	err = openstack.ReconcileServerImage(t.Context(), client, server, withUserDataHash(novaRebuildServer("REBUILD", rebuildNewImageID), types.UserDataHash(server.Spec.UserData)))
	requireTypedYield(t, err, "applying the requested changes")
	requireRebuildAcceptedStamp(t, server)

	err = openstack.ReconcileServerImage(t.Context(), client, server, withUserDataHash(novaRebuildServer("ACTIVE", rebuildNewImageID), types.UserDataHash(server.Spec.UserData)))
	require.NoError(t, err, "Nova's user-data record must prevent a second rebuild")
}

// TestReconcileServerImageRebuildDecision pins the single-pass decision from
// the image ref and Nova's user-data record.
func TestReconcileServerImageRebuildDecision(t *testing.T) {
	t.Parallel()

	userData := []byte("#cloud-config\nusers: []\n")
	desired := "a8cc7f5ccfcf822d62581acaa581743e4396c6487b0048fddbdc0233d2892fd2"

	cases := []struct {
		name             string
		novaHash         string
		novaGeneration   string
		novaBaseline     string
		novaStatus       string
		novaImageID      string
		taskState        string
		locked           bool
		enabled          bool
		wantRecord       bool
		wantRebuild      bool
		wantUserData     bool
		unstamped        bool
		parkMessage      string
		customerMetadata map[string]string
	}{
		{
			// A server without a record must not be reimaged during migration.
			name:             "no record on converged image",
			enabled:          true,
			novaStatus:       "ACTIVE",
			novaImageID:      rebuildNewImageID,
			wantRecord:       true,
			customerMetadata: map[string]string{"region:user_data_hash": "customer-tag"},
		},
		{
			name:        "no record during a foreign task",
			enabled:     true,
			novaStatus:  "ACTIVE",
			novaImageID: rebuildNewImageID,
			taskState:   taskStateRebooting,
			wantRecord:  true,
		},
		{
			name:        "no record on locked converged server",
			enabled:     true,
			novaStatus:  "ACTIVE",
			novaImageID: rebuildNewImageID,
			locked:      true,
			unstamped:   true,
		},
		{
			name:           "disabled with changed user data on locked converged server",
			novaHash:       "old-user-data",
			novaGeneration: "3",
			novaStatus:     "ACTIVE",
			novaImageID:    rebuildNewImageID,
			locked:         true,
			unstamped:      true,
		},
		{
			// Nova refuses a metadata write in ERROR, and the park still applies.
			name:        "no record on converged image in error",
			enabled:     true,
			novaStatus:  "ERROR",
			novaImageID: rebuildNewImageID,
			parkMessage: "the provider reports the server in an error state; change the image or replace the server",
			unstamped:   true,
		},
		{
			name:        "no record on converged image in error with a task",
			enabled:     true,
			novaStatus:  "ERROR",
			novaImageID: rebuildNewImageID,
			taskState:   "rescuing",
			parkMessage: "the provider reports the server in an error state; change the image or replace the server",
			unstamped:   true,
		},
		{
			name:        "no record on shelved server",
			enabled:     true,
			novaStatus:  "SHELVED",
			novaImageID: rebuildNewImageID,
			unstamped:   true,
		},
		{
			name:             "no record on changed image",
			enabled:          true,
			novaStatus:       "ACTIVE",
			novaImageID:      rebuildOldImageID,
			wantRebuild:      true,
			customerMetadata: map[string]string{"customer-key": "customer-value"},
		},
		{
			name:           "recorded user data on changed image",
			enabled:        true,
			novaHash:       desired,
			novaGeneration: "3",
			novaStatus:     "ACTIVE",
			novaImageID:    rebuildOldImageID,
			wantRebuild:    true,
		},
		{
			name:           "changed user data on converged image",
			wantUserData:   true,
			enabled:        true,
			novaHash:       "old-user-data",
			novaGeneration: "3",
			novaStatus:     "ACTIVE",
			novaImageID:    rebuildNewImageID,
			wantRebuild:    true,
		},
		{
			name:        "image-only rebuild keeps stored payload with flag enabled",
			enabled:     true,
			novaHash:    desired,
			novaStatus:  "ACTIVE",
			novaImageID: rebuildOldImageID,
			wantRebuild: true,
		},
		{
			name:         "image and user data both change",
			enabled:      true,
			novaHash:     "old-user-data",
			novaStatus:   "ACTIVE",
			novaImageID:  rebuildOldImageID,
			wantRebuild:  true,
			wantUserData: true,
		},
		{
			name:           "recorded user data on converged image",
			enabled:        true,
			novaHash:       desired,
			novaGeneration: "3",
			novaStatus:     "ACTIVE",
			novaImageID:    rebuildNewImageID,
		},
		{
			name:           "disabled with changed user data on converged image",
			novaHash:       "old-user-data",
			novaGeneration: "3",
			novaStatus:     "ACTIVE",
			novaImageID:    rebuildNewImageID,
			wantRecord:     true,
		},
		{
			name:           "disabled with changed user data and image",
			novaHash:       "old-user-data",
			novaGeneration: "3",
			novaStatus:     "ACTIVE",
			novaImageID:    rebuildOldImageID,
			wantRebuild:    true,
		},
		{
			name:         "changed user data on baseline",
			wantUserData: true,
			enabled:      true,
			novaBaseline: "old-user-data/",
			novaStatus:   "ACTIVE",
			novaImageID:  rebuildNewImageID,
			wantRebuild:  true,
		},
		{
			// A baseline write that commits after a rebuild must not undo it.
			name:           "baseline behind the record",
			enabled:        true,
			novaHash:       desired,
			novaGeneration: "3",
			novaBaseline:   "old-user-data/",
			novaStatus:     "ACTIVE",
			novaImageID:    rebuildNewImageID,
		},
		{
			// A change recorded while rebuilds were off is not applied later.
			name:           "baseline over the record",
			enabled:        true,
			novaHash:       "old-user-data",
			novaGeneration: "3",
			novaBaseline:   desired + "/3",
			novaStatus:     "ACTIVE",
			novaImageID:    rebuildNewImageID,
		},
		{
			name:           "disabled with changed user data on baseline over the record",
			novaHash:       "older-user-data",
			novaGeneration: "3",
			novaBaseline:   "old-user-data/3",
			novaStatus:     "ACTIVE",
			novaImageID:    rebuildNewImageID,
			wantRecord:     true,
		},
		{
			name:           "disabled with changed user data in error",
			novaHash:       "old-user-data",
			novaGeneration: "3",
			novaStatus:     "ERROR",
			novaImageID:    rebuildNewImageID,
			parkMessage:    "the provider reports the server in an error state; change the image or replace the server",
			unstamped:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client := mock.NewMockServerObservationInterface(gomock.NewController(t))
			server := desiredRebuildServer()
			server.Generation = 4
			server.Spec.UserData = userData

			if tc.wantRecord {
				client.EXPECT().UpdateServerMetadata(gomock.Any(), "server-1", map[string]string{"region:system:user_data_baseline_hash": desired + "/" + tc.novaGeneration}).Return(nil)
			}

			if tc.wantRebuild {
				metadata := map[string]string{"region:system:user_data_hash": desired, "region:system:user_data_generation": "4"}
				maps.Copy(metadata, tc.customerMetadata)

				client.EXPECT().RebuildServer(gomock.Any(), "server-1", openstack.ServerRebuildOptions{
					ImageID:     idstest.MustParseImageID(rebuildNewImageID),
					UserData:    userData,
					UseUserData: tc.wantUserData,
					Metadata:    metadata,
				}).
					Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)
			}

			novaServer := withUserDataBaseline(withUserDataGeneration(withUserDataHash(novaRebuildServerTask(tc.novaStatus, tc.novaImageID, tc.taskState), tc.novaHash), tc.novaGeneration), tc.novaBaseline)
			novaRecorded := len(novaServer.Metadata) != 0
			novaServer.Locked = &tc.locked

			maps.Copy(novaServer.Metadata, tc.customerMetadata)

			expectServerObservation(client, novaServer)

			err := reconcileExistingServer(t, client, server, &types.ServerCreateOptions{UserData: userData, RebuildOnUserData: tc.enabled})

			requireRebuildOutcome(t, server, err, tc.wantRebuild, tc.parkMessage)

			requireUserDataRecorded(t, server, tc.wantRecord || tc.wantRebuild || novaRecorded)
			requireUserDataRecordCurrent(t, server, !tc.unstamped)

			require.Subset(t, novaServer.Metadata, tc.customerMetadata)
		})
	}
}

func requireRebuildOutcome(t *testing.T, server *unikornv1.Server, err error, rebuilt bool, recheckMessage string) {
	t.Helper()

	if rebuilt {
		require.ErrorIs(t, err, provisioners.ErrYield)
		requireRebuildAcceptedStamp(t, server)

		return
	}

	if recheckMessage != "" {
		require.ErrorIs(t, err, provisioners.ErrRecheck)

		var perr *provisioners.Error

		require.ErrorAs(t, err, &perr)
		require.Equal(t, unikornv1core.ConditionReasonErrored, perr.Reason())
		require.Equal(t, recheckMessage, perr.Message())
	} else {
		require.NoError(t, err)
	}

	active, readErr := server.StatusConditionRead(unikornv1core.ConditionActive)
	require.NoError(t, readErr)
	require.NotEqual(t, string(unikornv1.ActiveConditionReasonRebuilding), active.Reason)
}

func TestReconcileServerImageRecordsOnLaterPoll(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		server *servers.Server
		locked bool
	}{
		{name: "failed before launch", server: novaUnlaunchedServer("ERROR", rebuildNewImageID)},
		{name: "never launched", server: novaUnlaunchedServer("BUILD", rebuildNewImageID)},
		{name: "shelved", server: novaRebuildServer("SHELVED", rebuildNewImageID)},
		{name: "rescued", server: novaRebuildServer("RESCUE", rebuildNewImageID)},
		{name: "locked", server: novaRebuildServer("ACTIVE", rebuildNewImageID), locked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client := mock.NewMockServerObservationInterface(gomock.NewController(t))
			server := desiredRebuildServer()
			server.Spec.UserData = []byte("#cloud-config\nusers: []\n")

			tc.server.Locked = &tc.locked
			err := openstack.ReconcileServerImage(t.Context(), client, server, withUserDataHash(tc.server, ""))
			require.NoError(t, err)
			requireUserDataRecorded(t, server, false)
			requireNoImageRowStamp(t, server)

			client.EXPECT().UpdateServerMetadata(gomock.Any(), "server-1", map[string]string{
				"region:system:user_data_baseline_hash": "a8cc7f5ccfcf822d62581acaa581743e4396c6487b0048fddbdc0233d2892fd2/",
			}).Return(nil)

			err = openstack.ReconcileServerImage(t.Context(), client, server, withUserDataHash(novaRebuildServer("ACTIVE", rebuildNewImageID), ""))
			require.NoError(t, err)
			requireUserDataRecorded(t, server, true)
			requireNoImageRowStamp(t, server)
		})
	}
}

func TestReconcileServerImageRecordRefusalRetries(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusConflict, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()

			client := mock.NewMockServerObservationInterface(gomock.NewController(t))
			server := desiredRebuildServer()
			failure := gophercloud.ErrUnexpectedResponseCode{Actual: status}

			client.EXPECT().UpdateServerMetadata(gomock.Any(), "server-1", gomock.Any()).Return(failure)

			err := openstack.ReconcileServerImage(t.Context(), client, server, withUserDataHash(novaRebuildServer("ACTIVE", rebuildNewImageID), ""))
			if status == http.StatusConflict {
				requireTypedYield(t, err,
					"waiting for the provider to accept the user-data record")
			} else {
				require.Equal(t, failure, err)
				require.NotErrorIs(t, err, provisioners.ErrYield)
			}

			require.False(t, provisioners.IsTerminal(err))
			requireUserDataRecorded(t, server, false)
		})
	}
}

func TestReconcileServerImageRebuildsUserDataChangedDuringRebuild(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Spec.UserData = []byte("#cloud-config\nwrite_files: []\n")
	acceptedHash := types.UserDataHash(server.Spec.UserData)

	imageOnly := rebuildOptionsFor(server.Spec.UserData)
	imageOnly.UseUserData = false
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", imageOnly).Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	err := openstack.ReconcileServerImage(t.Context(), client, server, withUserDataHash(novaRebuildServer("ACTIVE", rebuildOldImageID), acceptedHash))
	require.ErrorIs(t, err, provisioners.ErrYield)

	server.Spec.UserData = []byte("#cloud-config\npackages: []\n")

	err = openstack.ReconcileServerImage(t.Context(), client, server, withUserDataHash(novaRebuildServer("REBUILD", rebuildNewImageID), acceptedHash))
	require.ErrorIs(t, err, provisioners.ErrYield)

	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptionsFor(server.Spec.UserData)).Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	err = openstack.ReconcileServerImage(t.Context(), client, server, withUserDataHash(novaRebuildServer("ACTIVE", rebuildNewImageID), acceptedHash))
	require.ErrorIs(t, err, provisioners.ErrYield)
}

func expectServerObservation(compute *mock.MockServerObservationInterface, server *servers.Server) {
	compute.EXPECT().GetServer(gomock.Any(), gomock.Any()).Return(server, nil)

	if server.Status == "ERROR" {
		compute.EXPECT().GetServerFault(gomock.Any(), server.ID).Return(&servers.Fault{}, nil)
	}
}

// reconcileExistingServer exercises option propagation through the full pass.
func reconcileExistingServer(t *testing.T, compute *mock.MockServerObservationInterface, server *unikornv1.Server, options *types.ServerCreateOptions) error {
	t.Helper()

	network := networkFixture()
	server.Spec.Networks = []unikornv1.ServerNetworkSpec{{ID: idstest.MustParseNetworkID(network.Name)}}
	openstackNetwork := openstackNetworkFixture(network)
	openstackSubnet := openstackSubnetFixture(network, openstackNetwork)
	port := openstackServerPortFixture(server, openstackNetwork, openstackSubnet)
	networking := mock.NewMockNetworkingInterface(gomock.NewController(t))
	networking.EXPECT().GetNetwork(t.Context(), networkMatcher(network)).Return(openstackNetwork, nil)
	networking.EXPECT().FindServerPorts(t.Context(), server).Return([]ports.Port{*port}, nil)
	networking.EXPECT().GetFloatingIP(t.Context(), port.ID).Return(nil, coreerrors.ErrResourceNotFound)
	p := openstack.NewTestProvider(getClient(t, []client.Object{network}), regionFixture())
	_, err := openstack.CreateServerWithClients(t.Context(), p, networking, compute, identityFixture(), server, options, "")

	return err
}

func TestReconcileServerIgnoresChangedAugmentation(t *testing.T) {
	t.Parallel()

	server := desiredRebuildServer()
	server.Spec.UserData = []byte("#cloud-config\nusers: []\n")
	options := &types.ServerCreateOptions{UserData: []byte("#cloud-config\nusers:\n  - name: managed\n"), RebuildOnUserData: true}
	compute := mock.NewMockServerObservationInterface(gomock.NewController(t))
	compute.EXPECT().GetServer(gomock.Any(), gomock.Any()).Return(withUserDataHash(novaRebuildServer("ACTIVE", rebuildNewImageID), types.UserDataHash(server.Spec.UserData)), nil)

	require.NoError(t, reconcileExistingServer(t, compute, server, options))
	requireUserDataRecorded(t, server, true)
}

// A baseline write given up on while rebuilds were off, which Nova commits
// only after rebuilds to its user data and back, must not arm another rebuild,
// whether the server was created with the record or recorded by a baseline.
func TestReconcileServerImageLateBaselineAfterRevertingRebuilds(t *testing.T) {
	t.Parallel()

	for _, createdGeneration := range []string{"", "1"} {
		t.Run(map[bool]string{false: "recorded by a baseline", true: "created with the record"}[createdGeneration != ""], func(t *testing.T) {
			t.Parallel()

			userDataA := []byte("#cloud-config\nusers: []\n")
			userDataB := []byte("#cloud-config\npackages: []\n")
			hashA := types.UserDataHash(userDataA)
			hashB := types.UserDataHash(userDataB)

			client := mock.NewMockServerInterface(gomock.NewController(t))
			server := desiredRebuildServer()
			nova := novaRebuildServer("ACTIVE", rebuildNewImageID)
			withUserDataGeneration(withUserDataHash(nova, hashA), createdGeneration)

			if createdGeneration == "" {
				nova = withUserDataBaseline(withUserDataHash(nova, ""), hashA+"/")
			}

			// B is recorded while rebuilds are off, but the write times out.
			server.Generation = 2
			server.Spec.UserData = userDataB
			stale := map[string]string{"region:system:user_data_baseline_hash": hashB + "/" + createdGeneration}

			client.EXPECT().UpdateServerMetadata(gomock.Any(), "server-1", stale).Return(context.DeadlineExceeded)

			err := openstack.ReconcileServerImageWithoutUserDataRebuild(t.Context(), client, server, nova)
			require.ErrorIs(t, err, context.DeadlineExceeded)

			client.EXPECT().RebuildServer(gomock.Any(), "server-1", gomock.Any()).Times(2).
				DoAndReturn(func(_ context.Context, _ string, options openstack.ServerRebuildOptions) (*servers.Server, error) {
					nova.Metadata = options.Metadata

					return novaRebuildServer("REBUILD", rebuildNewImageID), nil
				})

			// With rebuilds on, B is applied, then A.
			err = openstack.ReconcileServerImage(t.Context(), client, server, nova)
			require.ErrorIs(t, err, provisioners.ErrYield)
			require.Equal(t, map[string]string{"region:system:user_data_hash": hashB, "region:system:user_data_generation": "2"}, nova.Metadata)

			server.Generation = 3
			server.Spec.UserData = userDataA

			err = openstack.ReconcileServerImage(t.Context(), client, server, nova)
			require.ErrorIs(t, err, provisioners.ErrYield)
			require.Equal(t, map[string]string{"region:system:user_data_hash": hashA, "region:system:user_data_generation": "3"}, nova.Metadata)

			// The write given up on commits.
			maps.Copy(nova.Metadata, stale)

			err = openstack.ReconcileServerImage(t.Context(), client, server, nova)
			require.NoError(t, err)
			requireUserDataRecordCurrent(t, server, true)
		})
	}
}

// A change whose baseline write is deferred leaves the condition True but not
// current, so the rollout check still lists the server.
func TestReconcileServerImageDeferredBaselineIsNotCurrent(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Generation = 1
	server.Spec.UserData = []byte("#cloud-config\nusers: []\n")
	recorded := withUserDataGeneration(withUserDataHash(novaRebuildServer("ACTIVE", rebuildNewImageID), types.UserDataHash(server.Spec.UserData)), "1")

	err := openstack.ReconcileServerImageWithoutUserDataRebuild(t.Context(), client, server, recorded)
	require.NoError(t, err)
	requireUserDataRecordCurrent(t, server, true)

	server.Generation = 2
	server.Spec.UserData = []byte("#cloud-config\npackages: []\n")
	busy := novaRebuildServerTask("ACTIVE", rebuildNewImageID, taskStateRebooting)
	locked := true
	busy.Locked = &locked
	busy.Metadata = recorded.Metadata

	err = openstack.ReconcileServerImageWithoutUserDataRebuild(t.Context(), client, server, busy)
	require.NoError(t, err)
	requireUserDataRecorded(t, server, true)
	requireUserDataRecordCurrent(t, server, false)

	client.EXPECT().UpdateServerMetadata(gomock.Any(), "server-1", map[string]string{
		"region:system:user_data_baseline_hash": types.UserDataHash(server.Spec.UserData) + "/1",
	}).Return(nil)

	err = openstack.ReconcileServerImageWithoutUserDataRebuild(t.Context(), client, server, recorded)
	require.NoError(t, err)
	requireUserDataRecordCurrent(t, server, true)
}
