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

	"github.com/go-logr/logr"
	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/ports"
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
	"k8s.io/utils/ptr"
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
func requireTypedYield(t *testing.T, err error, reason unikornv1core.ProvisioningConditionReason, message string) {
	t.Helper()

	require.ErrorIs(t, err, provisioners.ErrYield)

	var perr *provisioners.Error

	require.ErrorAs(t, err, &perr, "a yield must be typed so the condition can name the wait")
	require.Equal(t, reason, perr.Reason())
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
			requireTypedYield(t, err, unikornv1core.ConditionReasonProvisioning, "rebuilding the server onto the requested image")
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
// provisioner's bounded retry machinery owns. This pass must complete without a
// park so that machinery is reached.
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
	requireTypedYield(t, err, unikornv1core.ConditionReasonProvisioning, "another operation is in progress on the server")
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
			requireTypedYield(t, err, unikornv1core.ConditionReasonProvisioning, "once the server has booted")
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

// TestReconcileServerRebuildOmitsGuestConfiguration pins that the rebuild carries
// only the image; Nova preserves guest configuration on an omitted field.
// observeAndConverge runs the found-server half of a pass in the order the pass
// runs it: the read and its projection, then the image rows. The order itself
// is pinned through the real pass by TestCreateServerObservesFirst.
func observeAndConverge(t *testing.T, p *openstack.Provider, client *mock.MockServerObservationInterface, server *unikornv1.Server) error {
	t.Helper()

	observed, err := openstack.ObserveServer(t.Context(), p, client, identityFixture(), server)
	require.NoError(t, err)

	return openstack.ReconcileServerImage(t.Context(), client, server, observed)
}

func TestReconcileServerRebuildOmitsGuestConfiguration(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerObservationInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Spec.UserData = []byte("#cloud-config\nusers: []\n")
	client.EXPECT().GetServer(gomock.Any(), server).
		Return(novaRebuildServer("ACTIVE", rebuildOldImageID), nil)
	// Only the image reaches Nova, even with user data set and a keypair in play.
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

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
