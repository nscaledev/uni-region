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

// requireRebuildAcceptedStamp asserts the fixed in-flight view the reconciler
// writes on rebuild acceptance (markServerRebuildAccepted): Active Rebuilding
// and health Unknown, matching what the monitor derives for a Nova REBUILD so
// reconciler and monitor writes agree rather than flap.
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

// requireNoReconcilerStamp asserts a pre-acceptance pass wrote neither the
// Active lifecycle condition nor the monitor-owned Healthy condition, leaving
// both for the monitor to derive.
func requireNoReconcilerStamp(t *testing.T, server *unikornv1.Server) {
	t.Helper()

	_, activeErr := server.StatusConditionRead(unikornv1core.ConditionActive)
	require.Error(t, activeErr, "a pre-acceptance pass must not write a synthetic Active lifecycle condition")

	_, healthErr := server.StatusConditionRead(unikornv1core.ConditionHealthy)
	require.Error(t, healthErr, "a pre-acceptance pass must not write the monitor-owned Healthy condition")
}

const (
	rebuildOldImageID   = "11111111-1111-4111-a111-111111111111"
	rebuildNewImageID   = "22222222-2222-4222-a222-222222222222"
	rebuildThirdImageID = "33333333-3333-4333-a333-333333333333"
)

// desiredRebuildServer is a CR wanting the new image, with no status launch
// latch: the gate authorizes from the fresh Nova launched_at, not CR status.
func desiredRebuildServer() *unikornv1.Server {
	return &unikornv1.Server{
		Spec: unikornv1.ServerSpec{
			Image: &unikornv1.ServerImage{ID: idstest.MustParseImageID(rebuildNewImageID)},
		},
	}
}

// novaRebuildServer is a launched server: its Nova launched_at is non-zero, the
// fresh signal the rebuild gate authorizes from (not the CR status latches).
func novaRebuildServer(status, imageID string) *servers.Server {
	return &servers.Server{
		ID:         "server-1",
		Status:     status,
		Image:      map[string]any{"id": imageID},
		LaunchedAt: time.Now().Add(-time.Hour),
	}
}

// novaUnlaunchedServer is a never-booted server: Nova reports a zero
// launched_at, so the gate must defer any image change until first boot.
func novaUnlaunchedServer(status, imageID string) *servers.Server {
	server := novaRebuildServer(status, imageID)
	server.LaunchedAt = time.Time{}

	return server
}

// novaRebuildServerTask is a launched server with a non-empty task_state, the
// signal the quiescence gate reads to tell in-flight apart from settled.
func novaRebuildServerTask(status, imageID, taskState string) *servers.Server {
	server := novaRebuildServer(status, imageID)
	server.TaskState = taskState

	return server
}

func rebuildOptions() openstack.ServerRebuildOptions {
	return openstack.ServerRebuildOptions{ImageID: idstest.MustParseImageID(rebuildNewImageID)}
}

// TestReconcileServerImageStartsOnce pins the two-pass write-ahead protocol: the
// first pass records intent and yields without touching Nova; only the second,
// whose marker was read back durable, submits.
func TestReconcileServerImageStartsOnce(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	server := desiredRebuildServer()

	// Arm pass: intent recorded, no Nova call, yield persists the marker. The
	// yield is silent — no Phase and no monitor-owned Healthy condition.
	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Equal(t, idstest.MustParseImageID(rebuildNewImageID), server.Status.Rebuild.TargetImageID)
	require.Equal(t, unikornv1.ServerRebuildStateInitiated, server.Status.Rebuild.State)
	requireNoReconcilerStamp(t, server)

	// Submit pass: the durable Initiated marker authorizes one submission;
	// acceptance advances it to Rebuilding.
	_, err = openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.NoError(t, err)
	require.Equal(t, idstest.MustParseImageID(rebuildNewImageID), server.Status.Rebuild.TargetImageID)
	require.Equal(t, unikornv1.ServerRebuildStateRebuilding, server.Status.Rebuild.State)

	// The reconcile completes after submission; pin the accepted status stamps.
	requireRebuildAcceptedStamp(t, server)
}

// TestReconcileServerRebuildOmitsGuestConfiguration pins that the rebuild call
// carries only the image. Guest configuration is preserved by Nova's
// omitted-field semantics, so neither the server's stored user data nor the
// keypair name in play reaches the rebuild request.
func TestReconcileServerRebuildOmitsGuestConfiguration(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	// Intent already durable: this pass submits.
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), State: unikornv1.ServerRebuildStateInitiated}
	server.Spec.UserData = []byte("#cloud-config\nusers: []\n")
	client.EXPECT().GetServer(gomock.Any(), server).
		Return(novaRebuildServer("ACTIVE", rebuildOldImageID), nil)
	// Only the image reaches Nova, even with user data set and a keypair in play.
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	_, err := openstack.ReconcileServer(t.Context(), nil, client, server, nil, "identity-keypair")
	require.NoError(t, err)
	requireRebuildAcceptedStamp(t, server)
}

// TestCreateServerCopiesFullStatusBackForAugmentedServers pins that the caller's
// server observes the full post-reconcile status (Phase, Healthy, ...), not just
// Status.Rebuild, when user-data augmentation forces a deep-copy reconcile.
func TestCreateServerCopiesFullStatusBackForAugmentedServers(t *testing.T) {
	t.Parallel()

	server := desiredRebuildServer()
	// Intent already durable: this pass submits.
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), State: unikornv1.ServerRebuildStateInitiated}

	options := &types.ServerCreateOptions{UserData: []byte("#cloud-config\nssh_authorized_keys: []\n")}
	require.NotSame(t, server, openstack.ServerForCreate(server, options), "test setup requires user-data augmentation to force a deep copy")

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().GetServer(gomock.Any(), gomock.Any()).Return(novaRebuildServer("ACTIVE", rebuildOldImageID), nil)
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	err := openstack.ReconcileServerForCreate(t.Context(), nil, client, server, options, nil, "")
	require.NoError(t, err)

	requireRebuildAcceptedStamp(t, server)
}

// TestReconcileServerImageCompletesWhileNovaRebuilds pins that with no marker, a
// Nova REBUILD on the already-desired image is a foreign rebuild — the monitor's
// concern. The pass completes without touching Nova, the marker, or Phase/Healthy.
func TestReconcileServerImageCompletesWhileNovaRebuilds(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("REBUILD", rebuildNewImageID))
	require.NoError(t, err)
	require.Nil(t, server.Status.Rebuild)
	requireNoReconcilerStamp(t, server)
}

// TestReconcileServerImageObservedRebuildAdvancesMarker pins that Nova reporting
// REBUILD while a matching marker is still Initiated advances it to Rebuilding.
func TestReconcileServerImageObservedRebuildAdvancesMarker(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), State: unikornv1.ServerRebuildStateInitiated}

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("REBUILD", rebuildNewImageID))
	require.NoError(t, err)
	require.Equal(t, unikornv1.ServerRebuildStateRebuilding, server.Status.Rebuild.State)
}

// TestReconcileServerImageCompletesWhileAcceptedRebuildConverges pins P7c: an
// accepted rebuild still in flight (non-target ref, active task) is not
// re-submitted; the reconcile re-asserts the accepted stamp and completes,
// preserving the marker for P4c's later supersession.
func TestReconcileServerImageCompletesWhileAcceptedRebuildConverges(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), State: unikornv1.ServerRebuildStateRebuilding}

	// task_state active: genuinely in flight (an empty task would be supersession).
	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServerTask("ACTIVE", rebuildOldImageID, "rebuilding"))
	require.NoError(t, err)
	require.Equal(t, idstest.MustParseImageID(rebuildNewImageID), server.Status.Rebuild.TargetImageID)
	require.Equal(t, unikornv1.ServerRebuildStateRebuilding, server.Status.Rebuild.State)
	requireRebuildAcceptedStamp(t, server)
}

// TestReconcileServerImageClearsMarkerOnSuccess pins the converged-clear (P6a)
// for every non-Failed marker state: a quiescent convergence retires the marker,
// confirmed by read-back (the clearing pass yields, the requeued pass that reads
// it absent completes). Failed is excluded — it parks instead, see
// TestReconcileServerImageDoesNotClearFailedMarker.
func TestReconcileServerImageClearsMarkerOnSuccess(t *testing.T) {
	t.Parallel()

	states := []unikornv1.ServerRebuildState{
		unikornv1.ServerRebuildStateInitiated,
		unikornv1.ServerRebuildStateRebuilding,
		unikornv1.ServerRebuildStateSucceeded,
	}

	for _, state := range states {
		t.Run(string(state), func(t *testing.T) {
			t.Parallel()

			client := mock.NewMockServerInterface(gomock.NewController(t))
			server := desiredRebuildServer()
			server.Status.Rebuild = &unikornv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), State: state}

			// Clearing pass: marker removed, yield to confirm by read-back.
			_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildNewImageID))
			require.ErrorIs(t, err, provisioners.ErrYield)
			require.Nil(t, server.Status.Rebuild)

			// Confirming pass: marker reads back absent, so the intent is settled.
			_, err = openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildNewImageID))
			require.NoError(t, err)
			require.Nil(t, server.Status.Rebuild)
		})
	}
}

// TestReconcileServerImageDoesNotClearFailedMarker pins that a Failed marker
// parks (P4a) even over a converged quiescent read — a post-acceptance failure
// leaves an unverifiable root disk, so a false park beats a false success.
func TestReconcileServerImageDoesNotClearFailedMarker(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), State: unikornv1.ServerRebuildStateFailed}

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildNewImageID))
	require.ErrorIs(t, err, provisioners.ErrUserActionRequired)
	require.Equal(t, unikornv1.ServerRebuildStateFailed, server.Status.Rebuild.State, "a Failed marker is never cleared by a converged read")
}

// TestReconcileServerImageParksAcceptedFailure pins the two-phase park (P4b →
// P4a): a marker with acceptance evidence (durably >= Rebuilding, or the ref
// flipped to the target) that observes ERROR fails. The first pass stamps Failed
// (direct) and yields; only the second, which reads Failed back, parks. The
// direct stamp overrides a stale Succeeded, or the retained level would re-fire
// the settlement wake forever on a parked server.
func TestReconcileServerImageParksAcceptedFailure(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		imageID string
		state   unikornv1.ServerRebuildState
	}{
		"unmoved ref":                 {imageID: rebuildOldImageID, state: unikornv1.ServerRebuildStateRebuilding},
		"flipped ref":                 {imageID: rebuildNewImageID, state: unikornv1.ServerRebuildStateRebuilding},
		"stale succeeded observation": {imageID: rebuildNewImageID, state: unikornv1.ServerRebuildStateSucceeded},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := mock.NewMockServerInterface(gomock.NewController(t))
			server := desiredRebuildServer()
			server.Status.Rebuild = &unikornv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), State: tc.state}

			// Stamp pass: failure recorded (overriding a stale Succeeded), yield.
			_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", tc.imageID))
			require.ErrorIs(t, err, provisioners.ErrYield)
			require.Equal(t, unikornv1.ServerRebuildStateFailed, server.Status.Rebuild.State, "the pre-park stamp records the failure")

			condition, conditionErr := server.StatusConditionRead(unikornv1core.ConditionHealthy)
			require.NoError(t, conditionErr)
			require.Equal(t, metav1.ConditionFalse, condition.Status)

			// Park pass: Failed reads back durable, so the terminal park issues.
			_, err = openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", tc.imageID))
			require.ErrorIs(t, err, provisioners.ErrUserActionRequired)
			require.Equal(t, unikornv1.ServerRebuildStateFailed, server.Status.Rebuild.State, "the park retains the marker with the failure recorded")
		})
	}
}

func TestReconcileServerImageDoesNotRebuildUnrelatedError(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", rebuildNewImageID))
	require.NoError(t, err)
}

// TestReconcileServerImageRebuildsWhenNovaLaunchedButStatusUnobserved is the
// headline fresh-read-gate case: Nova reports launched_at set but the monitor
// never recorded it (CR latches nil). The gate must authorize from the fresh
// Nova read, or the image change is silently dropped.
func TestReconcileServerImageRebuildsWhenNovaLaunchedButStatusUnobserved(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	server := desiredRebuildServer()
	// The monitor never observed the first ACTIVE: the status latches are nil.
	server.Status.ProvisionedAt = nil
	server.Status.LaunchedAt = nil

	// The gate authorizes from the fresh read: arm, then submit.
	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Equal(t, idstest.MustParseImageID(rebuildNewImageID), server.Status.Rebuild.TargetImageID)

	_, err = openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.NoError(t, err)
	require.Equal(t, idstest.MustParseImageID(rebuildNewImageID), server.Status.Rebuild.TargetImageID)
	require.Equal(t, unikornv1.ServerRebuildStateRebuilding, server.Status.Rebuild.State)
}

// TestReconcileServerImageDefersUntilFreshLaunch pins that a server Nova reports
// as never booted (zero launched_at) defers its image change and never rebuilds,
// even when stale status latches claim it launched.
func TestReconcileServerImageDefersUntilFreshLaunch(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	// Status says launched (stale); the gate must ignore it and read Nova.
	launched := metav1.NewTime(time.Now().Add(-time.Hour))
	server.Status.ProvisionedAt = &launched
	server.Status.LaunchedAt = &launched

	// gomock enforces that no RebuildServer call is made.
	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaUnlaunchedServer("ACTIVE", rebuildOldImageID))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Nil(t, server.Status.Rebuild)
}

// TestReconcileServerImageDefersErroredUnlaunchedToCreateRetry pins P7a: a
// never-booted server Nova reports in ERROR with a pending image change and no
// marker is in the create-retry domain. The pass yields silently (no
// Phase/Healthy write) and submits no rebuild.
func TestReconcileServerImageDefersErroredUnlaunchedToCreateRetry(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	// gomock enforces that no RebuildServer call is made.
	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaUnlaunchedServer("ERROR", rebuildOldImageID))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Nil(t, server.Status.Rebuild)

	_, conditionErr := server.StatusConditionRead(unikornv1core.ConditionHealthy)
	require.Error(t, conditionErr, "the pre-acceptance create-retry yield must not write the monitor-owned Healthy condition")
}

// TestReconcileServerImageUnreadableImageYields pins P5: a fresh Nova read whose
// image ref is missing or unparseable means convergence cannot be checked, so
// the reconcile yields visibly without touching Nova, the marker, or Healthy.
func TestReconcileServerImageUnreadableImageYields(t *testing.T) {
	t.Parallel()

	testCases := map[string]map[string]any{
		"missing image ref": {},
		"non-UUID image id": {"id": "not-a-uuid"},
	}

	for name, image := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// gomock enforces that no RebuildServer call is made.
			client := mock.NewMockServerInterface(gomock.NewController(t))
			server := desiredRebuildServer()

			openstackServer := novaRebuildServer("ACTIVE", "")
			openstackServer.Image = image

			_, err := openstack.ReconcileServerImage(t.Context(), client, server, openstackServer)
			require.ErrorIs(t, err, provisioners.ErrYield)
			require.Nil(t, server.Status.Rebuild)

			_, conditionErr := server.StatusConditionRead(unikornv1core.ConditionHealthy)
			require.Error(t, conditionErr, "this path must not write the monitor-owned Healthy condition")
		})
	}
}

// TestReconcileServerImageConflictKeepsInitiated pins the 409 wait: a Nova
// conflict is pre-acceptance, so the marker stays Initiated.
func TestReconcileServerImageConflictKeepsInitiated(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(nil, gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusConflict})

	server := desiredRebuildServer()
	// Intent already durable: this pass submits.
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), State: unikornv1.ServerRebuildStateInitiated}

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Equal(t, unikornv1.ServerRebuildStateInitiated, server.Status.Rebuild.State)

	// The 409 is pre-acceptance: the yield is silent — no Phase, no Healthy write.
	requireNoReconcilerStamp(t, server)
}

// TestReconcileServerImageParksLostAcceptanceFailure pins the loss-window
// recovery the write-ahead marker exists for: Nova accepted a rebuild, every
// post-arm write was lost (marker still Initiated), then it failed fast. The
// ref flipped to the target is the acceptance evidence (P4b's ref==target
// disjunct), so the server parks rather than reporting a false success.
func TestReconcileServerImageParksLostAcceptanceFailure(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), State: unikornv1.ServerRebuildStateInitiated}

	// Stamp pass: the ref flip attributes the ERROR to our rebuild.
	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", rebuildNewImageID))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Equal(t, unikornv1.ServerRebuildStateFailed, server.Status.Rebuild.State, "the pre-park stamp survives a lost monitor write")

	// Park pass: Failed reads back durable.
	_, err = openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", rebuildNewImageID))
	require.ErrorIs(t, err, provisioners.ErrUserActionRequired)
	require.Equal(t, unikornv1.ServerRebuildStateFailed, server.Status.Rebuild.State)
}

// TestReconcileServerImageArmedUnrelatedErrorSubmits pins that intent alone is
// not acceptance evidence: an Initiated marker with the ref unmoved means Nova
// never acted, so an ERROR is unrelated and the submission proceeds (the
// remediation rebuild) rather than parking.
func TestReconcileServerImageArmedUnrelatedErrorSubmits(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	server := desiredRebuildServer()
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), State: unikornv1.ServerRebuildStateInitiated}

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", rebuildOldImageID))
	require.NoError(t, err)
	require.Equal(t, unikornv1.ServerRebuildStateRebuilding, server.Status.Rebuild.State)
}

// TestReconcileServerImageNewImageRearmsAfterParkedFailure pins the only re-arm
// path for a parked (Failed) rebuild: a changed desired image. A parked failure
// for image B does not retry; only Spec.Image.ID moving to image C re-arms
// (replacing the Failed marker with a fresh Initiated one) and re-submits.
func TestReconcileServerImageNewImageRearmsAfterParkedFailure(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", openstack.ServerRebuildOptions{
		ImageID: idstest.MustParseImageID(rebuildThirdImageID),
	}).Return(novaRebuildServer("REBUILD", rebuildThirdImageID), nil)

	server := desiredRebuildServer()
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{
		TargetImageID: idstest.MustParseImageID(rebuildNewImageID),
		State:         unikornv1.ServerRebuildStateRebuilding,
	}

	// An accepted rebuild for image B reached ERROR: stamp Failed (P4b), park (P4a).
	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", rebuildNewImageID))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Equal(t, unikornv1.ServerRebuildStateFailed, server.Status.Rebuild.State)

	_, err = openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", rebuildNewImageID))
	require.ErrorIs(t, err, provisioners.ErrUserActionRequired)
	require.Equal(t, unikornv1.ServerRebuildStateFailed, server.Status.Rebuild.State)

	// Re-arm: the desired image moves on to C; the replacement marker is written
	// ahead, back at Initiated.
	server.Spec.Image.ID = idstest.MustParseImageID(rebuildThirdImageID)

	_, err = openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", rebuildNewImageID))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Equal(t, idstest.MustParseImageID(rebuildThirdImageID), server.Status.Rebuild.TargetImageID)
	require.Equal(t, unikornv1.ServerRebuildStateInitiated, server.Status.Rebuild.State)

	// Submit: the durable Initiated marker for C authorizes one submission.
	_, err = openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", rebuildNewImageID))
	require.NoError(t, err)
	require.Equal(t, idstest.MustParseImageID(rebuildThirdImageID), server.Status.Rebuild.TargetImageID)
	require.Equal(t, unikornv1.ServerRebuildStateRebuilding, server.Status.Rebuild.State)
}

// TestReconcileServerImageInitiatedForeignRebuildYields pins the row the whole
// redesign turns on. An Initiated marker with a foreign rebuild in flight toward
// a different image (ref off target, task active) must not advance and must not
// clean-complete: the pass yields (P7d), keeping the submission gate alive. The
// monitor leaves it alone, so the reconciler's yield loop is the only wake
// channel and a clean-complete would wedge the marker forever.
func TestReconcileServerImageInitiatedForeignRebuildYields(t *testing.T) {
	t.Parallel()

	// gomock enforces that no RebuildServer call is made while the foreign op
	// holds the server.
	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), State: unikornv1.ServerRebuildStateInitiated}

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("REBUILD", rebuildOldImageID))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Equal(t, unikornv1.ServerRebuildStateInitiated, server.Status.Rebuild.State, "a foreign rebuild must not advance the submission gate off Initiated")
}

// TestReconcileServerImageUnknownMarkerStateYields pins the defensive tail of
// the pending-state dispatch: a marker state this version does not recognize
// (version skew during a rolling upgrade — a newer controller wrote a state
// this one predates) must yield, never clean-complete as provisioned, and must
// not submit a rebuild.
func TestReconcileServerImageUnknownMarkerStateYields(t *testing.T) {
	t.Parallel()

	// gomock enforces that no RebuildServer call is made on an unrecognized state.
	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), State: unikornv1.ServerRebuildState("Verifying")}

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.ErrorIs(t, err, provisioners.ErrYield)
}

// TestReconcileServerImageParksSupersededRebuild pins P4c supersession: an
// accepted rebuild whose fresh read shows a readable ref moved off the target
// with a quiesced task can no longer converge. The first pass stamps Failed and
// yields (P4c), the second parks (P4a); it never resubmits or clears.
func TestReconcileServerImageParksSupersededRebuild(t *testing.T) {
	t.Parallel()

	// gomock enforces that no RebuildServer call is made.
	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), State: unikornv1.ServerRebuildStateRebuilding}

	// ACTIVE, off-target ref, empty task_state: quiescent but not converged.
	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Equal(t, unikornv1.ServerRebuildStateFailed, server.Status.Rebuild.State, "supersession stamps Failed")

	_, err = openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.ErrorIs(t, err, provisioners.ErrUserActionRequired)
	require.Equal(t, unikornv1.ServerRebuildStateFailed, server.Status.Rebuild.State)
}

// TestReconcileServerImageSucceededTaskActiveYields pins the quiescence gate on
// the clear: a Succeeded marker on a converged ref but an active task_state must
// not clear — activity after the stamp postpones settlement, so the pass yields.
func TestReconcileServerImageSucceededTaskActiveYields(t *testing.T) {
	t.Parallel()

	// gomock enforces that no RebuildServer call is made.
	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), State: unikornv1.ServerRebuildStateSucceeded}

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServerTask("ACTIVE", rebuildNewImageID, "rebuilding"))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.NotNil(t, server.Status.Rebuild, "an active task after the Succeeded stamp postpones the clear")
	require.Equal(t, unikornv1.ServerRebuildStateSucceeded, server.Status.Rebuild.State)
}

// TestReconcileServerImageAcceptedStampIgnoresResponseBody pins that the
// acceptance stamp is fixed (Building, Healthy False/Provisioning) and never
// derived from the rebuild response body — here a 202 body still reading ACTIVE
// on the old image would falsely stamp Healthy/Running.
func TestReconcileServerImageAcceptedStampIgnoresResponseBody(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	// The response body reads ACTIVE on the OLD image — a body-derived stamp
	// would map it to Healthy=True/Running.
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(novaRebuildServer("ACTIVE", rebuildOldImageID), nil)

	server := desiredRebuildServer()
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), State: unikornv1.ServerRebuildStateInitiated}

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.NoError(t, err)
	require.Equal(t, unikornv1.ServerRebuildStateRebuilding, server.Status.Rebuild.State)
	requireRebuildAcceptedStamp(t, server)
}
