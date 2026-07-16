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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	rebuildOldImageID   = "11111111-1111-4111-a111-111111111111"
	rebuildNewImageID   = "22222222-2222-4222-a222-222222222222"
	rebuildThirdImageID = "33333333-3333-4333-a333-333333333333"
)

func desiredRebuildServer() *unikornv1.Server {
	launchedAt := metav1.NewTime(time.Now().Add(-time.Hour))

	return &unikornv1.Server{
		Spec: unikornv1.ServerSpec{
			Image: &unikornv1.ServerImage{ID: idstest.MustParseImageID(rebuildNewImageID)},
		},
		Status: unikornv1.ServerStatus{ProvisionedAt: &launchedAt},
	}
}

func novaRebuildServer(status, imageID string) *servers.Server {
	return &servers.Server{ID: "server-1", Status: status, Image: map[string]any{"id": imageID}}
}

func rebuildOptions() openstack.ServerRebuildOptions {
	return openstack.ServerRebuildOptions{ImageID: idstest.MustParseImageID(rebuildNewImageID)}
}

func TestReconcileServerImageStartsOnce(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.NoError(t, err)
	require.Equal(t, idstest.MustParseImageID(rebuildNewImageID), server.Status.Rebuild.TargetImageID)
	require.Equal(t, int32(1), server.Status.Rebuild.AcceptedAttempts)

	// The reconcile completes after submission; the status stamps below plus
	// the monitor edge are the only settlement mechanism, so pin them.
	require.Equal(t, unikornv1.InstanceLifecyclePhaseBuilding, server.Status.Phase)
	condition, conditionErr := server.StatusConditionRead(unikornv1core.ConditionHealthy)
	require.NoError(t, conditionErr)
	require.Equal(t, unikornv1core.ConditionReasonProvisioning, condition.Reason)
}

func TestReconcileServerImagePreservesEffectiveGuestConfiguration(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Spec.UserData = []byte("#cloud-config\nusers: []\n")
	client.EXPECT().GetServer(gomock.Any(), server).
		Return(novaRebuildServer("ACTIVE", rebuildOldImageID), nil)
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", openstack.ServerRebuildOptions{
		ImageID:  idstest.MustParseImageID(rebuildNewImageID),
		KeyName:  "identity-keypair",
		UserData: server.Spec.UserData,
	}).Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	_, err := openstack.ReconcileServer(t.Context(), nil, client, server, nil, "identity-keypair")
	require.NoError(t, err)
	require.Equal(t, unikornv1.InstanceLifecyclePhaseBuilding, server.Status.Phase)
}

// TestCreateServerCopiesFullStatusBackForAugmentedServers pins the status
// copy-back contract: the caller's server must observe the FULL
// post-reconcile status (Phase, Healthy condition, ...), not just
// Status.Rebuild, whenever CreateServer's user-data augmentation forces it to
// reconcile a deep copy rather than the caller's own server. Copying back a
// narrower slice would leave an accepted rebuild's Phase invisible on the
// caller's server.
func TestCreateServerCopiesFullStatusBackForAugmentedServers(t *testing.T) {
	t.Parallel()

	server := desiredRebuildServer()

	options := &types.ServerCreateOptions{UserData: []byte("#cloud-config\nssh_authorized_keys: []\n")}
	require.NotSame(t, server, openstack.ServerForCreate(server, options), "test setup requires user-data augmentation to force a deep copy")

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().GetServer(gomock.Any(), gomock.Any()).Return(novaRebuildServer("ACTIVE", rebuildOldImageID), nil)
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", openstack.ServerRebuildOptions{
		ImageID:  idstest.MustParseImageID(rebuildNewImageID),
		UserData: options.UserData,
	}).Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	err := openstack.ReconcileServerForCreate(t.Context(), nil, client, server, options, nil, "")
	require.NoError(t, err)

	require.Equal(t, unikornv1.InstanceLifecyclePhaseBuilding, server.Status.Phase, "caller's server should observe the accepted rebuild's Phase, not just Status.Rebuild")
}

func TestReconcileServerImageCompletesWhileNovaRebuilds(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	// Nova is mid-rebuild: the reconcile stamps the observed state and
	// completes; the health monitor observes the ACTIVE transition and its
	// status write wakes the reconciler for the settlement pass.
	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("REBUILD", rebuildNewImageID))
	require.NoError(t, err)
	require.Equal(t, unikornv1.InstanceLifecyclePhaseBuilding, server.Status.Phase)

	condition, conditionErr := server.StatusConditionRead(unikornv1core.ConditionHealthy)
	require.NoError(t, conditionErr)
	require.Equal(t, unikornv1core.ConditionReasonProvisioning, condition.Reason)
}

// TestReconcileServerImageCompletesWhileAcceptedRebuildConverges pins the
// accepted-not-converged branch: a rebuild already accepted (marker present,
// AcceptedAttempts == 1) that Nova has not yet converged (still reporting the
// old image) must not be re-submitted. The reconcile stamps Building /
// Provisioning and completes without yielding; the marker is preserved so the
// monitor edge drives the eventual settlement.
func TestReconcileServerImageCompletesWhileAcceptedRebuildConverges(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), AcceptedAttempts: 1}

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.NoError(t, err)
	require.Equal(t, unikornv1.InstanceLifecyclePhaseBuilding, server.Status.Phase)
	require.Equal(t, idstest.MustParseImageID(rebuildNewImageID), server.Status.Rebuild.TargetImageID)
	require.Equal(t, int32(1), server.Status.Rebuild.AcceptedAttempts)

	condition, conditionErr := server.StatusConditionRead(unikornv1core.ConditionHealthy)
	require.NoError(t, conditionErr)
	require.Equal(t, unikornv1core.ConditionReasonProvisioning, condition.Reason)
}

func TestReconcileServerImageClearsMarkerOnSuccess(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), AcceptedAttempts: 1}

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildNewImageID))
	require.NoError(t, err)
	require.Nil(t, server.Status.Rebuild)
}

func TestReconcileServerImageParksAcceptedFailure(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), AcceptedAttempts: 1}

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", rebuildNewImageID))
	require.ErrorIs(t, err, provisioners.ErrUserActionRequired)

	condition, conditionErr := server.StatusConditionRead(unikornv1core.ConditionHealthy)
	require.NoError(t, conditionErr)
	require.Equal(t, corev1.ConditionFalse, condition.Status)
}

func TestReconcileServerImageDoesNotRebuildUnrelatedError(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", rebuildNewImageID))
	require.NoError(t, err)
}

func TestReconcileServerImageRequiresPreviousLaunch(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Status.ProvisionedAt = nil

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.NoError(t, err)
	require.Nil(t, server.Status.Rebuild)
}

func TestReconcileServerImageConflictDoesNotConsumeAttempt(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(nil, gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusConflict})

	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Zero(t, server.Status.Rebuild.AcceptedAttempts)
}

// TestReconcileServerImageNewImageRearmsAfterParkedFailure pins the only
// remaining re-arm path for a parked (accepted-then-failed) rebuild: a
// changed desired image. A parked failure for image B does not itself
// retry; only Spec.Image.ID moving on to image C causes a fresh rebuild
// submission, and exactly one.
func TestReconcileServerImageNewImageRearmsAfterParkedFailure(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", openstack.ServerRebuildOptions{
		ImageID: idstest.MustParseImageID(rebuildThirdImageID),
	}).Return(novaRebuildServer("REBUILD", rebuildThirdImageID), nil)

	server := desiredRebuildServer()
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{
		TargetImageID:    idstest.MustParseImageID(rebuildNewImageID),
		AcceptedAttempts: 1,
	}

	// Parked: an accepted rebuild for image B (rebuildNewImageID) reached ERROR.
	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", rebuildNewImageID))
	require.ErrorIs(t, err, provisioners.ErrUserActionRequired)

	// Re-arm: the desired image moves on to C (rebuildThirdImageID).
	server.Spec.Image.ID = idstest.MustParseImageID(rebuildThirdImageID)

	_, err = openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", rebuildNewImageID))
	require.NoError(t, err)
	require.Equal(t, idstest.MustParseImageID(rebuildThirdImageID), server.Status.Rebuild.TargetImageID)
	require.Equal(t, int32(1), server.Status.Rebuild.AcceptedAttempts)
}

// TestReconcileServerImageParksWhenImageUnobservable pins the fail-closed
// handling for a launched server whose current image Nova cannot report (e.g.
// an out-of-band boot-from-volume server): convergence is undecidable — the
// desired-vs-observed diff has no observed side — so the server parks rather
// than silently reporting the spec converged, and no rebuild is ever
// submitted blind.
func TestReconcileServerImageParksWhenImageUnobservable(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, &servers.Server{ID: "server-1", Status: "ACTIVE"})
	require.ErrorIs(t, err, provisioners.ErrUserActionRequired)
	require.Nil(t, server.Status.Rebuild)
}

// TestReconcileServerImageLeavesUnobservablePrelaunchToCreate pins the
// pre-launch exception to the unobservable-image park: Nova can omit the
// image while a create is still in flight, and the create machinery owns that
// window, so the reconcile completes without parking or submitting a rebuild.
func TestReconcileServerImageLeavesUnobservablePrelaunchToCreate(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()
	server.Status.ProvisionedAt = nil

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, &servers.Server{ID: "server-1", Status: "BUILD"})
	require.NoError(t, err)
	require.Nil(t, server.Status.Rebuild)
}
