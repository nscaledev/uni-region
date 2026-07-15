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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	rebuildOldImageID = "11111111-1111-4111-a111-111111111111"
	rebuildNewImageID = "22222222-2222-4222-a222-222222222222"
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
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Equal(t, idstest.MustParseImageID(rebuildNewImageID), server.Status.Rebuild.TargetImageID)
	require.Equal(t, int32(1), server.Status.Rebuild.AcceptedAttempts)
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
	require.ErrorIs(t, err, provisioners.ErrYield)
}

func TestReconcileServerImageYieldsWhileNovaRebuilds(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	server := desiredRebuildServer()

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("REBUILD", rebuildNewImageID))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Equal(t, unikornv1.InstanceLifecyclePhaseBuilding, server.Status.Phase)
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

func TestReconcileServerImageNewGenerationRearms(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	server := desiredRebuildServer()
	server.Spec.RebuildGeneration = 2
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{
		TargetImageID:    idstest.MustParseImageID(rebuildNewImageID),
		Generation:       1,
		AcceptedAttempts: 1,
	}

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ACTIVE", rebuildOldImageID))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Equal(t, int64(2), server.Status.Rebuild.Generation)
	require.Equal(t, int32(1), server.Status.Rebuild.AcceptedAttempts)
}

func TestReconcileServerImageNewGenerationRearmsAfterError(t *testing.T) {
	t.Parallel()

	client := mock.NewMockServerInterface(gomock.NewController(t))
	client.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptions()).
		Return(novaRebuildServer("REBUILD", rebuildNewImageID), nil)

	server := desiredRebuildServer()
	server.Spec.RebuildGeneration = 2
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{
		TargetImageID:    idstest.MustParseImageID(rebuildNewImageID),
		Generation:       1,
		AcceptedAttempts: 1,
	}

	_, err := openstack.ReconcileServerImage(t.Context(), client, server, novaRebuildServer("ERROR", rebuildNewImageID))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Equal(t, int64(2), server.Status.Rebuild.Generation)
	require.Equal(t, int32(1), server.Status.Rebuild.AcceptedAttempts)
}
