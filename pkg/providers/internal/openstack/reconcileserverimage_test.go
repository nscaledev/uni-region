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
	"errors"
	"net/http"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack/mock"
)

var errRebuildFailed = errors.New("boom")

//nolint:unparam // Keep the helper shaped for desired-image test cases.
func desiredServer(imageID string) *unikornv1.Server {
	return &unikornv1.Server{
		Spec: unikornv1.ServerSpec{
			Image: &unikornv1.ServerImage{ID: imageID},
		},
	}
}

func TestReconcileServerImageRebuildsOnImageChange(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock.NewMockServerInterface(ctrl)

	openstackServer := &servers.Server{
		ID:     "srv-1",
		Status: "ACTIVE",
		Image:  map[string]any{"id": "image-old"},
	}

	client.EXPECT().RebuildServer(gomock.Any(), "srv-1", "image-new").Return(&servers.Server{}, nil)

	result, err := openstack.ReconcileServerImage(t.Context(), client, desiredServer("image-new"), openstackServer)

	require.ErrorIs(t, err, provisioners.ErrYield)
	assert.Equal(t, openstackServer, result)
}

func TestReconcileServerImageYieldsWhileRebuilding(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock.NewMockServerInterface(ctrl)

	// No RebuildServer expectation: a rebuild already in progress must not
	// trigger another. gomock fails the test if RebuildServer is called.
	openstackServer := &servers.Server{ID: "srv-1", Status: "REBUILD", Image: map[string]any{"id": "image-new"}}

	_, err := openstack.ReconcileServerImage(t.Context(), client, desiredServer("image-new"), openstackServer)

	require.ErrorIs(t, err, provisioners.ErrYield)
}

func TestReconcileServerImageNoOpWhenImageMatches(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock.NewMockServerInterface(ctrl)

	openstackServer := &servers.Server{ID: "srv-1", Status: "ACTIVE", Image: map[string]any{"id": "image-new"}}

	result, err := openstack.ReconcileServerImage(t.Context(), client, desiredServer("image-new"), openstackServer)

	require.NoError(t, err)
	assert.Equal(t, openstackServer, result)
}

func TestReconcileServerImageNoOpForBootFromVolume(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock.NewMockServerInterface(ctrl)

	// Image is nil for a boot-from-volume server; the current image is
	// indeterminate so no rebuild is attempted.
	openstackServer := &servers.Server{ID: "srv-1", Status: "ACTIVE", Image: nil}

	_, err := openstack.ReconcileServerImage(t.Context(), client, desiredServer("image-new"), openstackServer)

	require.NoError(t, err)
}

func TestReconcileServerImageNoOpWithoutDesiredImage(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock.NewMockServerInterface(ctrl)

	openstackServer := &servers.Server{ID: "srv-1", Status: "ACTIVE", Image: map[string]any{"id": "image-old"}}

	_, err := openstack.ReconcileServerImage(t.Context(), client, &unikornv1.Server{}, openstackServer)

	require.NoError(t, err)
}

func TestReconcileServerImageYieldsOnConflict(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock.NewMockServerInterface(ctrl)

	openstackServer := &servers.Server{ID: "srv-1", Status: "ACTIVE", Image: map[string]any{"id": "image-old"}}

	client.EXPECT().RebuildServer(gomock.Any(), "srv-1", "image-new").
		Return(nil, gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusConflict})

	_, err := openstack.ReconcileServerImage(t.Context(), client, desiredServer("image-new"), openstackServer)

	require.ErrorIs(t, err, provisioners.ErrYield)
}

func TestReconcileServerImagePropagatesError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock.NewMockServerInterface(ctrl)

	openstackServer := &servers.Server{ID: "srv-1", Status: "ACTIVE", Image: map[string]any{"id": "image-old"}}

	client.EXPECT().RebuildServer(gomock.Any(), "srv-1", "image-new").Return(nil, errRebuildFailed)

	_, err := openstack.ReconcileServerImage(t.Context(), client, desiredServer("image-new"), openstackServer)

	require.Error(t, err)
	require.NotErrorIs(t, err, provisioners.ErrYield)
}
