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

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"

	corev1 "k8s.io/api/core/v1"
)

func TestServerDeleteHeldOnlyWhileSpawning(t *testing.T) {
	t.Parallel()

	cases := []struct {
		status    string
		taskState string
		held      bool
	}{
		{status: "BUILD", taskState: "spawning", held: true},
		{status: "REBUILD", taskState: "rebuild_spawning", held: true},
		{status: "BUILD", taskState: "scheduling"},
		{status: "BUILD", taskState: "networking"},
		{status: "BUILD", taskState: "block_device_mapping"},
		{status: "BUILD"},
		{status: "REBUILD", taskState: "rebuilding"},
		{status: "ACTIVE"},
		{status: "ACTIVE", taskState: "powering-off"},
		{status: "ERROR", taskState: "spawning"},
		{status: "SHUTOFF", taskState: "powering-on"},
	}

	for _, tc := range cases {
		t.Run(tc.status+"/"+tc.taskState, func(t *testing.T) {
			t.Parallel()

			server := &servers.Server{Status: tc.status, TaskState: tc.taskState}

			require.Equal(t, tc.held, openstack.ServerDeleteHeld(server))
		})
	}
}

func TestHoldServerDeleteTracksTheHoldOnACondition(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}
	nova := &servers.Server{ID: "nova-server", Status: "BUILD", TaskState: "spawning"}

	require.ErrorIs(t, openstack.HoldServerDelete(t.Context(), server, nova), provisioners.ErrYield)

	held, err := unikornv1.GetDeletionHeldCondition(server)
	require.NoError(t, err)
	require.Equal(t, corev1.ConditionTrue, held.Status)
	require.Equal(t, unikornv1.DeletionHeldConditionReasonProviderBuilding, held.Reason)

	began := held.LastTransitionTime

	require.ErrorIs(t, openstack.HoldServerDelete(t.Context(), server, nova), provisioners.ErrYield)

	held, err = unikornv1.GetDeletionHeldCondition(server)
	require.NoError(t, err)
	require.Equal(t, began, held.LastTransitionTime, "a later held pass must keep the time the hold began")

	openstack.ReleaseServerDelete(server)

	held, err = unikornv1.GetDeletionHeldCondition(server)
	require.NoError(t, err)
	require.Equal(t, corev1.ConditionFalse, held.Status)
	require.Equal(t, unikornv1.DeletionHeldConditionReasonReleased, held.Reason)
}

func TestReleaseServerDeleteLeavesAnUnheldServerAlone(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}

	openstack.ReleaseServerDelete(server)

	_, err := unikornv1.GetDeletionHeldCondition(server)
	require.Error(t, err)
}
