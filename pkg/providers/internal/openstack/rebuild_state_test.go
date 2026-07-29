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

//nolint:testpackage // Tests cover the unexported monitor-side state advance directly.
package openstack

import (
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"
)

const (
	rebuildStateTargetImageID    = "22222222-2222-4222-a222-222222222222"
	rebuildStateOffTargetImageID = "11111111-1111-4111-a111-111111111111"
)

// TestAdvanceServerRebuildState tables the monitor's evidence rules: forward-only
// rank enforcement, attribution by image ref, and the task_state quiescence gate.
func TestAdvanceServerRebuildState(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		state      unikornv1.ServerRebuildState
		novaStatus string
		novaImage  map[string]any
		taskState  string
		want       unikornv1.ServerRebuildState
	}{
		// ref == target, quiescent, non-error: convergence. SHUTOFF settles the same.
		"ACTIVE on target quiescent advances Rebuilding to Succeeded": {
			state:      unikornv1.ServerRebuildStateRebuilding,
			novaStatus: "ACTIVE",
			novaImage:  map[string]any{"id": rebuildStateTargetImageID},
			want:       unikornv1.ServerRebuildStateSucceeded,
		},
		"SHUTOFF on target quiescent advances Rebuilding to Succeeded": {
			state:      unikornv1.ServerRebuildStateRebuilding,
			novaStatus: "SHUTOFF",
			novaImage:  map[string]any{"id": rebuildStateTargetImageID},
			want:       unikornv1.ServerRebuildStateSucceeded,
		},
		// ref flips at accept, so a quiescent converged ref advances even Initiated straight to Succeeded.
		"ACTIVE on target quiescent advances Initiated to Succeeded": {
			state:      unikornv1.ServerRebuildStateInitiated,
			novaStatus: "ACTIVE",
			novaImage:  map[string]any{"id": rebuildStateTargetImageID},
			want:       unikornv1.ServerRebuildStateSucceeded,
		},
		// task_state gate: ref == target but the task still active reads as Rebuilding, not Succeeded.
		"ACTIVE on target with active task advances Initiated to Rebuilding": {
			state:      unikornv1.ServerRebuildStateInitiated,
			novaStatus: "ACTIVE",
			novaImage:  map[string]any{"id": rebuildStateTargetImageID},
			taskState:  "rebuild_spawning",
			want:       unikornv1.ServerRebuildStateRebuilding,
		},
		"ACTIVE on target with active task does not advance Rebuilding to Succeeded": {
			state:      unikornv1.ServerRebuildStateRebuilding,
			novaStatus: "ACTIVE",
			novaImage:  map[string]any{"id": rebuildStateTargetImageID},
			taskState:  "rebuilding",
			want:       unikornv1.ServerRebuildStateRebuilding,
		},
		// REBUILD on the target ref is in-flight activity → Rebuilding.
		"REBUILD on target advances Initiated to Rebuilding": {
			state:      unikornv1.ServerRebuildStateInitiated,
			novaStatus: "REBUILD",
			novaImage:  map[string]any{"id": rebuildStateTargetImageID},
			want:       unikornv1.ServerRebuildStateRebuilding,
		},
		// ref == target, ERROR: a failed rebuild whatever the marker state.
		"ERROR on target advances Initiated to Failed": {
			state:      unikornv1.ServerRebuildStateInitiated,
			novaStatus: "ERROR",
			novaImage:  map[string]any{"id": rebuildStateTargetImageID},
			want:       unikornv1.ServerRebuildStateFailed,
		},
		// ref != target, still Initiated: no advance — an unattributed advance would destroy the submission gate.
		"REBUILD off target leaves Initiated alone": {
			state:      unikornv1.ServerRebuildStateInitiated,
			novaStatus: "REBUILD",
			novaImage:  map[string]any{"id": rebuildStateOffTargetImageID},
			want:       unikornv1.ServerRebuildStateInitiated,
		},
		// Supersession: accepted, readable ref off target, task quiesced → Failed.
		"STABLE off target quiescent advances Rebuilding to Failed": {
			state:      unikornv1.ServerRebuildStateRebuilding,
			novaStatus: "ACTIVE",
			novaImage:  map[string]any{"id": rebuildStateOffTargetImageID},
			want:       unikornv1.ServerRebuildStateFailed,
		},
		// Off-target ref, task still active: in flight, not yet superseded — no advance.
		"STABLE off target with active task leaves Rebuilding alone": {
			state:      unikornv1.ServerRebuildStateRebuilding,
			novaStatus: "ACTIVE",
			novaImage:  map[string]any{"id": rebuildStateOffTargetImageID},
			taskState:  "rebuilding",
			want:       unikornv1.ServerRebuildStateRebuilding,
		},
		// A foreign REBUILD off our target is active, not supersession.
		"REBUILD off target leaves Rebuilding alone": {
			state:      unikornv1.ServerRebuildStateRebuilding,
			novaStatus: "REBUILD",
			novaImage:  map[string]any{"id": rebuildStateOffTargetImageID},
			want:       unikornv1.ServerRebuildStateRebuilding,
		},
		// ERROR off target with marker >= Rebuilding: attributable via durable acceptance → Failed.
		"ERROR off target advances Rebuilding to Failed": {
			state:      unikornv1.ServerRebuildStateRebuilding,
			novaStatus: "ERROR",
			novaImage:  map[string]any{"id": rebuildStateOffTargetImageID},
			want:       unikornv1.ServerRebuildStateFailed,
		},
		// ERROR while Initiated, unmoved ref: unattributable — the reconciler owns it as unrelated.
		"ERROR off target leaves Initiated alone": {
			state:      unikornv1.ServerRebuildStateInitiated,
			novaStatus: "ERROR",
			novaImage:  map[string]any{"id": rebuildStateOffTargetImageID},
			want:       unikornv1.ServerRebuildStateInitiated,
		},
		// A stable status on a non-target ref carries no evidence for an unaccepted marker.
		"ACTIVE off target leaves Initiated alone": {
			state:      unikornv1.ServerRebuildStateInitiated,
			novaStatus: "ACTIVE",
			novaImage:  map[string]any{"id": rebuildStateOffTargetImageID},
			want:       unikornv1.ServerRebuildStateInitiated,
		},
		// Unreadable ref with durable acceptance and ERROR → Failed (why P4 precedes P5).
		"ERROR unreadable ref advances Rebuilding to Failed": {
			state:      unikornv1.ServerRebuildStateRebuilding,
			novaStatus: "ERROR",
			novaImage:  map[string]any{},
			want:       unikornv1.ServerRebuildStateFailed,
		},
		// Unreadable ref while Initiated: intent without acceptance — no advance.
		"ERROR unreadable ref leaves Initiated alone": {
			state:      unikornv1.ServerRebuildStateInitiated,
			novaStatus: "ERROR",
			novaImage:  map[string]any{},
			want:       unikornv1.ServerRebuildStateInitiated,
		},
		// Unreadable ref with no failure evidence is a no-op.
		"unreadable ref leaves Rebuilding alone": {
			state:      unikornv1.ServerRebuildStateRebuilding,
			novaStatus: "ACTIVE",
			novaImage:  map[string]any{},
			want:       unikornv1.ServerRebuildStateRebuilding,
		},
		"unparseable ref leaves Rebuilding alone": {
			state:      unikornv1.ServerRebuildStateRebuilding,
			novaStatus: "ACTIVE",
			novaImage:  map[string]any{"id": "not-a-uuid"},
			want:       unikornv1.ServerRebuildStateRebuilding,
		},
		// Forward-only: a late REBUILD observation never retreats a terminal.
		"late REBUILD never retreats Succeeded": {
			state:      unikornv1.ServerRebuildStateSucceeded,
			novaStatus: "REBUILD",
			novaImage:  map[string]any{"id": rebuildStateTargetImageID},
			want:       unikornv1.ServerRebuildStateSucceeded,
		},
		"late REBUILD never retreats Failed": {
			state:      unikornv1.ServerRebuildStateFailed,
			novaStatus: "REBUILD",
			novaImage:  map[string]any{"id": rebuildStateTargetImageID},
			want:       unikornv1.ServerRebuildStateFailed,
		},
		// Terminals are peers — neither flips. Only the reconciler's park can supersede one, never the monitor.
		"Succeeded never flips to Failed": {
			state:      unikornv1.ServerRebuildStateSucceeded,
			novaStatus: "ERROR",
			novaImage:  map[string]any{"id": rebuildStateTargetImageID},
			want:       unikornv1.ServerRebuildStateSucceeded,
		},
		"Succeeded off target quiescent does not supersede via the monitor": {
			state:      unikornv1.ServerRebuildStateSucceeded,
			novaStatus: "ACTIVE",
			novaImage:  map[string]any{"id": rebuildStateOffTargetImageID},
			want:       unikornv1.ServerRebuildStateSucceeded,
		},
		"Failed never flips to Succeeded": {
			state:      unikornv1.ServerRebuildStateFailed,
			novaStatus: "ACTIVE",
			novaImage:  map[string]any{"id": rebuildStateTargetImageID},
			want:       unikornv1.ServerRebuildStateFailed,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := &unikornv1.Server{}
			server.Status.Rebuild = &unikornv1.ServerRebuildStatus{
				TargetImageID: idstest.MustParseImageID(rebuildStateTargetImageID),
				State:         testCase.state,
			}

			advanceServerRebuildState(server, &servers.Server{
				ID:        "server-1",
				Status:    testCase.novaStatus,
				Image:     testCase.novaImage,
				TaskState: testCase.taskState,
			})

			require.Equal(t, testCase.want, server.Status.Rebuild.State)
			require.Equal(t, idstest.MustParseImageID(rebuildStateTargetImageID), server.Status.Rebuild.TargetImageID, "the monitor must never retarget the marker")
		})
	}
}

// TestAdvanceServerRebuildStateNilMarker pins that the monitor never creates a
// marker where none exists: observation is stimulus, never authorization.
func TestAdvanceServerRebuildStateNilMarker(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}

	advanceServerRebuildState(server, &servers.Server{
		ID:     "server-1",
		Status: "REBUILD",
		Image:  map[string]any{"id": rebuildStateTargetImageID},
	})

	require.Nil(t, server.Status.Rebuild)
}
