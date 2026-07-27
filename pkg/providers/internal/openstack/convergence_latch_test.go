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

//nolint:testpackage // Tests cover the unexported monitor-side convergence advance directly.
package openstack

import (
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/require"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
)

const (
	latchImageA = "11111111-1111-1111-1111-111111111111"
	latchImageB = "22222222-2222-2222-2222-222222222222"
)

// latchServer builds a Server CR at the given generation whose spec image is
// latchImageA, with Available and Active conditions in the given states —
// the CR as it stands at the top of a monitor poll, after setServerActive.
func latchServer(t *testing.T, generation int64, availReason unikornv1core.ProvisioningConditionReason, availStamp int64, activeReason unikornv1.ActiveConditionReason) *unikornv1.Server {
	t.Helper()

	s := &unikornv1.Server{}
	s.Generation = generation
	s.Spec.Image = &unikornv1.ServerImage{ID: idstest.MustParseImageID(latchImageA)}

	s.SetProvisioningCondition(corev1.ConditionTrue, availReason, "")

	if cond := meta.FindStatusCondition(s.Status.Conditions, string(unikornv1core.ConditionAvailable)); cond != nil {
		cond.ObservedGeneration = availStamp
	}

	s.SetActiveCondition(activeReason)
	s.Status.ObservedImageID = idstest.MustParseImageID(latchImageA)

	return s
}

func novaServer(image string) *servers.Server {
	out := &servers.Server{Status: "ACTIVE"}
	if image != "" {
		out.Image = map[string]any{"id": image}
	}

	return out
}

func latchStamp(t *testing.T, s *unikornv1.Server) int64 {
	t.Helper()

	cond := meta.FindStatusCondition(s.Status.Conditions, string(unikornv1core.ConditionActive))
	require.NotNil(t, cond)

	return cond.ObservedGeneration
}

func TestAdvanceServerConvergenceGates(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		server      func(t *testing.T) *unikornv1.Server
		nova        *servers.Server
		wantAdvance bool
	}{
		{
			name: "advances on running with all gates satisfied",
			server: func(t *testing.T) *unikornv1.Server {
				t.Helper()

				return latchServer(t, 4, unikornv1core.ConditionReasonProvisioned, 4, unikornv1.ActiveConditionReasonRunning)
			},
			nova:        novaServer(latchImageA),
			wantAdvance: true,
		},
		{
			name: "advances on stopped (deliberate rest state counts as arrival)",
			server: func(t *testing.T) *unikornv1.Server {
				t.Helper()

				return latchServer(t, 4, unikornv1core.ConditionReasonProvisioned, 4, unikornv1.ActiveConditionReasonStopped)
			},
			nova:        novaServer(latchImageA),
			wantAdvance: true,
		},
		{
			name: "gate 1 holds: available stamp lags the generation",
			server: func(t *testing.T) *unikornv1.Server {
				t.Helper()

				return latchServer(t, 4, unikornv1core.ConditionReasonProvisioned, 3, unikornv1.ActiveConditionReasonRunning)
			},
			nova:        novaServer(latchImageA),
			wantAdvance: false,
		},
		{
			name: "gate 1 holds: available is a yield (Provisioning), not Provisioned",
			server: func(t *testing.T) *unikornv1.Server {
				t.Helper()

				return latchServer(t, 4, unikornv1core.ConditionReasonProvisioning, 4, unikornv1.ActiveConditionReasonRunning)
			},
			nova:        novaServer(latchImageA),
			wantAdvance: false,
		},
		{
			name: "gate 2 holds: transient power state (Rebuilding)",
			server: func(t *testing.T) *unikornv1.Server {
				t.Helper()

				return latchServer(t, 4, unikornv1core.ConditionReasonProvisioned, 4, unikornv1.ActiveConditionReasonRebuilding)
			},
			nova:        novaServer(latchImageA),
			wantAdvance: false,
		},
		{
			name: "gate 2 holds: error blocks convergence",
			server: func(t *testing.T) *unikornv1.Server {
				t.Helper()

				return latchServer(t, 4, unikornv1core.ConditionReasonProvisioned, 4, unikornv1.ActiveConditionReasonError)
			},
			nova:        novaServer(latchImageA),
			wantAdvance: false,
		},
		{
			name: "gate 3 holds: observed image drifts from spec",
			server: func(t *testing.T) *unikornv1.Server {
				t.Helper()

				s := latchServer(t, 4, unikornv1core.ConditionReasonProvisioned, 4, unikornv1.ActiveConditionReasonRunning)
				s.Status.ObservedImageID = idstest.MustParseImageID(latchImageB)

				return s
			},
			nova:        novaServer(latchImageB),
			wantAdvance: false,
		},
		{
			name: "gate 3 fails closed: this poll's ref unreadable, retained observation ignored",
			server: func(t *testing.T) *unikornv1.Server {
				t.Helper()

				return latchServer(t, 4, unikornv1core.ConditionReasonProvisioned, 4, unikornv1.ActiveConditionReasonRunning)
			},
			nova:        novaServer(""),
			wantAdvance: false,
		},
		{
			name: "gate 3 fails closed: never-observed image with a spec image",
			server: func(t *testing.T) *unikornv1.Server {
				t.Helper()

				s := latchServer(t, 4, unikornv1core.ConditionReasonProvisioned, 4, unikornv1.ActiveConditionReasonRunning)
				s.Status.ObservedImageID = idstest.MustParseImageID("00000000-0000-0000-0000-000000000000")

				return s
			},
			nova:        novaServer(""),
			wantAdvance: false,
		},
		{
			name: "gate 3 vacuous for boot-from-volume (no spec image)",
			server: func(t *testing.T) *unikornv1.Server {
				t.Helper()

				s := latchServer(t, 4, unikornv1core.ConditionReasonProvisioned, 4, unikornv1.ActiveConditionReasonRunning)
				s.Spec.Image = nil
				s.Status.ObservedImageID = idstest.MustParseImageID("00000000-0000-0000-0000-000000000000")

				return s
			},
			nova:        novaServer(""),
			wantAdvance: true,
		},
		{
			name: "gate 4 holds: unsettled rebuild marker for the current target",
			server: func(t *testing.T) *unikornv1.Server {
				t.Helper()

				s := latchServer(t, 4, unikornv1core.ConditionReasonProvisioned, 4, unikornv1.ActiveConditionReasonRunning)
				s.Status.Rebuild = &unikornv1.ServerRebuildStatus{
					TargetImageID: idstest.MustParseImageID(latchImageA),
					State:         unikornv1.ServerRebuildStateInitiated,
				}

				return s
			},
			nova:        novaServer(latchImageA),
			wantAdvance: false,
		},
		{
			name: "gate 4 target-scoped: a superseded marker does not block",
			server: func(t *testing.T) *unikornv1.Server {
				t.Helper()

				s := latchServer(t, 4, unikornv1core.ConditionReasonProvisioned, 4, unikornv1.ActiveConditionReasonRunning)
				s.Status.Rebuild = &unikornv1.ServerRebuildStatus{
					TargetImageID: idstest.MustParseImageID(latchImageB),
					State:         unikornv1.ServerRebuildStateInitiated,
				}

				return s
			},
			nova:        novaServer(latchImageA),
			wantAdvance: true,
		},
		{
			name: "gate 4 settled marker (Succeeded) does not block",
			server: func(t *testing.T) *unikornv1.Server {
				t.Helper()

				s := latchServer(t, 4, unikornv1core.ConditionReasonProvisioned, 4, unikornv1.ActiveConditionReasonRunning)
				s.Status.Rebuild = &unikornv1.ServerRebuildStatus{
					TargetImageID: idstest.MustParseImageID(latchImageA),
					State:         unikornv1.ServerRebuildStateSucceeded,
				}

				return s
			},
			nova:        novaServer(latchImageA),
			wantAdvance: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			server := tc.server(t)
			before := latchStamp(t, server)

			advanceServerConvergence(server, tc.nova)

			want := before
			if tc.wantAdvance {
				want = server.Generation
			}

			require.Equal(t, want, latchStamp(t, server))
		})
	}
}

// A converged latch survives everything short of a new generation: later
// polls with blocked gates carry the stamp, never reset it.
func TestAdvanceServerConvergenceNeverRegresses(t *testing.T) {
	t.Parallel()

	server := latchServer(t, 5, unikornv1core.ConditionReasonProvisioned, 5, unikornv1.ActiveConditionReasonRunning)
	advanceServerConvergence(server, novaServer(latchImageA))
	require.Equal(t, int64(5), latchStamp(t, server))

	// The user stops the server; the monitor rewrites the reason and the
	// gates block (no re-advance needed) — the stamp must survive.
	server.SetActiveCondition(unikornv1.ActiveConditionReasonStopping)
	advanceServerConvergence(server, novaServer(latchImageA))
	require.Equal(t, int64(5), latchStamp(t, server))
}
