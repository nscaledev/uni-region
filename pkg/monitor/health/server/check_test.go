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

package server_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	healthserver "github.com/unikorn-cloud/region/pkg/monitor/health/server"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	namespace  = "test-ns"
	regionID   = "region-1"
	identityID = "identity-1"
	serverID   = "server-1"
	orgID      = "org-1"
)

// captureSink is a logr.LogSink that records Info calls so tests can assert on them.
// entries is a shared pointer so that copies produced by WithValues all write to the
// same slice (logr calls WithValues even with an empty key list).
type captureSink struct {
	entries   *[]map[string]any
	presetKVs []any
}

func newCaptureSink() *captureSink {
	entries := make([]map[string]any, 0)
	return &captureSink{entries: &entries}
}

var _ logr.LogSink = (*captureSink)(nil)

func (s *captureSink) Init(logr.RuntimeInfo)        {}
func (s *captureSink) Enabled(int) bool             { return true }
func (s *captureSink) Error(error, string, ...any)  {}
func (s *captureSink) WithName(string) logr.LogSink { return s }

func (s *captureSink) WithValues(kvs ...any) logr.LogSink {
	c := *s // shares the entries pointer; each copy gets its own presetKVs
	c.presetKVs = append(append([]any{}, s.presetKVs...), kvs...)

	return &c
}

func (s *captureSink) Info(_ int, msg string, keysAndValues ...any) {
	entry := map[string]any{"_msg": msg}

	for i := 0; i+1 < len(s.presetKVs); i += 2 {
		entry[fmt.Sprint(s.presetKVs[i])] = s.presetKVs[i+1]
	}

	for i := 0; i+1 < len(keysAndValues); i += 2 {
		entry[fmt.Sprint(keysAndValues[i])] = keysAndValues[i+1]
	}

	*s.entries = append(*s.entries, entry)
}

func (s *captureSink) transitionEntries() []map[string]any {
	var out []map[string]any

	for _, e := range *s.entries {
		if e["_msg"] == "instance state transition" {
			out = append(out, e)
		}
	}

	return out
}

func newFakeClient(t *testing.T, objects ...runtime.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&unikornv1.Server{})

	for _, o := range objects {
		builder = builder.WithRuntimeObjects(o)
	}

	return builder.Build()
}

func serverFixture(phase unikornv1.InstanceLifecyclePhase) *unikornv1.Server {
	return &unikornv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serverID,
			Namespace: namespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel: orgID,
				constants.RegionLabel:           regionID,
				constants.IdentityLabel:         identityID,
			},
		},
		Status: unikornv1.ServerStatus{
			Phase: phase,
		},
	}
}

func identityFixture() *unikornv1.Identity {
	return &unikornv1.Identity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      identityID,
			Namespace: namespace,
		},
	}
}

// runCheck builds a Checker, injects a capturing logger, and runs Check.
func runCheck(t *testing.T, srv *unikornv1.Server, updateFn func(*unikornv1.Server)) (*captureSink, error) {
	t.Helper()

	ctrl := gomock.NewController(t)

	mockProvider := mocktypes.NewMockProvider(ctrl)
	mockProvider.EXPECT().
		UpdateServerState(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ *unikornv1.Identity, s *unikornv1.Server) error {
			updateFn(s)
			return nil
		})

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(regionID).Return(mockProvider, nil)

	sink := newCaptureSink()
	ctx := logr.NewContext(t.Context(), logr.New(sink))

	checker := healthserver.New(newFakeClient(t, identityFixture(), srv), namespace, providers)

	return sink, checker.Check(ctx)
}

// TestCheckServerLogsOnPhaseChange verifies that a transition log is emitted when the
// server's lifecycle phase changes, and that it contains the required fields.
func TestCheckServerLogsOnPhaseChange(t *testing.T) {
	t.Parallel()

	srv := serverFixture(unikornv1.InstanceLifecyclePhasePending)

	sink, err := runCheck(t, srv, func(s *unikornv1.Server) {
		s.Status.Phase = unikornv1.InstanceLifecyclePhaseRunning
	})

	require.NoError(t, err)

	entries := sink.transitionEntries()
	require.Len(t, entries, 1)
	require.Equal(t, serverID, entries[0]["instance_id"])
	require.Equal(t, orgID, entries[0]["org_id"])
	require.Equal(t, regionID, entries[0]["region_id"])
	require.Equal(t, unikornv1.InstanceLifecyclePhasePending, entries[0]["from_state"])
	require.Equal(t, unikornv1.InstanceLifecyclePhaseRunning, entries[0]["to_state"])
	require.NotZero(t, entries[0]["time_since_creation_ms"])
}

// TestCheckServerNoLogWhenPhaseUnchanged verifies that no transition log is emitted
// when the provider reports the same phase.
func TestCheckServerNoLogWhenPhaseUnchanged(t *testing.T) {
	t.Parallel()

	srv := serverFixture(unikornv1.InstanceLifecyclePhaseRunning)

	sink, err := runCheck(t, srv, func(s *unikornv1.Server) {
		s.Status.Phase = unikornv1.InstanceLifecyclePhaseRunning
	})

	require.NoError(t, err)
	require.Empty(t, sink.transitionEntries())
}

// TestCheckServerNoLogWhenOnlyConditionChanges verifies that a health condition change
// does not produce a transition log when the phase is unchanged.
func TestCheckServerNoLogWhenOnlyConditionChanges(t *testing.T) {
	t.Parallel()

	srv := serverFixture(unikornv1.InstanceLifecyclePhaseRunning)

	sink, err := runCheck(t, srv, func(s *unikornv1.Server) {
		s.StatusConditionWrite(unikornv1core.ConditionHealthy, corev1.ConditionFalse, unikornv1core.ConditionReasonDegraded, "")
	})

	require.NoError(t, err)
	require.Empty(t, sink.transitionEntries())
}
