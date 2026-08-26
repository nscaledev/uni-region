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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"
	serverprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/server"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	retryRegionID   = "region-1"
	retryIdentityID = "identity-1"
)

func retryServer(opts ...func(*regionv1.Server)) *regionv1.Server {
	opts = append([]func(*regionv1.Server){
		func(server *regionv1.Server) {
			server.Labels = map[string]string{
				coreconstants.NameLabel: "server-1",
				constants.RegionLabel:   retryRegionID,
				constants.IdentityLabel: retryIdentityID,
			}
		},
	}, opts...)

	return testServer(opts...)
}

func retryIdentity() *regionv1.Identity {
	identity := &regionv1.Identity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      retryIdentityID,
			Namespace: "default",
		},
	}

	identity.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "")

	return identity
}

func retryClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme, err := coreclient.NewScheme(regionv1.AddToScheme)
	require.NoError(t, err)

	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{regionv1.SchemeGroupVersion})
	mapper.Add(regionv1.SchemeGroupVersion.WithKind("Server"), meta.RESTScopeNamespace)

	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithRESTMapper(mapper).
		WithObjects(objects...).
		Build()
}

// withProviderCreateFailure marks a server as a terminal provider-create failure
// via the Active condition — the axis ProviderCreateFailure now keys off (Nova
// ERROR is surfaced as ActiveConditionReasonError by the monitor).
func withProviderCreateFailure(server *regionv1.Server) {
	server.SetActiveCondition(regionv1.ActiveConditionReasonError)
}

// activeReason reads the server's lifecycle Active condition, failing the test if
// the condition is absent. It replaces the assertions that used to read the
// deleted Status.Phase field.
func activeReason(t *testing.T, server *regionv1.Server) regionv1.ActiveConditionReason {
	t.Helper()

	active, err := regionv1.GetActiveCondition(server)
	require.NoError(t, err)

	return active.Reason
}

func withProviderCreateRetrying(server *regionv1.Server) {
	server.Status.ProviderCreateFailures = 1
	server.Status.ProviderCreateRetrying = true
}

func withRuntimeStatus(server *regionv1.Server) {
	privateIP := "10.0.0.10"
	publicIP := "203.0.113.10"
	macAddress := "00:11:22:33:44:55"
	scheduledAt := metav1.NewTime(time.Now().Add(-2 * time.Minute))

	server.Status.PrivateIP = &privateIP
	server.Status.PublicIP = &publicIP
	server.Status.MACAddress = &macAddress
	server.Status.ScheduledAt = &scheduledAt
}

func withSatisfiedProviderCreateGate(server *regionv1.Server) {
	server.Spec.ProviderCreateGates = []regionv1.ServerProviderCreateGate{{ConditionType: "test/gate"}}
	server.ProviderCreateGateStatusWrite("test/gate", corev1.ConditionTrue, false, "ib-manager", "Programmed", "satisfied on the first attempt")
}

func retryProvisioner(t *testing.T, server *regionv1.Server, options *serverprovisioner.Options, provider *mocktypes.MockProvider, recorders ...record.EventRecorder) *serverprovisioner.Provisioner {
	t.Helper()

	providers := mockproviders.NewMockProviders(gomock.NewController(t))
	providers.EXPECT().LookupCloud(retryRegionID).Return(provider, nil)

	return serverprovisioner.NewForTest(server, providers, options, recorders...)
}

func requireEvent(t *testing.T, recorder *record.FakeRecorder, values ...string) {
	t.Helper()

	select {
	case event := <-recorder.Events:
		for _, value := range values {
			require.Contains(t, event, value)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func requireNoEvent(t *testing.T, recorder *record.FakeRecorder) {
	t.Helper()

	select {
	case event := <-recorder.Events:
		t.Fatalf("unexpected event: %s", event)
	default:
	}
}

func TestProvision_ProviderCreateFailureDeletesAndYields(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	server := retryServer(withProviderCreateFailure, withRuntimeStatus, withSatisfiedProviderCreateGate)

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().DeleteServer(gomock.Any(), gomock.Any(), server).Return(nil)
	provider.EXPECT().UpdateServerState(gomock.Any(), gomock.Any(), server).Return(coreerrors.ErrResourceNotFound)

	cli := retryClient(t, retryIdentity(), server)
	recorder := record.NewFakeRecorder(2)
	prov := retryProvisioner(t, server, nil, provider, recorder)

	err := prov.Provision(coreclient.NewContext(t.Context(), cli))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Equal(t, int32(1), server.Status.ProviderCreateFailures)
	require.False(t, server.Status.ProviderCreateRetrying)
	require.Equal(t, regionv1.ActiveConditionReasonPending, activeReason(t, server))
	require.Nil(t, server.Status.PrivateIP)
	require.Nil(t, server.Status.PublicIP)
	// The MAC is owned exclusively by the monitor; the reconciler's create-failure
	// reset must not clear it. A stale value self-heals on the next ACTIVE poll.
	require.Equal(t, ptr.To("00:11:22:33:44:55"), server.Status.MACAddress)
	require.Nil(t, server.Status.ScheduledAt)
	// The gate satisfied on the first attempt is reset to Unknown so external
	// services re-run their pre-create work before the retry.
	gate, ok := server.ProviderCreateGateStatusRead("test/gate")
	require.True(t, ok)
	require.Equal(t, corev1.ConditionUnknown, gate.Status)
	require.Equal(t, "ProviderCreateRetry", gate.Reason)

	requireEvent(t, recorder, corev1.EventTypeNormal, "ProviderCreateRetrying", "attempt 1/3")
	requireEvent(t, recorder, corev1.EventTypeNormal, "ProviderCreateRetryReady", "attempt 1/3")
}

func TestProvision_ProviderCreateRetryKeepsDeleting(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	server := retryServer(withProviderCreateRetrying, withRuntimeStatus)

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().DeleteServer(gomock.Any(), gomock.Any(), server).Return(nil)
	provider.EXPECT().
		UpdateServerState(gomock.Any(), gomock.Any(), server).
		DoAndReturn(func(_ context.Context, _ *regionv1.Identity, s *regionv1.Server) error {
			withProviderCreateFailure(s)

			return nil
		})

	cli := retryClient(t, retryIdentity(), server)
	recorder := record.NewFakeRecorder(1)
	prov := retryProvisioner(t, server, nil, provider, recorder)

	err := prov.Provision(coreclient.NewContext(t.Context(), cli))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.Equal(t, int32(1), server.Status.ProviderCreateFailures)
	require.True(t, server.Status.ProviderCreateRetrying)
	// The runtime reset ran, clearing the terminal Error phase back to Pending.
	require.Equal(t, regionv1.ActiveConditionReasonPending, activeReason(t, server))
	requireNoEvent(t, recorder)
}

// TestProvision_ProviderCreateRetryKeepsDeletingWithGate proves a satisfied gate
// carried over from the initial create does not block the delete mop-up: while
// ProviderCreateRetrying is true the reconcile short-circuits into the delete and
// can never reach CreateServer, so the gate is only reset once deletion is
// confirmed (branch a) — never on a still-deleting pass. The DeleteServer mock
// expectation demanding a call is itself the proof the mop-up was not gated.
func TestProvision_ProviderCreateRetryKeepsDeletingWithGate(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	server := retryServer(withProviderCreateRetrying, withRuntimeStatus, withSatisfiedProviderCreateGate)

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().DeleteServer(gomock.Any(), gomock.Any(), server).Return(nil)
	provider.EXPECT().
		UpdateServerState(gomock.Any(), gomock.Any(), server).
		DoAndReturn(func(_ context.Context, _ *regionv1.Identity, s *regionv1.Server) error {
			withProviderCreateFailure(s)

			return nil
		})

	cli := retryClient(t, retryIdentity(), server)
	prov := retryProvisioner(t, server, nil, provider, record.NewFakeRecorder(1))

	err := prov.Provision(coreclient.NewContext(t.Context(), cli))
	require.ErrorIs(t, err, provisioners.ErrYield)
	require.True(t, server.Status.ProviderCreateRetrying)
	// The gate stays satisfied while the delete is in flight — it is not reset
	// until the deletion-confirmed branch runs.
	gate, ok := server.ProviderCreateGateStatusRead("test/gate")
	require.True(t, ok)
	require.Equal(t, corev1.ConditionTrue, gate.Status)
}

func TestProvision_ProviderCreateFailureStopsAtAttemptLimit(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	server := retryServer(withProviderCreateFailure)
	server.Status.ProviderCreateFailures = 2

	provider := mocktypes.NewMockProvider(ctrl)

	cli := retryClient(t, retryIdentity(), server)
	recorder := record.NewFakeRecorder(1)
	prov := retryProvisioner(t, server, &serverprovisioner.Options{ProviderCreateMaxAttempts: 3}, provider, recorder)

	err := prov.Provision(coreclient.NewContext(t.Context(), cli))
	require.ErrorContains(t, err, "provider server create failed after 3 attempts")
	require.ErrorIs(t, err, provisioners.ErrTerminal)
	require.Equal(t, int32(3), server.Status.ProviderCreateFailures)
	require.False(t, server.Status.ProviderCreateRetrying)
	requireEvent(t, recorder, corev1.EventTypeWarning, "ProviderCreateFailed", "after 3 attempts")
}

// TestProvision_ProviderCreateFailureAtLimitDoesNotAdvance proves that a
// re-reconcile of an already-exhausted server (e.g. after a controller restart,
// where the failure predicate still holds) aborts terminally without advancing
// the counter past the cap.
func TestProvision_ProviderCreateFailureAtLimitDoesNotAdvance(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	server := retryServer(withProviderCreateFailure)
	server.Status.ProviderCreateFailures = 3

	provider := mocktypes.NewMockProvider(ctrl)

	cli := retryClient(t, retryIdentity(), server)
	recorder := record.NewFakeRecorder(1)
	prov := retryProvisioner(t, server, &serverprovisioner.Options{ProviderCreateMaxAttempts: 3}, provider, recorder)

	err := prov.Provision(coreclient.NewContext(t.Context(), cli))
	require.ErrorIs(t, err, provisioners.ErrTerminal)
	require.Equal(t, int32(3), server.Status.ProviderCreateFailures)
	require.False(t, server.Status.ProviderCreateRetrying)
}

func TestProvision_LaunchedServerHealthErrorDoesNotRetryCreate(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	server := retryServer(withProviderCreateFailure)
	launchedAt := metav1.NewTime(time.Now().Add(-time.Minute))
	server.Status.LaunchedAt = &launchedAt

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(nil)

	cli := retryClient(t, retryIdentity(), server)
	prov := retryProvisioner(t, server, nil, provider)

	require.NoError(t, prov.Provision(coreclient.NewContext(t.Context(), cli)))
	require.Zero(t, server.Status.ProviderCreateFailures)
	require.False(t, server.Status.ProviderCreateRetrying)
}

// TestProvision_ProvisionedServerHealthErrorDoesNotRetryCreate proves the
// ProvisionedAt latch blocks a rebuild even when the launch timestamp and phase
// have been lost: a server that has ever been provisioned must never be deleted
// and recreated, only reconciled normally.
func TestProvision_ProvisionedServerHealthErrorDoesNotRetryCreate(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	server := retryServer(withProviderCreateFailure)
	provisionedAt := metav1.NewTime(time.Now().Add(-time.Hour))
	server.Status.ProvisionedAt = &provisionedAt

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(nil)

	cli := retryClient(t, retryIdentity(), server)
	prov := retryProvisioner(t, server, nil, provider)

	require.NoError(t, prov.Provision(coreclient.NewContext(t.Context(), cli)))
	require.Zero(t, server.Status.ProviderCreateFailures)
	require.False(t, server.Status.ProviderCreateRetrying)
}

// TestProvision_YieldStillReleasesConsumedReferences pins that a yielding pass
// (a rebuild in flight, a create retrying) still releases references to
// resources the spec no longer names. A rebuild yields for its entire duration
// — 30+ minutes on baremetal — and a dropped security group must not be
// undeletable for that window.
func TestProvision_YieldStillReleasesConsumedReferences(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	server := retryServer()

	// A security group carrying this server's consumption reference, which the
	// server's spec no longer names.
	droppedGroup := &regionv1.SecurityGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dropped-group",
			Namespace: "default",
			Labels: map[string]string{
				constants.IdentityLabel: retryIdentityID,
			},
			Finalizers: []string{"servers.region.unikorn-cloud.org/" + server.Name},
		},
	}

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(provisioners.ErrYield)

	cli := retryClient(t, retryIdentity(), server, droppedGroup)
	prov := retryProvisioner(t, server, nil, provider)

	require.ErrorIs(t, prov.Provision(coreclient.NewContext(t.Context(), cli)), provisioners.ErrYield)

	updated := &regionv1.SecurityGroup{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: "default", Name: "dropped-group"}, updated))
	require.Empty(t, updated.Finalizers, "a yielding pass must still release references the spec no longer holds")
}

// TestProvision_ParkStillReleasesConsumedReferences pins that a parked pass —
// a provider outcome satisfying provisioners.IsTerminal (here
// ErrUserActionRequired) — still releases references to resources the spec no
// longer names. A park persists until a spec edit, longer than any yield, so a
// dropped security group must not keep this server's finalizer and be
// undeletable for the lifetime of the park. The provider detaches dropped
// groups from the Neutron port before the image row runs, so releasing on a
// park is safe.
func TestProvision_ParkStillReleasesConsumedReferences(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	server := retryServer()

	// A security group carrying this server's consumption reference, which the
	// server's spec no longer names.
	droppedGroup := &regionv1.SecurityGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dropped-group",
			Namespace: "default",
			Labels: map[string]string{
				constants.IdentityLabel: retryIdentityID,
			},
			Finalizers: []string{"servers.region.unikorn-cloud.org/" + server.Name},
		},
	}

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(
		provisioners.UserActionRequired(unikornv1core.ConditionReasonErrored, "the provider rejected the rebuild toward the desired image; select a different image or replace the server"))

	cli := retryClient(t, retryIdentity(), server, droppedGroup)
	prov := retryProvisioner(t, server, nil, provider)

	err := prov.Provision(coreclient.NewContext(t.Context(), cli))
	require.True(t, provisioners.IsTerminal(err), "a parked pass must still carry its terminal disposition")

	updated := &regionv1.SecurityGroup{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: "default", Name: "dropped-group"}, updated))
	require.Empty(t, updated.Finalizers, "a parked pass must still release references the spec no longer holds")
}

// errProviderBoom is a sentinel for a genuine (non-yield) provider failure.
var errProviderBoom = errors.New("provider boom")

// TestProvision_NonYieldErrorDoesNotReleaseReferences pins that a genuine
// provider error returns early: reference release only accompanies a pass that
// reached the provider and left it in a known state (success or yield).
func TestProvision_NonYieldErrorDoesNotReleaseReferences(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	server := retryServer()

	droppedGroup := &regionv1.SecurityGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dropped-group",
			Namespace: "default",
			Labels: map[string]string{
				constants.IdentityLabel: retryIdentityID,
			},
			Finalizers: []string{"servers.region.unikorn-cloud.org/" + server.Name},
		},
	}

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), server, gomock.Any()).Return(errProviderBoom)

	cli := retryClient(t, retryIdentity(), server, droppedGroup)
	prov := retryProvisioner(t, server, nil, provider)

	require.ErrorIs(t, prov.Provision(coreclient.NewContext(t.Context(), cli)), errProviderBoom)

	updated := &regionv1.SecurityGroup{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: "default", Name: "dropped-group"}, updated))
	require.NotEmpty(t, updated.Finalizers)
}
