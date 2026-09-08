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

package v1alpha1_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func availableCondition(t *testing.T, server *regionv1.Server) *metav1.Condition {
	t.Helper()

	condition := meta.FindStatusCondition(server.Status.Conditions, string(unikornv1core.ConditionAvailable))
	require.NotNil(t, condition)

	return condition
}

// TestServerSetProvisioningConditionStampsGeneration pins that every outcome
// stamps the evaluated generation, and a generation bump is picked up on restamp.
func TestServerSetProvisioningConditionStampsGeneration(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		status corev1.ConditionStatus
		reason unikornv1core.ProvisioningConditionReason
	}{
		{corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned},
		{corev1.ConditionFalse, unikornv1core.ConditionReasonProvisioning},
		{corev1.ConditionFalse, unikornv1core.ConditionReasonErrored},
		{corev1.ConditionFalse, unikornv1core.ConditionReasonDeprovisioning},
	} {
		server := &regionv1.Server{ObjectMeta: metav1.ObjectMeta{Generation: 1}}
		server.SetProvisioningCondition(tc.status, tc.reason, "message")
		require.Equal(t, int64(1), availableCondition(t, server).ObservedGeneration)
		require.True(t, server.ProvisioningConditionCurrent())

		server.Generation = 2
		require.False(t, server.ProvisioningConditionCurrent())

		server.SetProvisioningCondition(tc.status, tc.reason, "message")
		require.Equal(t, int64(2), availableCondition(t, server).ObservedGeneration)
		require.True(t, server.ProvisioningConditionCurrent())
	}
}

// TestServerProvisioningConditionCurrent pins that a missing condition, a
// zero-stamped condition, and a stamp from a previous generation are not current.
func TestServerProvisioningConditionCurrent(t *testing.T) {
	t.Parallel()

	for _, setup := range []func(*regionv1.Server){
		func(*regionv1.Server) {},
		func(server *regionv1.Server) {
			unikornv1core.UpdateCondition(&server.Status.Conditions, unikornv1core.ConditionAvailable, corev1.ConditionTrue, string(unikornv1core.ConditionReasonProvisioned), "provisioned")
		},
		func(server *regionv1.Server) {
			server.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "provisioned")
			server.Generation = 2
		},
	} {
		server := &regionv1.Server{ObjectMeta: metav1.ObjectMeta{Generation: 1}}
		setup(server)
		require.False(t, server.ProvisioningConditionCurrent())
	}
}

// TestServerProvisioningConditionStaleWriteConflicts pins the concurrency
// property the stamp depends on: a reconciler holding a copy of the server from
// before a spec update stamps the generation it evaluated, and its status write
// is rejected on resourceVersion rather than landing under the newer generation.
func TestServerProvisioningConditionStaleWriteConflicts(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	server := &regionv1.Server{ObjectMeta: metav1.ObjectMeta{Name: "server", Namespace: "ns", Generation: 1}}

	scheme := runtime.NewScheme()
	require.NoError(t, regionv1.AddToScheme(scheme))

	cli := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&regionv1.Server{}).WithObjects(server).Build()

	stale := &regionv1.Server{}
	require.NoError(t, cli.Get(ctx, client.ObjectKeyFromObject(server), stale))

	// A concurrent spec update lands first; the fake client does not bump
	// metadata.generation itself, so the test does what the API server would.
	updated := stale.DeepCopy()
	updated.Generation = 2
	updated.Spec.Pause = true
	require.NoError(t, cli.Update(ctx, updated))

	stale.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "provisioned")
	require.Equal(t, int64(1), availableCondition(t, stale).ObservedGeneration)

	err := cli.Status().Update(ctx, stale)
	require.True(t, kerrors.IsConflict(err), "expected a conflict, got %v", err)

	stored := &regionv1.Server{}
	require.NoError(t, cli.Get(ctx, client.ObjectKeyFromObject(server), stored))
	require.Equal(t, int64(2), stored.Generation)
	require.Nil(t, meta.FindStatusCondition(stored.Status.Conditions, string(unikornv1core.ConditionAvailable)))
	require.False(t, stored.ProvisioningConditionCurrent())
}
