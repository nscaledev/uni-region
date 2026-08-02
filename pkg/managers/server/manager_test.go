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

//nolint:testpackage // Tests cover the unexported watch predicate directly.
package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/event"
)

func serverWithProviderCreateFailure() *unikornv1.Server {
	server := &unikornv1.Server{}
	server.SetActiveCondition(unikornv1.ActiveConditionReasonError)
	server.Status.Observed = &unikornv1.ServerObservedStatus{ServerGeneration: 1}

	return server
}

func TestProviderCreateFailureUpdate(t *testing.T) {
	t.Parallel()

	t.Run("PreLaunchError", func(t *testing.T) {
		t.Parallel()

		require.True(t, providerCreateFailureUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: &unikornv1.Server{},
			ObjectNew: serverWithProviderCreateFailure(),
		}))
	})

	t.Run("AlreadyErrored", func(t *testing.T) {
		t.Parallel()

		server := serverWithProviderCreateFailure()

		require.False(t, providerCreateFailureUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: server,
			ObjectNew: server.DeepCopy(),
		}))
	})

	t.Run("AlreadyLaunched", func(t *testing.T) {
		t.Parallel()

		server := serverWithProviderCreateFailure()
		launchedAt := metav1.NewTime(time.Now())
		server.Status.Observed.LaunchedAt = &launchedAt

		require.False(t, providerCreateFailureUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: &unikornv1.Server{},
			ObjectNew: server,
		}))
	})

	t.Run("RunningWithoutLaunchTimestamp", func(t *testing.T) {
		t.Parallel()

		server := serverWithProviderCreateFailure()
		server.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)

		require.False(t, providerCreateFailureUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: &unikornv1.Server{},
			ObjectNew: server,
		}))
	})

	// A server that has ever been provisioned must never re-arm the rebuild path,
	// even if its launch timestamp has been lost and the error phase then appears
	// (e.g. a flaky-provider re-reconcile after a controller restart).
	t.Run("ProvisionedWithoutLaunchTimestamp", func(t *testing.T) {
		t.Parallel()

		server := serverWithProviderCreateFailure()
		provisionedAt := metav1.NewTime(time.Now().Add(-time.Hour))
		server.Status.Observed.ProvisionedAt = &provisionedAt

		require.False(t, providerCreateFailureUpdate(event.TypedUpdateEvent[*unikornv1.Server]{
			ObjectOld: &unikornv1.Server{},
			ObjectNew: server,
		}))
	})
}
