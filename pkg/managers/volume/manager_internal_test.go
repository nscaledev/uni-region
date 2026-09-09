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

package volume

import (
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"

	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestServerVolumesMapsAttachmentIntent(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{
		ObjectMeta: metav1.ObjectMeta{Namespace: "test"},
		Spec: unikornv1.ServerSpec{Volumes: []unikornv1.ServerVolumeSpec{
			{ID: "volume-a"},
			{ID: "volume-b"},
		}},
	}

	requests := serverVolumes(t.Context(), server)
	require.Equal(t, "test/volume-a", requests[0].String())
	require.Equal(t, "test/volume-b", requests[1].String())
}

func TestServerVolumeWatchMapsRemovedAttachmentIntent(t *testing.T) {
	t.Parallel()

	old := &unikornv1.Server{
		ObjectMeta: metav1.ObjectMeta{Namespace: "test", Generation: 1},
		Spec: unikornv1.ServerSpec{Volumes: []unikornv1.ServerVolumeSpec{
			{ID: "volume-a"},
			{ID: "volume-b"},
		}},
	}
	updated := old.DeepCopy()
	updated.Generation = 2
	updated.Spec.Volumes = nil

	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer queue.ShutDown()

	handler.TypedEnqueueRequestsFromMapFunc(serverVolumes).Update(
		t.Context(),
		event.TypedUpdateEvent[*unikornv1.Server]{ObjectOld: old, ObjectNew: updated},
		queue,
	)

	requests := make([]string, 0, queue.Len())

	for queue.Len() != 0 {
		request, shutdown := queue.Get()
		requests = append(requests, request.String())

		require.False(t, shutdown)
		queue.Done(request)
		queue.Forget(request)
	}

	require.ElementsMatch(t, []string{"test/volume-a", "test/volume-b"}, requests)
}

func TestServerUpdateWakesVolumesForIntentAndDeletion(t *testing.T) {
	t.Parallel()

	old := &unikornv1.Server{ObjectMeta: metav1.ObjectMeta{Generation: 1}}
	updated := old.DeepCopy()
	updated.Generation = 2
	require.True(t, serverUpdate(event.TypedUpdateEvent[*unikornv1.Server]{ObjectOld: old, ObjectNew: updated}))

	deleting := old.DeepCopy()
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	require.True(t, serverUpdate(event.TypedUpdateEvent[*unikornv1.Server]{ObjectOld: old, ObjectNew: deleting}))

	require.False(t, serverUpdate(event.TypedUpdateEvent[*unikornv1.Server]{ObjectOld: old, ObjectNew: old.DeepCopy()}))
}
