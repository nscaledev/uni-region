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

//nolint:testpackage // Tests cover the unexported monitor-side observation directly.
package openstack

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

const (
	observedImageID    = "33333333-3333-4333-a333-333333333333"
	observedOldImageID = "44444444-4444-4444-a444-444444444444"
)

func observedImagePointer(s string) *regionids.ImageID {
	id := idstest.MustParseImageID(s)

	return &id
}

func observedTimePointer(t time.Time) *metav1.Time {
	at := metav1.NewTime(t)

	return &at
}

// TestSetServerObservedImage tables the image read rules: a readable ref is
// recorded and overwrites, and an unreadable one preserves whatever was there.
// Preserving matters because the alternative — clearing — lets a single bad read
// erase a known image, which a reader cannot distinguish from "never observed".
func TestSetServerObservedImage(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		priorImage *regionids.ImageID
		novaImage  map[string]any
		want       *regionids.ImageID
	}{
		"readable ref is recorded": {
			novaImage: map[string]any{"id": observedImageID},
			want:      observedImagePointer(observedImageID),
		},
		"readable ref overwrites a previous image": {
			priorImage: observedImagePointer(observedOldImageID),
			novaImage:  map[string]any{"id": observedImageID},
			want:       observedImagePointer(observedImageID),
		},
		"absent ref preserves the previous image": {
			priorImage: observedImagePointer(observedOldImageID),
			novaImage:  nil,
			want:       observedImagePointer(observedOldImageID),
		},
		"empty ref preserves the previous image": {
			priorImage: observedImagePointer(observedOldImageID),
			novaImage:  map[string]any{"id": ""},
			want:       observedImagePointer(observedOldImageID),
		},
		"unparseable ref preserves the previous image": {
			priorImage: observedImagePointer(observedOldImageID),
			novaImage:  map[string]any{"id": "not-a-uuid"},
			want:       observedImagePointer(observedOldImageID),
		},
		"absent ref with no previous image records nothing": {
			novaImage: nil,
			want:      nil,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := &unikornv1.Server{}

			if testCase.priorImage != nil {
				server.Status.Observed = &unikornv1.ServerObservedStatus{Image: testCase.priorImage}
			}

			setServerObservedStatus(server, &servers.Server{
				ID:     "server-1",
				Status: novaStatusActive,
				Image:  testCase.novaImage,
			})

			require.NotNil(t, server.Status.Observed, "a successful poll always records an observation")
			require.Equal(t, testCase.want, server.Status.Observed.Image)
		})
	}
}

// TestSetServerObservedError tables the error read rules. The error is live state,
// not a latch: it clears on an authoritative non-error read. That is safe only
// because an unreachable provider aborts the poll before this is called.
func TestSetServerObservedError(t *testing.T) {
	t.Parallel()

	faultTime := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)

	testCases := map[string]struct {
		priorError *unikornv1.ServerObservedError
		novaStatus string
		novaFault  servers.Fault
		want       *unikornv1.ServerObservedError
	}{
		"error status records the provider fault": {
			novaStatus: novaStatusError,
			novaFault: servers.Fault{
				Code:    500,
				Created: faultTime,
				Message: "No valid host was found",
			},
			want: &unikornv1.ServerObservedError{
				Code:    ptr.To(int32(500)),
				Message: "No valid host was found",
				At:      observedTimePointer(faultTime),
			},
		},
		"non-error status clears a previously recorded error": {
			priorError: &unikornv1.ServerObservedError{Code: ptr.To(int32(500)), Message: "No valid host was found"},
			novaStatus: novaStatusActive,
			want:       nil,
		},
		"stale fault on a non-error server records nothing": {
			novaStatus: novaStatusActive,
			novaFault: servers.Fault{
				Code:    500,
				Created: faultTime,
				Message: "No valid host was found",
			},
			want: nil,
		},
		"error status with no provider timestamp leaves the time unset": {
			novaStatus: novaStatusError,
			novaFault: servers.Fault{
				Code:    500,
				Message: "No valid host was found",
			},
			want: &unikornv1.ServerObservedError{
				Code:    ptr.To(int32(500)),
				Message: "No valid host was found",
			},
		},
		"error status with no visible fault records an empty detail": {
			novaStatus: novaStatusError,
			want:       &unikornv1.ServerObservedError{},
		},
		"fault code beyond int32 is dropped rather than truncated": {
			novaStatus: novaStatusError,
			novaFault: servers.Fault{
				Code:    math.MaxInt32 + 1,
				Message: "No valid host was found",
			},
			want: &unikornv1.ServerObservedError{
				Message: "No valid host was found",
			},
		},
		"negative fault code is dropped": {
			novaStatus: novaStatusError,
			novaFault: servers.Fault{
				Code:    -1,
				Message: "No valid host was found",
			},
			want: &unikornv1.ServerObservedError{
				Message: "No valid host was found",
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := &unikornv1.Server{}

			if testCase.priorError != nil {
				server.Status.Observed = &unikornv1.ServerObservedStatus{Error: testCase.priorError}
			}

			setServerObservedStatus(server, &servers.Server{
				ID:     "server-1",
				Status: testCase.novaStatus,
				Fault:  testCase.novaFault,
			})

			require.NotNil(t, server.Status.Observed)
			require.Equal(t, testCase.want, server.Status.Observed.Error)
		})
	}
}

// TestSetServerObservedErrorDropsProviderDetail pins that the provider's internal
// detail never reaches status. It is an admin-only stack trace, and status is
// projected to API consumers.
func TestSetServerObservedErrorDropsProviderDetail(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}

	setServerObservedStatus(server, &servers.Server{
		ID:     "server-1",
		Status: novaStatusError,
		Fault: servers.Fault{
			Code:    500,
			Message: "No valid host was found",
			Details: "Traceback (most recent call last): nova/compute/manager.py",
		},
	})

	require.NotNil(t, server.Status.Observed.Error)
	require.NotContains(t, server.Status.Observed.Error.Message, "Traceback", "provider internals must not reach projected status")
}

// TestUpdateServerStateWithClientsRecordsObservedStatus pins the observation into
// the monitor's poll path, so the subtree is populated by the same provider read
// that drives health, MAC and phase rather than needing a second one.
func TestUpdateServerStateWithClientsRecordsObservedStatus(t *testing.T) {
	t.Parallel()

	compute := &stubComputeClient{server: &servers.Server{
		ID:     "nova-id",
		Status: novaStatusActive,
		Image:  map[string]any{"id": observedImageID},
	}}
	identity := &unikornv1.Identity{}
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{
		FlavorID: idstest.MustParseFlavorID("11111111-1111-4111-a111-111111111111"),
	}}
	server.Generation = 4

	provider := &Provider{
		openstack: &openStackClients{
			_region: &unikornv1.Region{},
		},
	}

	err := provider.updateServerStateWithClients(t.Context(), identity, server, compute,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return nil, errIronicUnavailable
		})

	require.NoError(t, err)
	require.NotNil(t, server.Status.Observed)
	require.Equal(t, int64(4), server.Status.Observed.Generation)
	require.Equal(t, observedImagePointer(observedImageID), server.Status.Observed.Image)
	require.Nil(t, server.Status.Observed.Error)
}

// TestSetServerObservedGeneration pins the freshness stamp. Without it an
// observation cannot be told apart from one taken before a spec edit.
func TestSetServerObservedGeneration(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}
	server.Generation = 7

	setServerObservedStatus(server, &servers.Server{
		ID:     "server-1",
		Status: novaStatusActive,
		Image:  map[string]any{"id": observedImageID},
	})

	require.Equal(t, int64(7), server.Status.Observed.Generation)
}

// TestSetServerObservedStatusStampsGenerationWithoutFacts pins that a poll which
// read the provider but could record nothing still creates the subtree. A present
// subtree with no image means "polled, image unreadable"; an absent one means
// "never successfully polled". Readers depend on the difference.
func TestSetServerObservedStatusStampsGenerationWithoutFacts(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}
	server.Generation = 3

	setServerObservedStatus(server, &servers.Server{
		ID:     "server-1",
		Status: novaStatusActive,
	})

	require.NotNil(t, server.Status.Observed)
	require.Equal(t, int64(3), server.Status.Observed.Generation)
	require.Nil(t, server.Status.Observed.Image)
	require.Nil(t, server.Status.Observed.Error)
}
