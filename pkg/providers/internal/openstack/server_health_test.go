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

//nolint:testpackage
package openstack

import (
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/require"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
)

func TestConvertServerHealthStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		server      *servers.Server
		wantStatus  corev1.ConditionStatus
		wantReason  unikornv1core.ConditionReason
		wantMessage string
	}{
		{
			name:        "nil server",
			server:      nil,
			wantStatus:  corev1.ConditionUnknown,
			wantReason:  unikornv1core.ConditionReasonUnknown,
			wantMessage: "unable to determine server status",
		},
		{
			name:        "active",
			server:      &servers.Server{Status: "ACTIVE"},
			wantStatus:  corev1.ConditionTrue,
			wantReason:  unikornv1core.ConditionReasonHealthy,
			wantMessage: "server is healthy",
		},
		{
			name:        "error without fault",
			server:      &servers.Server{Status: "ERROR"},
			wantStatus:  corev1.ConditionFalse,
			wantReason:  unikornv1core.ConditionReasonErrored,
			wantMessage: "server is in an error state",
		},
		{
			// Nova attaches the scheduling/build failure cause to the server
			// fault; surface it so the CR condition explains the error rather
			// than requiring cloud-side log access.
			name: "error with fault message",
			server: &servers.Server{
				Status: "ERROR",
				Fault: servers.Fault{
					Code:    500,
					Message: "No valid host was found. There are not enough hosts available.",
				},
			},
			wantStatus:  corev1.ConditionFalse,
			wantReason:  unikornv1core.ConditionReasonErrored,
			wantMessage: "server is in an error state: No valid host was found. There are not enough hosts available.",
		},
		{
			// A stale fault from a recovered server must not leak into the
			// healthy condition message.
			name: "active with stale fault",
			server: &servers.Server{
				Status: "ACTIVE",
				Fault:  servers.Fault{Message: "old failure"},
			},
			wantStatus:  corev1.ConditionTrue,
			wantReason:  unikornv1core.ConditionReasonHealthy,
			wantMessage: "server is healthy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			status, reason, message := convertServerHealthStatus(tt.server)

			require.Equal(t, tt.wantStatus, status)
			require.Equal(t, tt.wantReason, reason)
			require.Equal(t, tt.wantMessage, message)
		})
	}
}
