/*
Copyright 2025 the Unikorn Authors.
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
package storage

import (
	"testing"

	"github.com/stretchr/testify/require"

	unikorncorev1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	servererrors "github.com/unikorn-cloud/core/pkg/server/errors"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func TestValidateSnapshotPolicyListSemanticRules(t *testing.T) {
	t.Parallel()

	// daily is the valid baseline; each case mutates a copy.
	daily := func(configure func(*openapi.StorageSnapshotPolicyV2Spec)) openapi.StorageSnapshotPolicyV2Spec {
		policy := openapi.StorageSnapshotPolicyV2Spec{
			Name: "daily",
			Schedule: openapi.StorageSnapshotScheduleV2Spec{
				Interval:  openapi.StorageSnapshotScheduleIntervalV2Daily,
				TimeOfDay: ptr.To("04:00Z"),
			},
			Retention: openapi.StorageSnapshotRetentionV2Spec{Keep: 7},
		}

		if configure != nil {
			configure(&policy)
		}

		return policy
	}

	for _, tt := range []struct {
		name      string
		policies  openapi.StorageSnapshotPolicyListV2Spec
		wantError bool
	}{
		{
			name:     "empty list is allowed",
			policies: openapi.StorageSnapshotPolicyListV2Spec{},
		},
		{
			name: "valid hourly has no time fields",
			policies: openapi.StorageSnapshotPolicyListV2Spec{daily(func(p *openapi.StorageSnapshotPolicyV2Spec) {
				p.Name = "hourly"
				p.Schedule = openapi.StorageSnapshotScheduleV2Spec{Interval: openapi.StorageSnapshotScheduleIntervalV2Hourly}
			})},
		},
		{
			name:     "valid daily",
			policies: openapi.StorageSnapshotPolicyListV2Spec{daily(nil)},
		},
		{
			name: "valid weekly",
			policies: openapi.StorageSnapshotPolicyListV2Spec{daily(func(p *openapi.StorageSnapshotPolicyV2Spec) {
				p.Name = "weekly"
				p.Schedule.Interval = openapi.StorageSnapshotScheduleIntervalV2Weekly
				p.Schedule.DayOfWeek = ptr.To(openapi.StorageSnapshotDayOfWeekV2Monday)
			})},
		},
		{
			name: "valid monthly",
			policies: openapi.StorageSnapshotPolicyListV2Spec{daily(func(p *openapi.StorageSnapshotPolicyV2Spec) {
				p.Name = "monthly"
				p.Schedule.Interval = openapi.StorageSnapshotScheduleIntervalV2Monthly
				p.Schedule.DayOfMonth = ptr.To(15)
			})},
		},
		{
			name: "hourly must not define timeOfDay",
			policies: openapi.StorageSnapshotPolicyListV2Spec{daily(func(p *openapi.StorageSnapshotPolicyV2Spec) {
				p.Schedule.Interval = openapi.StorageSnapshotScheduleIntervalV2Hourly
			})},
			wantError: true,
		},
		{
			name: "daily requires timeOfDay",
			policies: openapi.StorageSnapshotPolicyListV2Spec{daily(func(p *openapi.StorageSnapshotPolicyV2Spec) {
				p.Schedule.TimeOfDay = nil
			})},
			wantError: true,
		},
		{
			name: "weekly requires dayOfWeek",
			policies: openapi.StorageSnapshotPolicyListV2Spec{daily(func(p *openapi.StorageSnapshotPolicyV2Spec) {
				p.Schedule.Interval = openapi.StorageSnapshotScheduleIntervalV2Weekly
			})},
			wantError: true,
		},
		{
			name: "monthly requires dayOfMonth",
			policies: openapi.StorageSnapshotPolicyListV2Spec{daily(func(p *openapi.StorageSnapshotPolicyV2Spec) {
				p.Schedule.Interval = openapi.StorageSnapshotScheduleIntervalV2Monthly
			})},
			wantError: true,
		},
		{
			name: "unknown interval is rejected",
			policies: openapi.StorageSnapshotPolicyListV2Spec{daily(func(p *openapi.StorageSnapshotPolicyV2Spec) {
				p.Schedule.Interval = "yearly"
			})},
			wantError: true,
		},
		{
			name:      "duplicate names are rejected",
			policies:  openapi.StorageSnapshotPolicyListV2Spec{daily(nil), daily(nil)},
			wantError: true,
		},
		{
			name: "system-default is a reserved name",
			policies: openapi.StorageSnapshotPolicyListV2Spec{daily(func(p *openapi.StorageSnapshotPolicyV2Spec) {
				p.Name = "system-default"
			})},
			wantError: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateSnapshotPolicyList(&tt.policies)

			if tt.wantError {
				require.Error(t, err)
				require.True(t, servererrors.IsUnprocessableContent(err), "expected 422, got: %v", err)

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestMaterializeDefaultSnapshotProtection(t *testing.T) {
	t.Parallel()

	hiddenBaseline := regionv1.FileStorageSnapshotPolicy{
		Name: "system-default",
		Schedule: regionv1.FileStorageSnapshotPolicySchedule{
			Interval:  regionv1.FileStorageSnapshotPolicyIntervalDaily,
			TimeOfDay: ptr.To("04:00Z"),
		},
		Retention: regionv1.FileStorageSnapshotPolicyRetention{Keep: 7},
	}

	hourly := regionv1.FileStorageSnapshotPolicy{
		Name: "hourly",
		Schedule: regionv1.FileStorageSnapshotPolicySchedule{
			Interval: regionv1.FileStorageSnapshotPolicyIntervalHourly,
		},
		Retention: regionv1.FileStorageSnapshotPolicyRetention{Keep: 24},
	}

	callerSystemDefault := regionv1.FileStorageSnapshotPolicy{
		Name: "system-default",
		Schedule: regionv1.FileStorageSnapshotPolicySchedule{
			Interval: regionv1.FileStorageSnapshotPolicyIntervalHourly,
		},
		Retention: regionv1.FileStorageSnapshotPolicyRetention{Keep: 24},
	}

	for _, tt := range []struct {
		name    string
		caller  []regionv1.FileStorageSnapshotPolicy
		enabled bool
		want    []regionv1.FileStorageSnapshotPolicy
	}{
		{
			name:    "enabled with no caller policies adds the hidden baseline",
			enabled: true,
			want:    []regionv1.FileStorageSnapshotPolicy{hiddenBaseline},
		},
		{
			name:    "enabled appends the baseline after caller policies",
			caller:  []regionv1.FileStorageSnapshotPolicy{hourly},
			enabled: true,
			want:    []regionv1.FileStorageSnapshotPolicy{hourly, hiddenBaseline},
		},
		{
			// Defensive idempotency: validation reserves the name so a well-formed user
			// list never contains system-default, but materialize still collapses any
			// existing entry to a single baseline if handed an already-materialized list.
			name:    "enabled strips a pre-existing system-default and keeps one baseline",
			caller:  []regionv1.FileStorageSnapshotPolicy{callerSystemDefault},
			enabled: true,
			want:    []regionv1.FileStorageSnapshotPolicy{hiddenBaseline},
		},
		{
			name:    "disabled stores the caller list unchanged",
			caller:  []regionv1.FileStorageSnapshotPolicy{hourly},
			enabled: false,
			want:    []regionv1.FileStorageSnapshotPolicy{hourly},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tt.want, materializeDefaultSnapshotProtection(tt.caller, tt.enabled))
		})
	}
}

func TestGenerateSnapshotPolicies(t *testing.T) {
	t.Parallel()

	policies := openapi.StorageSnapshotPolicyListV2Spec{
		{
			Name: "weekly",
			Schedule: openapi.StorageSnapshotScheduleV2Spec{
				Interval:  openapi.StorageSnapshotScheduleIntervalV2Weekly,
				TimeOfDay: ptr.To("02:30Z"),
				DayOfWeek: ptr.To(openapi.StorageSnapshotDayOfWeekV2Monday),
			},
			Retention: openapi.StorageSnapshotRetentionV2Spec{Keep: 4},
		},
	}

	require.Nil(t, generateSnapshotPolicies(nil))
	require.Nil(t, generateSnapshotPolicies(&openapi.StorageSnapshotPolicyListV2Spec{}))
	require.Equal(t, []regionv1.FileStorageSnapshotPolicy{
		{
			Name: "weekly",
			Schedule: regionv1.FileStorageSnapshotPolicySchedule{
				Interval:  regionv1.FileStorageSnapshotPolicyIntervalWeekly,
				TimeOfDay: ptr.To("02:30Z"),
				DayOfWeek: ptr.To(regionv1.FileStorageSnapshotPolicyWeekdayMonday),
			},
			Retention: regionv1.FileStorageSnapshotPolicyRetention{Keep: 4},
		},
	}, generateSnapshotPolicies(&policies))
}

func TestConvertSnapshotPolicies(t *testing.T) {
	t.Parallel()

	require.Equal(t, openapi.StorageSnapshotPolicyListV2Spec{
		{
			Name: "monthly",
			Schedule: openapi.StorageSnapshotScheduleV2Spec{
				Interval:   openapi.StorageSnapshotScheduleIntervalV2Monthly,
				TimeOfDay:  ptr.To("05:00Z"),
				DayOfMonth: ptr.To(15),
			},
			Retention: openapi.StorageSnapshotRetentionV2Spec{Keep: 12},
		},
	}, convertSnapshotPolicies([]regionv1.FileStorageSnapshotPolicy{
		{
			Name: "monthly",
			Schedule: regionv1.FileStorageSnapshotPolicySchedule{
				Interval:   regionv1.FileStorageSnapshotPolicyIntervalMonthly,
				TimeOfDay:  ptr.To("05:00Z"),
				DayOfMonth: ptr.To(15),
			},
			Retention: regionv1.FileStorageSnapshotPolicyRetention{Keep: 12},
		},
	}))
}

func TestUserManagedSnapshotPoliciesHidesSystemDefault(t *testing.T) {
	t.Parallel()

	hourly := regionv1.FileStorageSnapshotPolicy{
		Name: "hourly",
		Schedule: regionv1.FileStorageSnapshotPolicySchedule{
			Interval: regionv1.FileStorageSnapshotPolicyIntervalHourly,
		},
		Retention: regionv1.FileStorageSnapshotPolicyRetention{Keep: 24},
	}

	require.Equal(t, []regionv1.FileStorageSnapshotPolicy{hourly}, userManagedSnapshotPolicies([]regionv1.FileStorageSnapshotPolicy{
		{
			Name: "system-default",
			Schedule: regionv1.FileStorageSnapshotPolicySchedule{
				Interval: regionv1.FileStorageSnapshotPolicyIntervalHourly,
			},
			Retention: regionv1.FileStorageSnapshotPolicyRetention{Keep: 1},
		},
		hourly,
	}))
}

func TestConvertSnapshotPolicyStatuses(t *testing.T) {
	t.Parallel()

	spec := []regionv1.FileStorageSnapshotPolicy{
		{Name: "hourly"},
		{Name: "daily"},
	}
	status := []regionv1.FileStorageSnapshotPolicyStatus{
		{Name: "stale"},
		{
			Name: "daily",
			Conditions: []metav1.Condition{
				{
					Type:    string(unikorncorev1.ConditionAvailable),
					Reason:  string(unikorncorev1.ConditionReasonProvisioned),
					Message: "snapshot policy is active",
				},
			},
		},
	}

	require.Equal(t, openapi.StorageSnapshotPolicyListV2Status{
		{
			Name:               "hourly",
			ProvisioningStatus: coreopenapi.ResourceProvisioningStatusPending,
		},
		{
			Name:               "daily",
			ProvisioningStatus: coreopenapi.ResourceProvisioningStatusProvisioned,
			Message:            ptr.To("snapshot policy is active"),
		},
	}, convertSnapshotPolicyStatuses(spec, status))
}
