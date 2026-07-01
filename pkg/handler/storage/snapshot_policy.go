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

package storage

import (
	unikorncorev1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/openapi"

	"k8s.io/utils/ptr"
)

const systemDefaultSnapshotPolicyName = "system-default"

// userManagedSnapshotPolicies returns the caller-facing policies from a stored list
// by dropping the hidden system-default baseline. system-default is a reserved name
// validation never lets a user-managed policy claim, so any system-default entry is
// always the platform baseline: stripping it unconditionally yields exactly the
// user-managed policies (and is a no-op when default protection is disabled, since
// no system-default entry exists).
func userManagedSnapshotPolicies(in []regionv1.FileStorageSnapshotPolicy) []regionv1.FileStorageSnapshotPolicy {
	out := make([]regionv1.FileStorageSnapshotPolicy, 0, len(in))

	for _, policy := range in {
		if policy.Name == systemDefaultSnapshotPolicyName {
			continue
		}

		out = append(out, policy)
	}

	return out
}

// systemDefaultSnapshotPolicy is the hidden platform-managed baseline materialized
// into stored spec.snapshotPolicies while default snapshot protection is enabled.
// The existing storage controller reconciles it like any user-managed policy; it
// is never exposed in public REST reads.
func systemDefaultSnapshotPolicy() regionv1.FileStorageSnapshotPolicy {
	return regionv1.FileStorageSnapshotPolicy{
		Name: systemDefaultSnapshotPolicyName,
		Schedule: regionv1.FileStorageSnapshotPolicySchedule{
			Interval:  regionv1.FileStorageSnapshotPolicyIntervalDaily,
			TimeOfDay: ptr.To("04:00Z"),
		},
		Retention: regionv1.FileStorageSnapshotPolicyRetention{Keep: 7},
	}
}

// materializeDefaultSnapshotProtection returns the snapshot policy list to store for
// the given user-managed policies and resolved default-protection state. The hidden
// system-default baseline is present if and only if default protection is enabled, so
// the boolean and the stored entry never drift. Validation reserves the system-default
// name, so a well-formed user list never contains one; when enabled, any system-default
// entry is stripped before the single baseline is appended, making the result idempotent
// (exactly one baseline) even if handed an already-materialized list. When disabled the
// user list is stored unchanged.
func materializeDefaultSnapshotProtection(userPolicies []regionv1.FileStorageSnapshotPolicy, enabled bool) []regionv1.FileStorageSnapshotPolicy {
	if !enabled {
		return userPolicies
	}

	return append(userManagedSnapshotPolicies(userPolicies), systemDefaultSnapshotPolicy())
}

func convertSnapshotPolicies(in []regionv1.FileStorageSnapshotPolicy) openapi.StorageSnapshotPolicyListV2Spec {
	out := make(openapi.StorageSnapshotPolicyListV2Spec, len(in))

	for i, policy := range in {
		out[i] = convertSnapshotPolicySpec(policy)
	}

	return out
}

func convertSnapshotPoliciesPointer(in []regionv1.FileStorageSnapshotPolicy) *openapi.StorageSnapshotPolicyListV2Spec {
	out := convertSnapshotPolicies(in)

	return &out
}

func convertSnapshotPolicySpec(policy regionv1.FileStorageSnapshotPolicy) openapi.StorageSnapshotPolicyV2Spec {
	var dayOfWeek *openapi.StorageSnapshotDayOfWeekV2

	if policy.Schedule.DayOfWeek != nil {
		dayOfWeek = ptr.To(openapi.StorageSnapshotDayOfWeekV2(*policy.Schedule.DayOfWeek))
	}

	return openapi.StorageSnapshotPolicyV2Spec{
		Name: policy.Name,
		Schedule: openapi.StorageSnapshotScheduleV2Spec{
			Interval:   openapi.StorageSnapshotScheduleIntervalV2(policy.Schedule.Interval),
			TimeOfDay:  policy.Schedule.TimeOfDay,
			DayOfWeek:  dayOfWeek,
			DayOfMonth: policy.Schedule.DayOfMonth,
		},
		Retention: openapi.StorageSnapshotRetentionV2Spec{
			Keep: policy.Retention.Keep,
		},
	}
}

func convertSnapshotPolicyStatuses(spec []regionv1.FileStorageSnapshotPolicy, status []regionv1.FileStorageSnapshotPolicyStatus) openapi.StorageSnapshotPolicyListV2Status {
	observed := make(map[string]regionv1.FileStorageSnapshotPolicyStatus, len(status))
	for _, policyStatus := range status {
		observed[policyStatus.Name] = policyStatus
	}

	out := make(openapi.StorageSnapshotPolicyListV2Status, len(spec))

	for i, policy := range spec {
		policyStatus := openapi.StorageSnapshotPolicyV2Status{
			Name:               policy.Name,
			ProvisioningStatus: coreopenapi.ResourceProvisioningStatusPending,
		}

		if observedStatus, ok := observed[policy.Name]; ok {
			policyStatus.ProvisioningStatus, policyStatus.Message = convertSnapshotPolicyStatus(observedStatus)
		}

		out[i] = policyStatus
	}

	return out
}

func convertSnapshotPolicyStatus(in regionv1.FileStorageSnapshotPolicyStatus) (coreopenapi.ResourceProvisioningStatus, *string) {
	condition := snapshotPolicyAvailableCondition(in)
	if condition == nil {
		return coreopenapi.ResourceProvisioningStatusPending, nil
	}

	var message *string
	if condition.Message != "" {
		message = ptr.To(condition.Message)
	}

	//nolint:exhaustive
	switch condition.Reason {
	case unikorncorev1.ConditionReasonProvisioning:
		return coreopenapi.ResourceProvisioningStatusProvisioning, message
	case unikorncorev1.ConditionReasonProvisioned:
		return coreopenapi.ResourceProvisioningStatusProvisioned, message
	case unikorncorev1.ConditionReasonErrored:
		return coreopenapi.ResourceProvisioningStatusError, message
	case unikorncorev1.ConditionReasonDeprovisioning:
		return coreopenapi.ResourceProvisioningStatusDeprovisioning, message
	}

	return coreopenapi.ResourceProvisioningStatusUnknown, message
}

func snapshotPolicyAvailableCondition(in regionv1.FileStorageSnapshotPolicyStatus) *unikorncorev1.Condition {
	for i := range in.Conditions {
		if in.Conditions[i].Type == unikorncorev1.ConditionAvailable {
			return &in.Conditions[i]
		}
	}

	return nil
}

// validateSnapshotPolicyList enforces the snapshot policy rules the generated
// OpenAPI schema cannot express, and which the request-validation middleware
// therefore does not catch: per-list name uniqueness, cross-field schedule
// consistency, and the reserved system-default name. Primitive field constraints
// (name pattern and the provider-safe length limit, timeOfDay format, dayOfWeek
// enum, dayOfMonth and keep ranges, and the four-policy list limit) are enforced
// by the bundled schema before the handler runs.
//
// system-default is unconditionally reserved for the hidden Default Snapshot
// Protection baseline, independent of whether protection is currently enabled, so
// a user-managed policy may never claim it. The list passed here is always the
// caller-supplied desired state, before the baseline is materialized in generateV2,
// so this never rejects the platform's own baseline.
func validateSnapshotPolicyList(policies *openapi.StorageSnapshotPolicyListV2Spec) error {
	if policies == nil {
		return nil
	}

	seen := make(map[string]struct{}, len(*policies))

	for i := range *policies {
		policy := &(*policies)[i]

		if err := validateSnapshotPolicyScheduleMatrix(policy.Schedule); err != nil {
			return err
		}

		if policy.Name == systemDefaultSnapshotPolicyName {
			return errors.HTTPUnprocessableContent(`"system-default" is a reserved snapshot policy name`)
		}

		if _, ok := seen[policy.Name]; ok {
			return errors.HTTPUnprocessableContent("snapshot policy names must be unique")
		}

		seen[policy.Name] = struct{}{}
	}

	return nil
}

func validateSnapshotPolicyScheduleMatrix(schedule openapi.StorageSnapshotScheduleV2Spec) error {
	switch schedule.Interval {
	case openapi.StorageSnapshotScheduleIntervalV2Hourly:
		return validateHourlySnapshotPolicySchedule(schedule)
	case openapi.StorageSnapshotScheduleIntervalV2Daily:
		return validateDailySnapshotPolicySchedule(schedule)
	case openapi.StorageSnapshotScheduleIntervalV2Weekly:
		return validateWeeklySnapshotPolicySchedule(schedule)
	case openapi.StorageSnapshotScheduleIntervalV2Monthly:
		return validateMonthlySnapshotPolicySchedule(schedule)
	default:
		return errors.HTTPUnprocessableContent("snapshot policy interval is invalid")
	}
}

func validateHourlySnapshotPolicySchedule(schedule openapi.StorageSnapshotScheduleV2Spec) error {
	if schedule.TimeOfDay != nil || schedule.DayOfWeek != nil || schedule.DayOfMonth != nil {
		return errors.HTTPUnprocessableContent("hourly snapshot policies must not define timeOfDay, dayOfWeek, or dayOfMonth")
	}

	return nil
}

func validateDailySnapshotPolicySchedule(schedule openapi.StorageSnapshotScheduleV2Spec) error {
	if schedule.TimeOfDay == nil || schedule.DayOfWeek != nil || schedule.DayOfMonth != nil {
		return errors.HTTPUnprocessableContent("daily snapshot policies require timeOfDay and must not define dayOfWeek or dayOfMonth")
	}

	return nil
}

func validateWeeklySnapshotPolicySchedule(schedule openapi.StorageSnapshotScheduleV2Spec) error {
	if schedule.TimeOfDay == nil || schedule.DayOfWeek == nil || schedule.DayOfMonth != nil {
		return errors.HTTPUnprocessableContent("weekly snapshot policies require timeOfDay and dayOfWeek and must not define dayOfMonth")
	}

	return nil
}

func validateMonthlySnapshotPolicySchedule(schedule openapi.StorageSnapshotScheduleV2Spec) error {
	if schedule.TimeOfDay == nil || schedule.DayOfMonth == nil || schedule.DayOfWeek != nil {
		return errors.HTTPUnprocessableContent("monthly snapshot policies require timeOfDay and dayOfMonth and must not define dayOfWeek")
	}

	return nil
}

func generateSnapshotPolicies(in *openapi.StorageSnapshotPolicyListV2Spec) []regionv1.FileStorageSnapshotPolicy {
	if in == nil || len(*in) == 0 {
		return nil
	}

	out := make([]regionv1.FileStorageSnapshotPolicy, len(*in))

	for i, policy := range *in {
		out[i] = generateSnapshotPolicy(policy)
	}

	return out
}

func generateSnapshotPolicy(policy openapi.StorageSnapshotPolicyV2Spec) regionv1.FileStorageSnapshotPolicy {
	var dayOfWeek *regionv1.FileStorageSnapshotPolicyWeekday

	if policy.Schedule.DayOfWeek != nil {
		dayOfWeek = ptr.To(regionv1.FileStorageSnapshotPolicyWeekday(*policy.Schedule.DayOfWeek))
	}

	return regionv1.FileStorageSnapshotPolicy{
		Name: policy.Name,
		Schedule: regionv1.FileStorageSnapshotPolicySchedule{
			Interval:   regionv1.FileStorageSnapshotPolicyInterval(policy.Schedule.Interval),
			TimeOfDay:  policy.Schedule.TimeOfDay,
			DayOfWeek:  dayOfWeek,
			DayOfMonth: policy.Schedule.DayOfMonth,
		},
		Retention: regionv1.FileStorageSnapshotPolicyRetention{
			Keep: policy.Retention.Keep,
		},
	}
}
