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

package common

import (
	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ProvisioningResult is a resource whose Available condition records the spec
// generation it was evaluated against.
type ProvisioningResult interface {
	metav1.Object
	ProvisioningConditionCurrent() bool
}

// ProjectScopedReadMetadata projects the standard read metadata for a resource
// that stamps its Available condition. Core derives provisioningStatus from
// that condition alone, which between a spec update and the first reconcile
// still holds the previous spec's result. A result that does not carry the
// current generation is not evidence about the current spec, so it is reported
// as in flight. Deletion keeps priority: core already projects a deleting
// resource as deprovisioning whatever the condition says, and this does not
// override it.
func ProjectScopedReadMetadata(in ProvisioningResult, tags unikornv1core.TagList) coreopenapi.ProjectScopedResourceReadMetadata {
	out := conversion.ProjectScopedResourceReadMetadata(in, tags)

	if in.GetDeletionTimestamp() != nil || in.ProvisioningConditionCurrent() {
		return out
	}

	if out.ProvisioningStatus == coreopenapi.ResourceProvisioningStatusPending {
		return out
	}

	out.ProvisioningStatus = coreopenapi.ResourceProvisioningStatusProvisioning
	out.ProvisioningStatusDetail = &coreopenapi.ProvisioningStatusDetail{
		Reason:  coreopenapi.ProvisioningStatusReasonProvisioning,
		Message: "awaiting reconciliation of the current specification",
	}

	return out
}
