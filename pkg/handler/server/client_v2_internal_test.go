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

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

func TestConvertVolumeProvisioningStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input regionv1.AttachmentProvisioningStatus
		want  coreopenapi.ResourceProvisioningStatus
	}{
		{name: "provisioning", input: regionv1.AttachmentProvisioning, want: coreopenapi.ResourceProvisioningStatusProvisioning},
		{name: "provisioned", input: regionv1.AttachmentProvisioned, want: coreopenapi.ResourceProvisioningStatusProvisioned},
		{name: "errored", input: regionv1.AttachmentErrored, want: coreopenapi.ResourceProvisioningStatusError},
		{name: "deprovisioning", input: regionv1.AttachmentDeprovisioning, want: coreopenapi.ResourceProvisioningStatusDeprovisioning},
		{name: "unset", want: coreopenapi.ResourceProvisioningStatusPending},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, convertVolumeProvisioningStatus(tt.input))
		})
	}
}
