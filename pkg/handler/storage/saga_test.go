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
	"go.uber.org/mock/gomock"

	corev1 "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/region/pkg/handler/storage/mock"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

// TestValidateAttachments_NetworkNotFound tests that when a network ID is specified in the attachments but does not exist, a 'network not found' error is returned.
func TestValidateAttachments_NetworkNotFound(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	m := mock.NewMockNetworkGetter(c)
	m.EXPECT().
		GetV2(gomock.Any(), "missing-net").
		Return(nil, errors.HTTPNotFound())

	attachments := &openapi.StorageAttachmentV2Spec{NetworkIds: []string{"missing-net"}}
	err := validateAttachments(t.Context(), m, attachments, "proj-1")

	require.Error(t, err)
	require.ErrorContains(t, err, "network not found")
	require.False(t, errors.IsHTTPNotFound(err))
}

// TestValidateAttachments_NonHTTPNotFoundError tests that when a network ID is specified in the attachments but the network client returns a non-HTTPNotFound error, the error is propagated as-is.
func TestValidateAttachments_NonHTTPNotFoundError(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	m := mock.NewMockNetworkGetter(c)
	m.EXPECT().
		GetV2(gomock.Any(), "any-net").
		Return(nil, errors.OAuth2ServerError("unable to lookup network"))

	attachments := &openapi.StorageAttachmentV2Spec{NetworkIds: []string{"any-net"}}
	err := validateAttachments(t.Context(), m, attachments, "proj-1")

	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to lookup network")
}

// TestValidateAttachments_ProjectMismatch tests that when a network exists but belongs to a different project, a 'network not available in project' error is returned.
func TestValidateAttachments_ProjectMismatch(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	m := mock.NewMockNetworkGetter(c)
	m.EXPECT().
		GetV2(gomock.Any(), "net-1").
		Return(&openapi.NetworkV2Read{
			Metadata: corev1.ProjectScopedResourceReadMetadata{ProjectId: "proj-OK", ProvisioningStatus: corev1.ResourceProvisioningStatusProvisioned},
		}, nil)

	attachments := &openapi.StorageAttachmentV2Spec{NetworkIds: []string{"net-1"}}
	err := validateAttachments(t.Context(), m, attachments, "proj-NO")

	require.Error(t, err)
	require.Contains(t, err.Error(), "network not available in project")
}

// TestValidateAttachments_OK tests that when all referenced networks exist and belong to the requested project,
// validation succeeds without error.
func TestValidateAttachments_OK(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	m := mock.NewMockNetworkGetter(c)
	m.EXPECT().
		GetV2(gomock.Any(), "net-1").
		Return(&openapi.NetworkV2Read{
			Metadata: corev1.ProjectScopedResourceReadMetadata{ProjectId: "proj-OK", ProvisioningStatus: corev1.ResourceProvisioningStatusProvisioned},
		}, nil)
	m.EXPECT().
		GetV2(gomock.Any(), "net-2").
		Return(&openapi.NetworkV2Read{
			Metadata: corev1.ProjectScopedResourceReadMetadata{ProjectId: "proj-OK", ProvisioningStatus: corev1.ResourceProvisioningStatusProvisioned},
		}, nil)

	attachments := &openapi.StorageAttachmentV2Spec{NetworkIds: []string{"net-1", "net-2"}}
	err := validateAttachments(t.Context(), m, attachments, "proj-OK")

	require.NoError(t, err)
}

// TestValidateAttachments_NetworkNotProvisioned tests that validation fails when a referenced
// network exists in the project but is not yet provisioned.
func TestValidateAttachments_NetworkNotProvisioned(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	m := mock.NewMockNetworkGetter(c)
	m.EXPECT().
		GetV2(gomock.Any(), "net-1").
		Return(&openapi.NetworkV2Read{
			Metadata: corev1.ProjectScopedResourceReadMetadata{ProjectId: "proj-OK", ProvisioningStatus: corev1.ResourceProvisioningStatusUnknown},
		}, nil)

	attachments := &openapi.StorageAttachmentV2Spec{NetworkIds: []string{"net-1"}}
	err := validateAttachments(t.Context(), m, attachments, "proj-OK")

	require.Error(t, err)
	require.Contains(t, err.Error(), "network not provisioned")
}
