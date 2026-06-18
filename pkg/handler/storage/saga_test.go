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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	corev1 "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/region/pkg/handler/storage/mock"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

const (
	netID1     = "33333333-3333-4333-a333-333333333333"
	netID2     = "44444444-4444-4444-a444-444444444444"
	netMissing = "11111111-1111-4111-a111-111111111111"
	netAny     = "22222222-2222-4222-a222-222222222222"
)

// TestValidateAttachments_NetworkNotFound tests that when a network ID is specified in the attachments but does not exist, a 'network not found' error is returned.
func TestValidateAttachments_NetworkNotFound(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	m := mock.NewMockNetworkGetter(c)
	m.EXPECT().
		GetV2(gomock.Any(), regionids.MustParseNetworkID(netMissing)).
		Return(nil, errors.HTTPNotFound())

	attachments := &openapi.StorageAttachmentV2Spec{NetworkIds: []string{netMissing}}
	err := validateAttachments(t.Context(), m, attachments, "proj-1")

	require.Error(t, err)
	require.True(t, errors.IsUnprocessableContent(err))
	require.ErrorContains(t, err, "network not found")
}

// TestValidateAttachments_NonHTTPNotFoundError tests that when a network ID is specified in the attachments but the network client returns a non-HTTPNotFound error, the error is propagated as-is.
func TestValidateAttachments_NonHTTPNotFoundError(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	m := mock.NewMockNetworkGetter(c)
	//nolint:err113
	m.EXPECT().
		GetV2(gomock.Any(), regionids.MustParseNetworkID(netAny)).
		Return(nil, fmt.Errorf("sentinel"))

	attachments := &openapi.StorageAttachmentV2Spec{NetworkIds: []string{netAny}}
	err := validateAttachments(t.Context(), m, attachments, "proj-1")

	require.Error(t, err)
	require.Contains(t, err.Error(), "sentinel")
}

// TestValidateAttachments_ProjectMismatch tests that when a network exists but belongs to a different project, a 'network not available in project' error is returned.
func TestValidateAttachments_ProjectMismatch(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	m := mock.NewMockNetworkGetter(c)
	m.EXPECT().
		GetV2(gomock.Any(), regionids.MustParseNetworkID(netID1)).
		Return(&openapi.NetworkV2Read{
			Metadata: corev1.ProjectScopedResourceReadMetadata{ProjectId: "proj-OK", ProvisioningStatus: corev1.ResourceProvisioningStatusProvisioned},
		}, nil)

	attachments := &openapi.StorageAttachmentV2Spec{NetworkIds: []string{netID1}}
	err := validateAttachments(t.Context(), m, attachments, "proj-NO")

	require.Error(t, err)
	require.True(t, errors.IsUnprocessableContent(err))
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
		GetV2(gomock.Any(), regionids.MustParseNetworkID(netID1)).
		Return(&openapi.NetworkV2Read{
			Metadata: corev1.ProjectScopedResourceReadMetadata{ProjectId: "proj-OK", ProvisioningStatus: corev1.ResourceProvisioningStatusProvisioned},
		}, nil)
	m.EXPECT().
		GetV2(gomock.Any(), regionids.MustParseNetworkID(netID2)).
		Return(&openapi.NetworkV2Read{
			Metadata: corev1.ProjectScopedResourceReadMetadata{ProjectId: "proj-OK", ProvisioningStatus: corev1.ResourceProvisioningStatusProvisioned},
		}, nil)

	attachments := &openapi.StorageAttachmentV2Spec{NetworkIds: []string{netID1, netID2}}
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
		GetV2(gomock.Any(), regionids.MustParseNetworkID(netID1)).
		Return(&openapi.NetworkV2Read{
			Metadata: corev1.ProjectScopedResourceReadMetadata{ProjectId: "proj-OK", ProvisioningStatus: corev1.ResourceProvisioningStatusPending},
		}, nil)

	attachments := &openapi.StorageAttachmentV2Spec{NetworkIds: []string{netID1}}
	err := validateAttachments(t.Context(), m, attachments, "proj-OK")

	require.Error(t, err)
	require.True(t, errors.IsUnprocessableContent(err))
	require.Contains(t, err.Error(), "network not provisioned")
}

// TestValidateAttachments_InvalidNetworkID tests that a malformed (non-UUID) network ID is
// rejected before any lookup, rather than being passed to the network client.
func TestValidateAttachments_InvalidNetworkID(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	t.Cleanup(c.Finish)

	// No GetV2 expectation: a malformed ID must be rejected before the lookup.
	m := mock.NewMockNetworkGetter(c)

	attachments := &openapi.StorageAttachmentV2Spec{NetworkIds: []string{"not-a-uuid"}}
	err := validateAttachments(t.Context(), m, attachments, "proj-1")

	require.Error(t, err)
	require.True(t, errors.IsUnprocessableContent(err))
	require.Contains(t, err.Error(), "invalid network ID")
}
