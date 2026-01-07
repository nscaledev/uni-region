/*
Copyright 2024-2025 the Unikorn Authors.
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
package filestorage

import (
	"testing"

	"github.com/stretchr/testify/require"

	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	"k8s.io/utils/ptr"
)

func TestRemoveAttachmentStatus_NilSlice(t *testing.T) {
	t.Parallel()

	require.NotPanics(t, func() {
		removeAttachmentStatus(nil, 10)
	})
}

func TestRemoveAttachmentStatus_EmptySlice(t *testing.T) {
	t.Parallel()

	fs := &regionv1.FileStorage{Status: regionv1.FileStorageStatus{Attachments: []regionv1.FileStorageAttachmentStatus{}}}
	removeAttachmentStatus(fs, 10)
	require.Empty(t, fs.Status.Attachments)
}

func TestRemoveAttachmentStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		removeID int
		want     []int
	}{
		{
			name:     "remove first",
			removeID: 1,
			want:     []int{2, 3},
		},
		{
			name:     "remove middle",
			removeID: 2,
			want:     []int{1, 3},
		},
		{
			name:     "remove last",
			removeID: 3,
			want:     []int{1, 2},
		},
		{
			name:     "no match",
			removeID: 4,
			want:     []int{1, 2, 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fileStorage := &regionv1.FileStorage{Status: regionv1.FileStorageStatus{Attachments: []regionv1.FileStorageAttachmentStatus{
				{NetworkID: "n1", SegmentationID: ptr.To(1)},
				{NetworkID: "n2", SegmentationID: ptr.To(2)},
				{NetworkID: "n3", SegmentationID: ptr.To(3)},
			}}}

			removeAttachmentStatus(fileStorage, tt.removeID)
			require.Len(t, fileStorage.Status.Attachments, len(tt.want))

			for i, id := range tt.want {
				require.Equal(t, id, *fileStorage.Status.Attachments[i].SegmentationID)
			}
		})
	}
}

func TestSetNetworkAttachmentStatus_NilFileStorage(t *testing.T) {
	t.Parallel()

	require.NotPanics(t, func() {
		setNetworkAttachmentStatus(nil, "n1", ptr.To(10), regionv1.AttachmentProvisioned, "ok")
	})
}

func TestSetNetworkAttachmentStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input *regionv1.FileStorage
		want  []regionv1.FileStorageAttachmentStatus
	}{
		{
			name:  "empty status",
			input: &regionv1.FileStorage{},
			want: []regionv1.FileStorageAttachmentStatus{
				{NetworkID: "n1", SegmentationID: ptr.To(11), ProvisioningStatus: regionv1.AttachmentProvisioning, Message: "ok"},
			},
		},
		{
			name: "append",
			input: &regionv1.FileStorage{Status: regionv1.FileStorageStatus{Attachments: []regionv1.FileStorageAttachmentStatus{
				{NetworkID: "n2", SegmentationID: ptr.To(2), ProvisioningStatus: regionv1.AttachmentErrored, Message: "old"},
			}}},
			want: []regionv1.FileStorageAttachmentStatus{
				{NetworkID: "n2", SegmentationID: ptr.To(2), ProvisioningStatus: regionv1.AttachmentErrored, Message: "old"},
				{NetworkID: "n1", SegmentationID: ptr.To(11), ProvisioningStatus: regionv1.AttachmentProvisioning, Message: "ok"},
			},
		},
		{
			name: "update existing",
			input: &regionv1.FileStorage{Status: regionv1.FileStorageStatus{Attachments: []regionv1.FileStorageAttachmentStatus{
				{NetworkID: "n1", SegmentationID: ptr.To(99), ProvisioningStatus: regionv1.AttachmentDeprovisioning, Message: "old"},
				{NetworkID: "n2", SegmentationID: ptr.To(2), ProvisioningStatus: regionv1.AttachmentErrored, Message: "old"},
			}}},
			want: []regionv1.FileStorageAttachmentStatus{
				{NetworkID: "n1", SegmentationID: ptr.To(11), ProvisioningStatus: regionv1.AttachmentProvisioning, Message: "ok"},
				{NetworkID: "n2", SegmentationID: ptr.To(2), ProvisioningStatus: regionv1.AttachmentErrored, Message: "old"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			setNetworkAttachmentStatus(tt.input, "n1", ptr.To(11), regionv1.AttachmentProvisioning, "ok")

			require.Len(t, tt.input.Status.Attachments, len(tt.want))

			for i, w := range tt.want {
				got := tt.input.Status.Attachments[i]
				require.Equal(t, w.NetworkID, got.NetworkID)
				require.Equal(t, w.SegmentationID, got.SegmentationID)
				require.Equal(t, w.ProvisioningStatus, got.ProvisioningStatus)
				require.Equal(t, w.Message, got.Message)
			}
		})
	}
}

func TestSetVLanAttachmentStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input *regionv1.FileStorage
		want  []regionv1.FileStorageAttachmentStatus
	}{
		{
			name: "no match",
			input: &regionv1.FileStorage{Status: regionv1.FileStorageStatus{Attachments: []regionv1.FileStorageAttachmentStatus{
				{NetworkID: "n1", SegmentationID: ptr.To(1), ProvisioningStatus: regionv1.AttachmentProvisioned, Message: "old"},
			}}},
			want: []regionv1.FileStorageAttachmentStatus{
				{NetworkID: "n1", SegmentationID: ptr.To(1), ProvisioningStatus: regionv1.AttachmentProvisioned, Message: "old"},
			},
		},
		{
			name: "update existing",
			input: &regionv1.FileStorage{Status: regionv1.FileStorageStatus{Attachments: []regionv1.FileStorageAttachmentStatus{
				{NetworkID: "n1", SegmentationID: ptr.To(1), ProvisioningStatus: regionv1.AttachmentProvisioned, Message: "old"},
				{NetworkID: "n3", SegmentationID: ptr.To(3), ProvisioningStatus: regionv1.AttachmentDeprovisioning, Message: "old"},
			}}},
			want: []regionv1.FileStorageAttachmentStatus{
				{NetworkID: "n1", SegmentationID: ptr.To(1), ProvisioningStatus: regionv1.AttachmentProvisioned, Message: "old"},
				{NetworkID: "n3", SegmentationID: ptr.To(3), ProvisioningStatus: regionv1.AttachmentErrored, Message: "updated"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			setVLanAttachmentStatus(tt.input, 3, regionv1.AttachmentErrored, "updated")

			require.Len(t, tt.input.Status.Attachments, len(tt.want))

			for i, w := range tt.want {
				got := tt.input.Status.Attachments[i]
				require.Equal(t, w.NetworkID, got.NetworkID)
				require.Equal(t, w.SegmentationID, got.SegmentationID)
				require.Equal(t, w.ProvisioningStatus, got.ProvisioningStatus)
				require.Equal(t, w.Message, got.Message)
			}
		})
	}
}
