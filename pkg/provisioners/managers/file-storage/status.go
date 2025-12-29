/*
Copyright 2024-2025 the Unikorn Authors.

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

package filestorage

import (
	"slices"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

// setNetworkAttachmentStatus sets the corresponding attachment status returns true if the status are changed by this call.
func setNetworkAttachmentStatus(fileStorage *unikornv1.FileStorage, networkID string, segmentationID *int, status unikornv1.AttachmentProvisioningStatus, message string) {
	if fileStorage == nil {
		return
	}

	matchNetworkID := func(as unikornv1.FileStorageAttachmentStatus) bool {
		return as.NetworkID == networkID
	}

	i := slices.IndexFunc(fileStorage.Status.Attachments, matchNetworkID)
	if i < 0 {
		fileStorage.Status.Attachments = append(fileStorage.Status.Attachments, unikornv1.FileStorageAttachmentStatus{
			NetworkID:          networkID,
			SegmentationID:     segmentationID,
			ProvisioningStatus: status,
			Message:            message,
		})

		return
	}

	fileStorage.Status.Attachments[i].ProvisioningStatus = status
	fileStorage.Status.Attachments[i].SegmentationID = segmentationID
	fileStorage.Status.Attachments[i].Message = message
}

// setVLanAttachmentStatus sets the corresponding attachment status returns true if the status are changed by this call.
func setVLanAttachmentStatus(fileStorage *unikornv1.FileStorage, segmentationID int, status unikornv1.AttachmentProvisioningStatus, message string) {
	if fileStorage == nil {
		return
	}

	matchSegmentationID := func(as unikornv1.FileStorageAttachmentStatus) bool {
		return *as.SegmentationID == segmentationID
	}

	i := slices.IndexFunc(fileStorage.Status.Attachments, matchSegmentationID)
	if i < 0 {
		return
	}

	fileStorage.Status.Attachments[i].ProvisioningStatus = status
	fileStorage.Status.Attachments[i].Message = message
}

// removeAttachmentStatus removes the attachment status for the given network ID.
func removeAttachmentStatus(fileStorage *unikornv1.FileStorage, segmentationID int) {
	if fileStorage == nil || len(fileStorage.Status.Attachments) == 0 {
		return
	}

	// If there no attachment for the given network ID, return false.
	matchSegmentationID := func(as unikornv1.FileStorageAttachmentStatus) bool {
		return *as.SegmentationID == segmentationID
	}

	i := slices.IndexFunc(fileStorage.Status.Attachments, matchSegmentationID)
	if i < 0 {
		return
	}

	fileStorage.Status.Attachments = slices.Delete(fileStorage.Status.Attachments, i, i+1)
}
