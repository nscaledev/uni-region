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

package driver

import (
	"net"

	"github.com/unikorn-cloud/region/pkg/file-storage/provisioners/types"

	"k8s.io/apimachinery/pkg/api/resource"
)

func convertGetFileSystemResponse(res *GetFileSystemResponse) *types.FileStorageDetails {
	if res == nil {
		return nil
	}

	return &types.FileStorageDetails{
		Size:              resource.NewQuantity(res.Size, resource.BinarySI),
		Path:              res.Path,
		RootSquashEnabled: res.RootSquashEnabled,
		UsedCapacity:      resource.NewQuantity(res.UsedCapacity, resource.BinarySI),
	}
}

func convertListFileSystemMountTargetsResponse(res *ListFileSystemMountTargetsResponse) *types.FileStorageAttachments {
	if res == nil || len(res.Items) == 0 {
		return &types.FileStorageAttachments{Items: nil}
	}

	attachments := make([]types.Attachment, len(res.Items))
	for i, a := range res.Items {
		attachments[i] = types.Attachment{
			VlanID: int(a.VlanID),
			IPRange: &types.IPRange{
				Start: net.ParseIP(a.StartIP),
				End:   net.ParseIP(a.EndIP),
			},
		}
	}

	return &types.FileStorageAttachments{
		Items: attachments,
	}
}
