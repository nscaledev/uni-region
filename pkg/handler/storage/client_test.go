/*
Copyright 2025 the Unikorn Authors.

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
	"time"

	"github.com/stretchr/testify/require"

	corev1 "github.com/unikorn-cloud/core/pkg/openapi"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGenerateAttachmentList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input *openapi.StorageAttachmentV2Spec
		want  []regionv1.Attachment
	}{
		{
			name: "single attachment",
			input: &openapi.StorageAttachmentV2Spec{
				NetworkIDs: openapi.NetworkIDList{"net-1"},
			},
			want: []regionv1.Attachment{
				{NetworkID: "net-1"},
			},
		},
		{
			name:  "empty",
			input: &openapi.StorageAttachmentV2Spec{},
			want:  []regionv1.Attachment{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := generateAttachmentList(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestGenerateV2List(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input *regionv1.FileStorageList
		want  openapi.StorageV2List
	}{
		{
			name: "test with data",
			input: &regionv1.FileStorageList{
				TypeMeta: metav1.TypeMeta{
					Kind:       "FileStorageList",
					APIVersion: "v1alpha1",
				},
				Items: []regionv1.FileStorage{
					{
						TypeMeta: metav1.TypeMeta{
							Kind:       "FileStorage",
							APIVersion: "v1alpha1",
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test-filestorage",
							Namespace: "default",
							Labels: map[string]string{
								"app": "mock",
							},
						},
						Spec:   regionv1.FileStorageSpec{},
						Status: regionv1.FileStorageStatus{},
					},
				},
			},
			want: openapi.StorageV2List{
				openapi.StorageV2Read{
					Metadata: corev1.ProjectScopedResourceReadMetadata{
						CreatedBy:          nil,
						CreationTime:       time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
						DeletionTime:       nil,
						Description:        nil,
						HealthStatus:       corev1.ResourceHealthStatus("unknown"),
						Id:                 "test-filestorage",
						ModifiedBy:         nil,
						ModifiedTime:       nil,
						Name:               "",
						OrganizationId:     "",
						ProjectId:          "",
						ProvisioningStatus: corev1.ResourceProvisioningStatus("unknown"),
						Tags:               nil,
					},

					Spec: openapi.StorageV2Spec{
						Attachments: &openapi.StorageAttachmentV2Spec{
							NetworkIDs: openapi.NetworkIDList{"net-1"},
						},
						Size: 1024,
						StorageType: openapi.StorageTypeV2Spec{
							NFS: nil,
						},
					},

					Status: openapi.StorageV2Status{
						Attachments:    nil,
						RegionId:       "",
						StorageClassId: "",
						Usage: openapi.StorageUsageV2Spec{
							Capacity: "",
							Free:     nil,
							Used:     nil,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := generateV2List(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestConvertV2(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input *regionv1.FileStorage
		want  *openapi.StorageV2Read
	}{
		{
			name: "basic conversion",
			input: &regionv1.FileStorage{
				TypeMeta: metav1.TypeMeta{
					Kind:       "FileStorage",
					APIVersion: "v1alpha1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-filestorage",
					Namespace: "default",
					Labels: map[string]string{
						"app": "mock",
					},
				},
				Spec:   regionv1.FileStorageSpec{},
				Status: regionv1.FileStorageStatus{},
			},
			want: &openapi.StorageV2Read{
				Metadata: corev1.ProjectScopedResourceReadMetadata{
					CreatedBy:          nil,
					CreationTime:       time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
					DeletionTime:       nil,
					Description:        nil,
					HealthStatus:       "unknown",
					Id:                 "test-filestorage",
					ModifiedBy:         nil,
					ModifiedTime:       nil,
					Name:               "",
					OrganizationId:     "",
					ProjectId:          "",
					ProvisioningStatus: "unknown",
				},
				Spec: openapi.StorageV2Spec{
					Attachments: &openapi.StorageAttachmentV2Spec{},
					Size:        1024,
					StorageType: openapi.StorageTypeV2Spec{},
				},
				Status: openapi.StorageV2Status{
					Attachments:    nil,
					RegionId:       "",
					StorageClassId: "",
					Usage: openapi.StorageUsageV2Spec{
						Capacity: "",
						Free:     nil,
						Used:     nil,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := convertV2(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}
