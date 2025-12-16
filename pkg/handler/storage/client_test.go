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
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	corev1 "github.com/unikorn-cloud/core/pkg/openapi"
	identityauth "github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/openapi"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func TestGenerateAttachmentList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input *openapi.StorageAttachmentV2Spec
		want  []regionv1.Attachment
	}{
		{
			name: "test with limited values",
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

func TestConvertV2List(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input *regionv1.FileStorageList
		want  openapi.StorageV2List
	}{
		{
			name: "test with limited values",
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
						Spec: regionv1.FileStorageSpec{
							NFS: &regionv1.NFS{
								RootSquash: true,
							},
						},
						Status: regionv1.FileStorageStatus{},
					},
				},
			},
			want: openapi.StorageV2List{
				openapi.StorageV2Read{
					Metadata: corev1.ProjectScopedResourceReadMetadata{
						CreationTime:       time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
						HealthStatus:       corev1.ResourceHealthStatus("unknown"),
						Id:                 "test-filestorage",
						ProvisioningStatus: corev1.ResourceProvisioningStatus("unknown"),
					},

					Spec: openapi.StorageV2Spec{
						SizeGiB: 0,
						Attachments: &openapi.StorageAttachmentV2Spec{
							NetworkIDs: []string{},
						},
						StorageType: openapi.StorageTypeV2Spec{
							NFS: &openapi.NFSV2Spec{
								RootSquash: true,
							},
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
						Spec: regionv1.FileStorageSpec{
							NFS: &regionv1.NFS{
								RootSquash: true,
							},
							Size: *convertSize(100),
							Attachments: []regionv1.Attachment{
								{
									NetworkID: "net-1",
								},
							},
						},
						Status: regionv1.FileStorageStatus{},
					},
				},
			},
			want: openapi.StorageV2List{
				openapi.StorageV2Read{
					Metadata: corev1.ProjectScopedResourceReadMetadata{
						CreationTime:       time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
						HealthStatus:       corev1.ResourceHealthStatus("unknown"),
						Id:                 "test-filestorage",
						ProvisioningStatus: corev1.ResourceProvisioningStatus("unknown"),
					},

					Spec: openapi.StorageV2Spec{
						SizeGiB: 100,
						Attachments: &openapi.StorageAttachmentV2Spec{
							NetworkIDs: []string{"net-1"},
						},
						StorageType: openapi.StorageTypeV2Spec{
							NFS: &openapi.NFSV2Spec{
								RootSquash: true,
							},
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

			got := convertV2List(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}

//nolint:dupl
func TestConvertV2(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input *regionv1.FileStorage
		want  *openapi.StorageV2Read
	}{
		{
			name: "test with limited values",
			input: &regionv1.FileStorage{
				TypeMeta: metav1.TypeMeta{
					Kind:       "FileStorage",
					APIVersion: "v1alpha1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "",
					Namespace: "default",
					Labels: map[string]string{
						"app": "mock",
					},
				},
				Spec: regionv1.FileStorageSpec{
					Size: *convertSize(int64(2)),
					NFS: &regionv1.NFS{
						RootSquash: true,
					},
					Attachments: []regionv1.Attachment{},
				},
			},
			want: &openapi.StorageV2Read{
				Metadata: corev1.ProjectScopedResourceReadMetadata{
					HealthStatus:       corev1.ResourceHealthStatusUnknown,
					ProvisioningStatus: corev1.ResourceProvisioningStatusUnknown,
				},
				Spec: openapi.StorageV2Spec{
					SizeGiB: 2,
					Attachments: &openapi.StorageAttachmentV2Spec{
						NetworkIDs: []string{},
					},
					StorageType: openapi.StorageTypeV2Spec{
						NFS: &openapi.NFSV2Spec{
							RootSquash: true,
						},
					},
				},
				Status: openapi.StorageV2Status{
					Usage: openapi.StorageUsageV2Spec{},
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

//nolint:dupl
func TestConvertV2SizeConversion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input *regionv1.FileStorage
		want  *openapi.StorageV2Read
	}{
		{
			name: "test with limited values",
			input: &regionv1.FileStorage{
				TypeMeta: metav1.TypeMeta{
					Kind:       "FileStorage",
					APIVersion: "v1alpha1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "",
					Namespace: "default",
					Labels: map[string]string{
						"app": "mock",
					},
				},
				Spec: regionv1.FileStorageSpec{
					Size: *convertSize(int64(2)),
					NFS: &regionv1.NFS{
						RootSquash: true,
					},
					Attachments: []regionv1.Attachment{},
				},
			},
			want: &openapi.StorageV2Read{
				Metadata: corev1.ProjectScopedResourceReadMetadata{
					HealthStatus:       corev1.ResourceHealthStatusUnknown,
					ProvisioningStatus: corev1.ResourceProvisioningStatusUnknown,
				},
				Spec: openapi.StorageV2Spec{
					SizeGiB: 2,
					Attachments: &openapi.StorageAttachmentV2Spec{
						NetworkIDs: []string{},
					},
					StorageType: openapi.StorageTypeV2Spec{
						NFS: &openapi.NFSV2Spec{
							RootSquash: true,
						},
					},
				},
				Status: openapi.StorageV2Status{
					Usage: openapi.StorageUsageV2Spec{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, int64(2147483648), tt.input.Spec.Size.Value())

			got := convertV2(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestConvertClass(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input *regionv1.FileStorageClass
		want  *openapi.StorageClassV2Read
	}{
		{
			name: "zero values",
			input: &regionv1.FileStorageClass{
				TypeMeta: metav1.TypeMeta{
					Kind:       "FileStorageClass",
					APIVersion: "v1alpha1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "",
					Namespace: "default",
				},
				Spec: regionv1.FileStorageClassSpec{},
			},
			want: &openapi.StorageClassV2Read{
				Metadata: corev1.ResourceReadMetadata{
					HealthStatus:       corev1.ResourceHealthStatusHealthy,
					ProvisioningStatus: corev1.ResourceProvisioningStatusProvisioned,
				},
				Spec: openapi.StorageClassV2Spec{
					Protocols: []openapi.StorageClassProtocolType{},
				},
			},
		},
		{
			name: "with region label and protocols",
			input: &regionv1.FileStorageClass{
				TypeMeta: metav1.TypeMeta{
					Kind:       "FileStorageClass",
					APIVersion: "v1alpha1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "sc-1",
					Namespace: "default",
					Labels: map[string]string{
						constants.RegionLabel:   "region-1",
						coreconstants.NameLabel: "sc-name",
					},
					Annotations: map[string]string{
						coreconstants.DescriptionAnnotation: "description",
					},
				},
				Spec: regionv1.FileStorageClassSpec{
					Protocols: []regionv1.Protocol{regionv1.NFSv3, regionv1.NFSv4},
				},
			},
			want: &openapi.StorageClassV2Read{
				Metadata: corev1.ResourceReadMetadata{
					Id:                 "sc-1",
					HealthStatus:       corev1.ResourceHealthStatusHealthy,
					ProvisioningStatus: corev1.ResourceProvisioningStatusProvisioned,
					Description:        ptr.To("description"),
					Name:               "sc-name",
				},
				Spec: openapi.StorageClassV2Spec{
					RegionId:  "region-1",
					Protocols: []openapi.StorageClassProtocolType{openapi.StorageClassProtocolTypeNfsv3, openapi.StorageClassProtocolTypeNfsv4},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := convertClass(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestConvertProtocols(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []regionv1.Protocol
		want  []openapi.StorageClassProtocolType
	}{
		{
			name:  "empty",
			input: nil,
			want:  []openapi.StorageClassProtocolType{},
		},
		{
			name:  "nfsv3 and nfsv4",
			input: []regionv1.Protocol{regionv1.NFSv3, regionv1.NFSv4},
			want:  []openapi.StorageClassProtocolType{openapi.StorageClassProtocolTypeNfsv3, openapi.StorageClassProtocolTypeNfsv4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := convertProtocols(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestGenerateV2(t *testing.T) {
	t.Parallel()

	inputBuilder := &generateV2InputBuilder{}

	tests := []struct {
		name  string
		input *generateV2Input
		want  *regionv1.FileStorage
	}{
		{
			name:  "generate FileStorage",
			input: inputBuilder.Default().Run(),
			want: &regionv1.FileStorage{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Labels: map[string]string{
						constants.RegionLabel:                    "reg-1",
						coreconstants.NameLabel:                  "test-filestorage",
						coreconstants.OrganizationLabel:          "org-1",
						coreconstants.ProjectLabel:               "proj-1",
						coreconstants.OrganizationPrincipalLabel: "org-1",
						coreconstants.ProjectPrincipalLabel:      "proj-1",
					},
					Annotations: map[string]string{
						coreconstants.CreatorAnnotation:          "user-1",
						coreconstants.CreatorPrincipalAnnotation: "actor@example.com",
					},
				},
				Spec: regionv1.FileStorageSpec{
					Size:           *resource.NewQuantity(int64(10737418240), resource.BinarySI),
					StorageClassID: "sc-1",
					Attachments:    []regionv1.Attachment{{NetworkID: "net-1"}},
					NFS: &regionv1.NFS{
						RootSquash: true,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client, ctx := newClientAndContext(t, &identityauth.Info{Userinfo: &identityopenapi.Userinfo{Sub: "user-1"}}, &principal.Principal{Actor: "actor@example.com"})

			got, err := client.generateV2(ctx, tt.input.organizationID, tt.input.projectID, tt.input.regionID, tt.input.request, tt.input.storageClassID)

			require.NoError(t, err)
			require.NotNil(t, got)

			// Name is dynamically generated; just assert it's present, then ignore it.
			require.NotEmpty(t, got.Name)
			got.Name = ""

			require.Equal(t, tt.want, got)
		})
	}
}

func TestGenerateV2Validations(t *testing.T) {
	t.Parallel()

	inputBuilder := &generateV2InputBuilder{}

	tests := []struct {
		name          string
		input         *generateV2Input
		principal     *principal.Principal
		authorization *identityauth.Info
		want          string
	}{
		{
			name:          "missing principal",
			input:         inputBuilder.Default().Run(),
			authorization: &identityauth.Info{Userinfo: &identityopenapi.Userinfo{Sub: "user-1"}},
			want:          "unable to set principal information",
		},
		{
			name:      "missing authorization",
			input:     inputBuilder.Default().Run(),
			principal: &principal.Principal{Actor: "actor@example.com"},
			want:      "failed to set identity metadata",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, ctx := newClientAndContext(t, tt.authorization, tt.principal)

			got, err := c.generateV2(ctx, tt.input.organizationID, tt.input.projectID, tt.input.regionID, tt.input.request, tt.input.storageClassID)

			require.Nil(t, got)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.want)
		})
	}
}

type generateV2Input struct {
	organizationID string
	projectID      string
	regionID       string
	storageClassID string
	request        *openapi.StorageV2Update
}

type generateV2InputBuilder struct {
	input *generateV2Input
}

func newDefaultGenerateV2Input() *generateV2Input {
	return &generateV2Input{
		organizationID: "org-1",
		projectID:      "proj-1",
		regionID:       "reg-1",
		storageClassID: "sc-1",
		request: &openapi.StorageV2Update{
			Metadata: corev1.ResourceWriteMetadata{
				Name: "test-filestorage",
			},
			Spec: openapi.StorageV2Spec{
				SizeGiB:     10,
				Attachments: &openapi.StorageAttachmentV2Spec{NetworkIDs: openapi.NetworkIDList{"net-1"}},
			},
		},
	}
}

func (b *generateV2InputBuilder) Default() *generateV2InputBuilder {
	b.input = newDefaultGenerateV2Input()

	return b
}

func (b *generateV2InputBuilder) WithSize(size int) *generateV2InputBuilder {
	if b.input == nil {
		b.input = newDefaultGenerateV2Input()
	}

	b.input.request.Spec.SizeGiB = int64(size)

	return b
}

func (b *generateV2InputBuilder) Run() *generateV2Input {
	return b.input
}

func newClientAndContext(t *testing.T, auth *identityauth.Info, principalInfo *principal.Principal) (*Client, context.Context) {
	t.Helper()

	client := &Client{namespace: "default"}
	ctx := t.Context()

	if auth != nil {
		ctx = identityauth.NewContext(ctx, auth)
	}

	if principalInfo != nil {
		ctx = principal.NewContext(ctx, principalInfo)
	}

	return client, ctx
}
