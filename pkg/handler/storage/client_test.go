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
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	corev1 "github.com/unikorn-cloud/core/pkg/openapi"
	identityauth "github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	networkclient "github.com/unikorn-cloud/region/pkg/handler/network"
	"github.com/unikorn-cloud/region/pkg/openapi"

	k8sv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const testNamespace = "uni-storage-test"

//nolint:gochecknoglobals
var (
	storageRange = &regionv1.AttachmentIPRange{
		Start: v1alpha1.IPv4Address{IP: net.IPv4(192, 168, 0, 1)},
		End:   v1alpha1.IPv4Address{IP: net.IPv4(192, 168, 0, 127)},
	}

	// TODO: This gets directly compared to the byte representation of the calculated range;
	// to avoid having to fiddle with converting 16 byte representations, I've just
	// inlined the exact, 4-byte IPv4 representation here. This may be a bit brittle.
	narrowedRange = &regionv1.AttachmentIPRange{
		Start: v1alpha1.IPv4Address{IP: net.IP{192, 168, 0, 1}},
		End:   v1alpha1.IPv4Address{IP: net.IP{192, 168, 0, 4}},
	}
)

const (
	giB = int64(1024 * 1024 * 1024)
	miB = int64(1024 * 1024)
)

func newTestNetwork(name string) *regionv1.Network {
	return &regionv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
			Labels: map[string]string{
				constants.ResourceAPIVersionLabel: "2",
			},
		},
		Status: regionv1.NetworkStatus{
			Openstack: &regionv1.NetworkStatusOpenstack{
				VlanID:       ptr.To(1111),
				StorageRange: storageRange,
			},
		},
	}
}

func newFakeClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, regionv1.AddToScheme(scheme))

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func newContextWithPermissions(ctx context.Context) context.Context {
	return rbac.NewContext(ctx, &identityopenapi.Acl{
		Global: &identityopenapi.AclEndpoints{
			identityopenapi.AclEndpoint{
				Name:       "region:networks:v2",
				Operations: []identityopenapi.AclOperation{"read"},
			},
		},
	})
}

func TestNarrowRange(t *testing.T) {
	t.Parallel()

	nr := narrowStorageRange(storageRange)
	require.Equal(t, nr, narrowedRange)

	// this can be nil, if it's not been set yet
	nr = narrowStorageRange(nil)
	require.Nilf(t, nr, "Expected nil output when nil input (and not a NPE panic)")
}

func TestGenerateAttachmentList(t *testing.T) {
	t.Parallel()

	network := newTestNetwork("net-1")
	client := newFakeClient(t, network)
	netclient := networkclient.New(client, testNamespace, nil)

	ctx := newContextWithPermissions(t.Context())

	tests := []struct {
		name  string
		input *openapi.StorageAttachmentV2Spec
		want  []regionv1.Attachment
	}{
		{
			name: "test with limited values",
			input: &openapi.StorageAttachmentV2Spec{
				NetworkIds: openapi.NetworkIDList{"net-1"},
			},
			want: []regionv1.Attachment{
				{
					NetworkID:      "net-1",
					SegmentationID: ptr.To(1111),
					IPRange:        narrowedRange,
				},
			},
		},
		{
			name:  "empty",
			input: &openapi.StorageAttachmentV2Spec{},
			want:  []regionv1.Attachment{},
		},
		{
			name:  "nil",
			input: nil,
			want:  []regionv1.Attachment{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := generateAttachmentList(ctx, netclient, tt.input)
			require.NoError(t, err)
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
							Namespace: testNamespace,
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
							NetworkIds: []string{},
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
							Namespace: testNamespace,
							Labels: map[string]string{
								"app": "mock",
							},
						},
						Spec: regionv1.FileStorageSpec{
							NFS: &regionv1.NFS{
								RootSquash: true,
							},
							Size: *gibToQuantity(int64(100)),
							Attachments: []regionv1.Attachment{
								{
									NetworkID:      "net-1",
									SegmentationID: ptr.To(1111),
									IPRange: &regionv1.AttachmentIPRange{
										Start: v1alpha1.IPv4Address{IP: net.IPv4(192, 168, 0, 1)},
										End:   v1alpha1.IPv4Address{IP: net.IPv4(192, 168, 0, 4)},
									},
								},
							},
						},
						Status: regionv1.FileStorageStatus{
							MountPath: ptr.To("/export"),
						},
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
							NetworkIds: []string{"net-1"},
						},
						StorageType: openapi.StorageTypeV2Spec{
							NFS: &openapi.NFSV2Spec{
								RootSquash: true,
							},
						},
					},

					Status: openapi.StorageV2Status{
						Attachments:    &openapi.StorageAttachmentListV2Status{{NetworkId: "net-1", MountSource: ptr.To("192.168.0.1:/export"), ProvisioningStatus: corev1.ResourceProvisioningStatusUnknown}},
						RegionId:       "",
						StorageClassId: "",
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
					Size: *gibToQuantity(int64(2)),
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
						NetworkIds: []string{},
					},
					StorageType: openapi.StorageTypeV2Spec{
						NFS: &openapi.NFSV2Spec{
							RootSquash: true,
						},
					},
				},
				Status: openapi.StorageV2Status{},
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
					Size: *gibToQuantity(int64(2)),
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
						NetworkIds: []string{},
					},
					StorageType: openapi.StorageTypeV2Spec{
						NFS: &openapi.NFSV2Spec{
							RootSquash: true,
						},
					},
				},
				Status: openapi.StorageV2Status{},
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

	network := newTestNetwork("net-1")

	k8s := newFakeClient(t, network)

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
					Namespace: testNamespace,
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
					Size:           *resource.NewQuantity(10*giB, resource.BinarySI),
					StorageClassID: "sc-1",
					Attachments: []regionv1.Attachment{
						{
							NetworkID:      "net-1",
							SegmentationID: ptr.To(1111),
							IPRange:        narrowedRange,
						}},
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

			client, ctx := newClientAndContext(t, k8s, &identityauth.Info{Userinfo: &identityopenapi.Userinfo{Sub: "user-1"}}, &principal.Principal{Actor: "actor@example.com"})

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

func TestGet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    regionv1.FileStorage
		expected *openapi.StorageV2Read
	}{
		{
			name: "passing conditions",
			input: regionv1.FileStorage{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      "fs-1",
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
					Size:           *resource.NewQuantity(1*giB, resource.BinarySI),
					StorageClassID: "sc-1",
					Attachments: []regionv1.Attachment{
						{NetworkID: "net-1"},
					},
					NFS: &regionv1.NFS{
						RootSquash: true,
					},
				},
			},
			expected: &openapi.StorageV2Read{
				Metadata: corev1.ProjectScopedResourceReadMetadata{
					ProjectId: "proj-1",
				},
				Status: openapi.StorageV2Status{
					StorageClassId: "sc-1",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			obj := defaultFSK8sObjects()

			obj = append(obj, &tt.input)

			c, ctx := newClientwithObjectandContext(t, ctx, obj...)

			result, err := c.Get(ctx, tt.input.Name)
			require.NoError(t, err)
			require.NotNil(t, result, "result should not be empty")
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
		},
		{
			name:      "missing authorization",
			input:     inputBuilder.Default().Run(),
			principal: &principal.Principal{Actor: "actor@example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := newFakeClient(t)

			c, ctx := newClientAndContext(t, client, tt.authorization, tt.principal)

			got, err := c.generateV2(ctx, tt.input.organizationID, tt.input.projectID, tt.input.regionID, tt.input.request, tt.input.storageClassID)

			require.Nil(t, got)
			require.Error(t, err)
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
				Attachments: &openapi.StorageAttachmentV2Spec{NetworkIds: openapi.NetworkIDList{"net-1"}},
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

func newClientAndContext(t *testing.T, c client.Client, auth *identityauth.Info, principalInfo *principal.Principal) (*Client, context.Context) {
	t.Helper()

	client := New(c, testNamespace, nil)
	ctx := t.Context()

	if auth != nil {
		ctx = identityauth.NewContext(ctx, auth)
	}

	if principalInfo != nil {
		ctx = principal.NewContext(ctx, principalInfo)
	}

	ctx = newContextWithPermissions(ctx)

	return client, ctx
}

//nolint:revive
func newClientwithObjectandContext(t *testing.T, ctx context.Context, initObjs ...client.Object) (*Client, context.Context) {
	t.Helper()

	scheme := runtime.NewScheme()

	require.NoError(t, regionv1.AddToScheme(scheme))

	// Add configmaps and secrets to the mock
	require.NoError(t, metav1.AddMetaToScheme(scheme))
	require.NoError(t, k8sv1.AddToScheme(scheme))

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(initObjs...).
		Build()

	c := &Client{
		client:    k8sClient,
		namespace: testNamespace,
	}

	oapiacl := &identityopenapi.Acl{Global: &identityopenapi.AclEndpoints{
		identityopenapi.AclEndpoint{
			Name: "region:filestorage:v2",
			Operations: identityopenapi.AclOperations{
				identityopenapi.Read, identityopenapi.Create,
			},
		},
	},
	}

	ctx = identityauth.NewContext(ctx, &identityauth.Info{Userinfo: &identityopenapi.Userinfo{Sub: "user-1"}})
	ctx = rbac.NewContext(ctx, oapiacl)
	ctx = principal.NewContext(ctx, &principal.Principal{Actor: "actor@example.com"})

	return c, ctx
}

// defaultFSK8sObjects creates a FileStorageProvisioner and FileStorageClass
// k8s client objects.
func defaultFSK8sObjects() []client.Object {
	return []client.Object{
		&regionv1.FileStorageProvisioner{
			Spec: regionv1.FileStorageProvisionerSpec{
				ConfigRef: &regionv1.NamespacedObject{
					Name:      "sc-1",
					Namespace: testNamespace,
				},
			},
		},
		&regionv1.FileStorageClass{
			TypeMeta: metav1.TypeMeta{
				Kind:       "FileStorageClass",
				APIVersion: "v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "sc-1",
				Namespace: testNamespace,
			},
			Spec: regionv1.FileStorageClassSpec{},
		},
	}
}
