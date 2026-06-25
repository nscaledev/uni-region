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
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	corev1 "github.com/unikorn-cloud/core/pkg/openapi"
	servererrors "github.com/unikorn-cloud/core/pkg/server/errors"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	identityauth "github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	identitymock "github.com/unikorn-cloud/identity/pkg/openapi/mock"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	networkclient "github.com/unikorn-cloud/region/pkg/handler/network"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/openapi"

	k8sv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace      = "uni-storage-test"
	testOrganizationID = "11111111-1111-4111-a111-111111111111"
	testProjectID      = "22222222-2222-4222-a222-222222222222"
	testRegionID       = "33333333-3333-4333-a333-333333333333"
	testFileStorageID  = "44444444-4444-4444-a444-444444444444"
	testAllocationID   = "66666666-6666-4666-a666-666666666666"
	testNetworkID      = "77777777-7777-4777-a777-777777777777"
)

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

	narrowedRangeCapped = &regionv1.AttachmentIPRange{
		Start: v1alpha1.IPv4Address{IP: net.IP{192, 168, 0, 1}},
		End:   v1alpha1.IPv4Address{IP: net.IP{192, 168, 0, 127}},
	}

	emptyStorageSnapshotPolicies        = openapi.StorageSnapshotPolicyListV2Spec{}
	emptyStorageSnapshotPoliciesPointer = &emptyStorageSnapshotPolicies
	emptyStorageSnapshotPolicyStatuses  = openapi.StorageSnapshotPolicyListV2Status{}
)

const (
	giB = int64(1024 * 1024 * 1024)
	miB = int64(1024 * 1024)
)

func newTestNetwork() *regionv1.Network {
	return &regionv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testNetworkID,
			Namespace: testNamespace,
			Labels: map[string]string{
				constants.ResourceAPIVersionLabel: "2",
				coreconstants.OrganizationLabel:   testOrganizationID,
				coreconstants.ProjectLabel:        testProjectID,
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
	restMapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{regionv1.SchemeGroupVersion})
	restMapper.Add(regionv1.SchemeGroupVersion.WithKind("FileStorage"), meta.RESTScopeNamespace)

	return fake.NewClientBuilder().WithScheme(scheme).WithRESTMapper(restMapper).WithObjects(objects...).Build()
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

	nr := narrowStorageRange(storageRange, 4)
	require.Equal(t, nr, narrowedRange)

	// this can be nil, if it's not been set yet
	nr = narrowStorageRange(nil, -1)
	require.Nilf(t, nr, "Expected nil output when nil input (and not a NPE panic)")
}

func TestNarrowRangeWithCap(t *testing.T) {
	t.Parallel()

	nr := narrowStorageRange(storageRange, 256)
	require.Equal(t, nr, narrowedRangeCapped)
}

func TestValidateStorageRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		network      *regionv1.Network
		parallelism  int
		wantRange    *regionv1.AttachmentIPRange
		wantError    bool
		wantErrorMsg string
	}{
		{
			name: "valid range has enough addresses",
			network: &regionv1.Network{
				Status: regionv1.NetworkStatus{
					Openstack: &regionv1.NetworkStatusOpenstack{
						StorageRange: &regionv1.AttachmentIPRange{
							Start: v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 1)},
							End:   v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 127)},
						},
					},
				},
			},
			parallelism: 4,
			wantRange: &regionv1.AttachmentIPRange{
				Start: v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 1)},
				End:   v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 127)},
			},
		},
		{
			name: "exact match of available addresses and parallelism",
			network: &regionv1.Network{
				Status: regionv1.NetworkStatus{
					Openstack: &regionv1.NetworkStatusOpenstack{
						StorageRange: &regionv1.AttachmentIPRange{
							Start: v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 1)},
							End:   v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 4)},
						},
					},
				},
			},
			parallelism: 4,
			wantRange: &regionv1.AttachmentIPRange{
				Start: v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 1)},
				End:   v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 4)},
			},
		},
		{
			name: "openstack status missing",
			network: &regionv1.Network{
				Status: regionv1.NetworkStatus{},
			},
			parallelism:  4,
			wantError:    true,
			wantErrorMsg: "network requested is not a suitable network",
		},
		{
			name: "storage range missing",
			network: &regionv1.Network{
				Status: regionv1.NetworkStatus{
					Openstack: &regionv1.NetworkStatusOpenstack{},
				},
			},
			parallelism:  4,
			wantError:    true,
			wantErrorMsg: "network requested does not have a storage range configured",
		},
		{
			name: "range is not valid ipv4",
			network: &regionv1.Network{
				Status: regionv1.NetworkStatus{
					Openstack: &regionv1.NetworkStatusOpenstack{
						StorageRange: &regionv1.AttachmentIPRange{
							Start: v1alpha1.IPv4Address{IP: net.ParseIP("2001:db8::1")},
							End:   v1alpha1.IPv4Address{IP: net.ParseIP("2001:db8::10")},
						},
					},
				},
			},
			parallelism:  4,
			wantError:    true,
			wantErrorMsg: "network storage range is not a valid IPv4 range",
		},
		{
			name: "single address range with parallelism 1",
			network: &regionv1.Network{
				Status: regionv1.NetworkStatus{
					Openstack: &regionv1.NetworkStatusOpenstack{
						StorageRange: &regionv1.AttachmentIPRange{
							Start: v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 5)},
							End:   v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 5)},
						},
					},
				},
			},
			parallelism: 1,
			wantRange: &regionv1.AttachmentIPRange{
				Start: v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 5)},
				End:   v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 5)},
			},
		},
		{
			name: "range smaller than parallelism is valid",
			network: &regionv1.Network{
				Status: regionv1.NetworkStatus{
					Openstack: &regionv1.NetworkStatusOpenstack{
						StorageRange: &regionv1.AttachmentIPRange{
							Start: v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 1)},
							End:   v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 3)},
						},
					},
				},
			},
			parallelism: 4,
			wantRange: &regionv1.AttachmentIPRange{
				Start: v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 1)},
				End:   v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 3)},
			},
		},
		{
			name: "single address range with parallelism greater than available addresses",
			network: &regionv1.Network{
				Status: regionv1.NetworkStatus{
					Openstack: &regionv1.NetworkStatusOpenstack{
						StorageRange: &regionv1.AttachmentIPRange{
							Start: v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 5)},
							End:   v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 5)},
						},
					},
				},
			},
			parallelism: 2,
			wantRange: &regionv1.AttachmentIPRange{
				Start: v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 5)},
				End:   v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 5)},
			},
		},
		{
			name: "zero usable address range",
			network: &regionv1.Network{
				Status: regionv1.NetworkStatus{
					Openstack: &regionv1.NetworkStatusOpenstack{
						StorageRange: &regionv1.AttachmentIPRange{
							Start: v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 5)},
							End:   v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 4)},
						},
					},
				},
			},
			parallelism:  5,
			wantError:    true,
			wantErrorMsg: "network storage range does not contain any usable addresses",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := validateStorageRange(tt.network, tt.parallelism)

			if tt.wantError {
				require.Error(t, err)
				require.True(t, servererrors.IsUnprocessableContent(err))
				require.EqualError(t, err, tt.wantErrorMsg)
				require.Nil(t, got)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantRange, got)
		})
	}
}

func TestGenerateAttachment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		storageRange *regionv1.AttachmentIPRange
		parallelism  int
		wantIPRange  *regionv1.AttachmentIPRange
		wantErrorMsg string
	}{
		{
			name: "exact match of available addresses and parallelism",
			storageRange: &regionv1.AttachmentIPRange{
				Start: v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 1)},
				End:   v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 4)},
			},
			parallelism: 4,
			wantIPRange: &regionv1.AttachmentIPRange{
				Start: v1alpha1.IPv4Address{IP: net.IP{10, 0, 0, 1}},
				End:   v1alpha1.IPv4Address{IP: net.IP{10, 0, 0, 4}},
			},
		},
		{
			name: "range larger than parallelism is narrowed",
			storageRange: &regionv1.AttachmentIPRange{
				Start: v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 1)},
				End:   v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 10)},
			},
			parallelism: 4,
			wantIPRange: &regionv1.AttachmentIPRange{
				Start: v1alpha1.IPv4Address{IP: net.IP{10, 0, 0, 1}},
				End:   v1alpha1.IPv4Address{IP: net.IP{10, 0, 0, 4}},
			},
		},
		{
			name: "range smaller than parallelism is used in full",
			storageRange: &regionv1.AttachmentIPRange{
				Start: v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 1)},
				End:   v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 3)},
			},
			parallelism: 4,
			wantIPRange: &regionv1.AttachmentIPRange{
				Start: v1alpha1.IPv4Address{IP: net.IP{10, 0, 0, 1}},
				End:   v1alpha1.IPv4Address{IP: net.IP{10, 0, 0, 3}},
			},
		},
		{
			name: "single address range is used in full",
			storageRange: &regionv1.AttachmentIPRange{
				Start: v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 5)},
				End:   v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 5)},
			},
			parallelism: 4,
			wantIPRange: &regionv1.AttachmentIPRange{
				Start: v1alpha1.IPv4Address{IP: net.IP{10, 0, 0, 5}},
				End:   v1alpha1.IPv4Address{IP: net.IP{10, 0, 0, 5}},
			},
		},
		{
			name: "zero usable address range is rejected",
			storageRange: &regionv1.AttachmentIPRange{
				Start: v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 5)},
				End:   v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 4)},
			},
			parallelism:  4,
			wantErrorMsg: "network storage range does not contain any usable addresses",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			network := newTestNetwork()
			network.Status.Openstack.StorageRange = tt.storageRange

			got, err := generateAttachment(network, tt.parallelism)

			if tt.wantErrorMsg != "" {
				require.Error(t, err)
				require.True(t, servererrors.IsUnprocessableContent(err))
				require.EqualError(t, err, tt.wantErrorMsg)
				require.Nil(t, got)

				return
			}

			require.NoError(t, err)
			require.Equal(t, testNetworkID, got.NetworkID)
			require.Equal(t, ptr.To(1111), got.SegmentationID)
			require.Equal(t, tt.wantIPRange, got.IPRange)
		})
	}
}

func TestGenerateAttachmentList(t *testing.T) {
	t.Parallel()

	network := newTestNetwork()
	client := newFakeClient(t, network)

	clientArgs := common.ClientArgs{
		Client:    client,
		Namespace: testNamespace,
	}

	netclient := networkclient.New(clientArgs)

	ctx := newContextWithPermissions(t.Context())

	tests := []struct {
		name  string
		input *storageV2GenerateRequest
		want  []regionv1.Attachment
	}{
		{
			name: "test with limited values",
			input: &storageV2GenerateRequest{
				Spec: storageV2GenerateSpec{
					Attachments: &openapi.StorageAttachmentV2Spec{
						NetworkIds: openapi.NetworkIDList{testNetworkID},
					},
					StorageType: openapi.StorageTypeV2Spec{
						NFS: &openapi.NFSV2Spec{},
					},
				},
			},
			want: []regionv1.Attachment{
				{
					NetworkID:      testNetworkID,
					SegmentationID: ptr.To(1111),
					IPRange:        narrowedRange,
				},
			},
		},
		{
			name:  "empty",
			input: &storageV2GenerateRequest{},
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

			got, err := generateAttachmentList(ctx, netclient, tt.input, DefaultParallelism)
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
						HealthStatus:       corev1.ResourceHealthStatusUnknown,
						Id:                 "test-filestorage",
						ProvisioningStatus: corev1.ResourceProvisioningStatusPending,
					},

					Spec: openapi.StorageV2Spec{
						SizeGiB: 0,
						Attachments: &openapi.StorageAttachmentV2Spec{
							NetworkIds: []string{},
						},
						DefaultSnapshotProtectionEnabled: ptr.To(false),
						SnapshotPolicies:                 emptyStorageSnapshotPoliciesPointer,
						StorageType: openapi.StorageTypeV2Spec{
							NFS: &openapi.NFSV2Spec{
								RootSquash: true,
							},
						},
					},

					Status: openapi.StorageV2Status{
						Attachments:      nil,
						RegionId:         "",
						SnapshotPolicies: emptyStorageSnapshotPolicyStatuses,
						StorageClassId:   "",
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
									NetworkID:      testNetworkID,
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
						HealthStatus:       corev1.ResourceHealthStatusUnknown,
						Id:                 "test-filestorage",
						ProvisioningStatus: corev1.ResourceProvisioningStatusPending,
					},

					Spec: openapi.StorageV2Spec{
						SizeGiB: 100,
						Attachments: &openapi.StorageAttachmentV2Spec{
							NetworkIds: []string{testNetworkID},
						},
						DefaultSnapshotProtectionEnabled: ptr.To(false),
						SnapshotPolicies:                 emptyStorageSnapshotPoliciesPointer,
						StorageType: openapi.StorageTypeV2Spec{
							NFS: &openapi.NFSV2Spec{
								RootSquash: true,
							},
						},
					},

					Status: openapi.StorageV2Status{
						Attachments:      &openapi.StorageAttachmentListV2Status{{NetworkId: testNetworkID, MountSource: ptr.To("192.168.0.1:/export"), ProvisioningStatus: corev1.ResourceProvisioningStatusPending}},
						RegionId:         "",
						SnapshotPolicies: emptyStorageSnapshotPolicyStatuses,
						StorageClassId:   "",
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

func TestConvertStatusAttachmentList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input *regionv1.FileStorage
		want  *openapi.StorageAttachmentListV2Status
	}{
		{
			name: "observed status enriches desired attachment",
			input: &regionv1.FileStorage{
				Spec: regionv1.FileStorageSpec{
					Attachments: []regionv1.Attachment{
						{
							NetworkID: testNetworkID,
							IPRange: &regionv1.AttachmentIPRange{
								Start: v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 100)},
								End:   v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 103)},
							},
						},
					},
				},
				Status: regionv1.FileStorageStatus{
					MountPath: ptr.To("/export/data"),
					Attachments: []regionv1.FileStorageAttachmentStatus{
						{
							NetworkID:          testNetworkID,
							ProvisioningStatus: regionv1.AttachmentProvisioned,
							IPRange: &regionv1.AttachmentIPRange{
								Start: v1alpha1.IPv4Address{IP: net.IPv4(192, 168, 20, 16)},
								End:   v1alpha1.IPv4Address{IP: net.IPv4(192, 168, 20, 23)},
							},
						},
					},
				},
			},
			want: &openapi.StorageAttachmentListV2Status{
				{
					NetworkId:          testNetworkID,
					MountSource:        ptr.To("10.0.0.100:/export/data"),
					MountOptions:       ptr.To(map[string]string{"remoteports": "192.168.20.16-192.168.20.23"}),
					ProvisioningStatus: corev1.ResourceProvisioningStatusProvisioned,
				},
			},
		},
		{
			name: "single observed IP range emits a single remote port",
			input: &regionv1.FileStorage{
				Spec: regionv1.FileStorageSpec{
					Attachments: []regionv1.Attachment{
						{
							NetworkID: testNetworkID,
						},
					},
				},
				Status: regionv1.FileStorageStatus{
					Attachments: []regionv1.FileStorageAttachmentStatus{
						{
							NetworkID:          testNetworkID,
							ProvisioningStatus: regionv1.AttachmentProvisioned,
							IPRange: &regionv1.AttachmentIPRange{
								Start: v1alpha1.IPv4Address{IP: net.IPv4(192, 168, 20, 16)},
								End:   v1alpha1.IPv4Address{IP: net.IPv4(192, 168, 20, 16)},
							},
						},
					},
				},
			},
			want: &openapi.StorageAttachmentListV2Status{
				{
					NetworkId:          testNetworkID,
					MountOptions:       ptr.To(map[string]string{"remoteports": "192.168.20.16"}),
					ProvisioningStatus: corev1.ResourceProvisioningStatusProvisioned,
				},
			},
		},
		{
			name: "desired attachment without observed status remains pending",
			input: &regionv1.FileStorage{
				Spec: regionv1.FileStorageSpec{
					Attachments: []regionv1.Attachment{
						{
							NetworkID: testNetworkID,
						},
					},
				},
			},
			want: &openapi.StorageAttachmentListV2Status{
				{
					NetworkId:          testNetworkID,
					ProvisioningStatus: corev1.ResourceProvisioningStatusPending,
				},
			},
		},
		{
			name: "stale observed status is not returned",
			input: &regionv1.FileStorage{
				Spec: regionv1.FileStorageSpec{
					Attachments: []regionv1.Attachment{
						{
							NetworkID: testNetworkID,
						},
					},
				},
				Status: regionv1.FileStorageStatus{
					Attachments: []regionv1.FileStorageAttachmentStatus{
						{
							NetworkID:          "net-2",
							ProvisioningStatus: regionv1.AttachmentProvisioned,
							IPRange: &regionv1.AttachmentIPRange{
								Start: v1alpha1.IPv4Address{IP: net.IPv4(192, 168, 20, 16)},
								End:   v1alpha1.IPv4Address{IP: net.IPv4(192, 168, 20, 23)},
							},
						},
					},
				},
			},
			want: &openapi.StorageAttachmentListV2Status{
				{
					NetworkId:          testNetworkID,
					ProvisioningStatus: corev1.ResourceProvisioningStatusPending,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := convertStatusAttachmentList(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestConvertAttachmentProvisioningStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input regionv1.AttachmentProvisioningStatus
		want  corev1.ResourceProvisioningStatus
	}{
		{
			name:  "provisioning",
			input: regionv1.AttachmentProvisioning,
			want:  corev1.ResourceProvisioningStatusProvisioning,
		},
		{
			name:  "provisioned",
			input: regionv1.AttachmentProvisioned,
			want:  corev1.ResourceProvisioningStatusProvisioned,
		},
		{
			name:  "errored",
			input: regionv1.AttachmentErrored,
			want:  corev1.ResourceProvisioningStatusError,
		},
		{
			name:  "deprovisioning",
			input: regionv1.AttachmentDeprovisioning,
			want:  corev1.ResourceProvisioningStatusDeprovisioning,
		},
		{
			name:  "unknown",
			input: regionv1.AttachmentProvisioningStatus(""),
			want:  corev1.ResourceProvisioningStatusUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := convertAttachmentProvisioningStatus(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestConvertV2(t *testing.T) {
	t.Parallel()

	usageTimestamp := time.Date(2026, 1, 31, 12, 0, 0, 0, time.UTC)

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
					ProvisioningStatus: corev1.ResourceProvisioningStatusPending,
				},
				Spec: openapi.StorageV2Spec{
					SizeGiB: 2,
					Attachments: &openapi.StorageAttachmentV2Spec{
						NetworkIds: []string{},
					},
					DefaultSnapshotProtectionEnabled: ptr.To(false),
					SnapshotPolicies:                 emptyStorageSnapshotPoliciesPointer,
					StorageType: openapi.StorageTypeV2Spec{
						NFS: &openapi.NFSV2Spec{
							RootSquash: true,
						},
					},
				},
				Status: openapi.StorageV2Status{
					SnapshotPolicies: emptyStorageSnapshotPolicyStatuses,
				},
			},
		},
		{
			name: "usage status with all fields set",
			input: &regionv1.FileStorage{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
				},
				Spec: regionv1.FileStorageSpec{
					Size:        *gibToQuantity(100),
					NFS:         &regionv1.NFS{RootSquash: true},
					Attachments: []regionv1.Attachment{},
				},
				Status: regionv1.FileStorageStatus{
					Size:           resource.NewQuantity(100*giB, resource.BinarySI),
					Usage:          resource.NewQuantity(50*giB, resource.BinarySI),
					UsageTimestamp: &metav1.Time{Time: usageTimestamp},
				},
			},
			want: &openapi.StorageV2Read{
				Metadata: corev1.ProjectScopedResourceReadMetadata{
					HealthStatus:       corev1.ResourceHealthStatusUnknown,
					ProvisioningStatus: corev1.ResourceProvisioningStatusPending,
				},
				Spec: openapi.StorageV2Spec{
					SizeGiB:                          100,
					Attachments:                      &openapi.StorageAttachmentV2Spec{NetworkIds: []string{}},
					DefaultSnapshotProtectionEnabled: ptr.To(false),
					SnapshotPolicies:                 emptyStorageSnapshotPoliciesPointer,
					StorageType:                      openapi.StorageTypeV2Spec{NFS: &openapi.NFSV2Spec{RootSquash: true}},
				},
				Status: openapi.StorageV2Status{
					SnapshotPolicies: emptyStorageSnapshotPolicyStatuses,
					Usage: &openapi.StorageUsageV2Status{
						CapacityBytes: 100 * giB,
						UsedBytes:     ptr.To(50 * giB),
						UpdatedAt:     &usageTimestamp,
					},
				},
			},
		},
		{
			name: "usage status with all nil fields",
			input: &regionv1.FileStorage{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
				},
				Spec: regionv1.FileStorageSpec{
					Size:        *gibToQuantity(100),
					NFS:         &regionv1.NFS{RootSquash: true},
					Attachments: []regionv1.Attachment{},
				},
				Status: regionv1.FileStorageStatus{
					Size:           nil,
					Usage:          nil,
					UsageTimestamp: nil,
				},
			},
			want: &openapi.StorageV2Read{
				Metadata: corev1.ProjectScopedResourceReadMetadata{
					HealthStatus:       corev1.ResourceHealthStatusUnknown,
					ProvisioningStatus: corev1.ResourceProvisioningStatusPending,
				},
				Spec: openapi.StorageV2Spec{
					SizeGiB:                          100,
					Attachments:                      &openapi.StorageAttachmentV2Spec{NetworkIds: []string{}},
					DefaultSnapshotProtectionEnabled: ptr.To(false),
					SnapshotPolicies:                 emptyStorageSnapshotPoliciesPointer,
					StorageType:                      openapi.StorageTypeV2Spec{NFS: &openapi.NFSV2Spec{RootSquash: true}},
				},
				Status: openapi.StorageV2Status{
					SnapshotPolicies: emptyStorageSnapshotPolicyStatuses,
					Usage:            nil,
				},
			},
		},
		{
			name: "usage status with only capacity set",
			input: &regionv1.FileStorage{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
				},
				Spec: regionv1.FileStorageSpec{
					Size:        *gibToQuantity(100),
					NFS:         &regionv1.NFS{RootSquash: true},
					Attachments: []regionv1.Attachment{},
				},
				Status: regionv1.FileStorageStatus{
					Size:           resource.NewQuantity(100*giB, resource.BinarySI),
					Usage:          nil,
					UsageTimestamp: nil,
				},
			},
			want: &openapi.StorageV2Read{
				Metadata: corev1.ProjectScopedResourceReadMetadata{
					HealthStatus:       corev1.ResourceHealthStatusUnknown,
					ProvisioningStatus: corev1.ResourceProvisioningStatusPending,
				},
				Spec: openapi.StorageV2Spec{
					SizeGiB:                          100,
					Attachments:                      &openapi.StorageAttachmentV2Spec{NetworkIds: []string{}},
					DefaultSnapshotProtectionEnabled: ptr.To(false),
					SnapshotPolicies:                 emptyStorageSnapshotPoliciesPointer,
					StorageType:                      openapi.StorageTypeV2Spec{NFS: &openapi.NFSV2Spec{RootSquash: true}},
				},
				Status: openapi.StorageV2Status{
					SnapshotPolicies: emptyStorageSnapshotPolicyStatuses,
					Usage: &openapi.StorageUsageV2Status{
						CapacityBytes: 100 * giB,
						UsedBytes:     nil,
						UpdatedAt:     nil,
					},
				},
			},
		},
		{
			name: "attachment with mount path",
			input: &regionv1.FileStorage{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
				},
				Spec: regionv1.FileStorageSpec{
					Size: *gibToQuantity(100),
					NFS:  &regionv1.NFS{RootSquash: true},
					Attachments: []regionv1.Attachment{
						{
							NetworkID: testNetworkID,
							IPRange: &regionv1.AttachmentIPRange{
								Start: v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 100)},
								End:   v1alpha1.IPv4Address{IP: net.IPv4(10, 0, 0, 110)},
							},
						},
					},
				},
				Status: regionv1.FileStorageStatus{
					MountPath: ptr.To("/export/data"),
				},
			},
			want: &openapi.StorageV2Read{
				Metadata: corev1.ProjectScopedResourceReadMetadata{
					HealthStatus:       corev1.ResourceHealthStatusUnknown,
					ProvisioningStatus: corev1.ResourceProvisioningStatusPending,
				},
				Spec: openapi.StorageV2Spec{
					SizeGiB:                          100,
					Attachments:                      &openapi.StorageAttachmentV2Spec{NetworkIds: []string{testNetworkID}},
					DefaultSnapshotProtectionEnabled: ptr.To(false),
					SnapshotPolicies:                 emptyStorageSnapshotPoliciesPointer,
					StorageType:                      openapi.StorageTypeV2Spec{NFS: &openapi.NFSV2Spec{RootSquash: true}},
				},
				Status: openapi.StorageV2Status{
					SnapshotPolicies: emptyStorageSnapshotPolicyStatuses,
					Attachments: &openapi.StorageAttachmentListV2Status{
						{
							NetworkId:          testNetworkID,
							MountSource:        ptr.To("10.0.0.100:/export/data"),
							ProvisioningStatus: corev1.ResourceProvisioningStatusPending,
						},
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

func TestConvertV2SizeConversion(t *testing.T) {
	t.Parallel()

	input := &regionv1.FileStorage{
		Spec: regionv1.FileStorageSpec{
			Size: *gibToQuantity(2),
		},
	}
	require.Equal(t, int64(2147483648), input.Spec.Size.Value())

	got := convertV2(input)
	require.Equal(t, int64(2), got.Spec.SizeGiB)
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
					Parallelism: DefaultParallelism,
					Protocols:   []openapi.StorageClassProtocolType{},
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
					RegionId:    "region-1",
					Parallelism: DefaultParallelism,
					Protocols:   []openapi.StorageClassProtocolType{openapi.StorageClassProtocolTypeNfsv3, openapi.StorageClassProtocolTypeNfsv4},
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

func TestGetStorageClassParallelism(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		parallelism     *int
		wantParallelism int
	}{
		{
			name:            "explicit parallelism value",
			parallelism:     ptr.To(8),
			wantParallelism: 8,
		},
		{
			name:            "nil parallelism defaults to DefaultParallelism",
			parallelism:     nil,
			wantParallelism: DefaultParallelism,
		},
		{
			name:            "zero parallelism defaults to DefaultParallelism",
			parallelism:     ptr.To(0),
			wantParallelism: DefaultParallelism,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			storageClass := &regionv1.FileStorageClass{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "sc-1",
					Namespace: testNamespace,
					Labels: map[string]string{
						constants.RegionLabel: "region-1",
					},
				},
				Spec: regionv1.FileStorageClassSpec{
					Protocols:   []regionv1.Protocol{regionv1.NFSv3},
					Parallelism: tt.parallelism,
				},
			}

			k8sClient := newFakeClient(t, storageClass)

			c := &Client{
				ClientArgs: common.ClientArgs{
					Client:    k8sClient,
					Namespace: testNamespace,
				},
			}

			ctx := newContextWithPermissions(t.Context())

			result, err := c.GetStorageClass(ctx, "sc-1")
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, tt.wantParallelism, result.Spec.Parallelism)
		})
	}
}

func TestCreateV2OmittedDefaultProtectionEnablesDefaultAndCreatesNoSnapshotPolicies(t *testing.T) {
	t.Parallel()

	got := createStorageV2ForSnapshotPolicyTest(t, nil)

	require.Equal(t, ptr.To(true), got.Spec.DefaultSnapshotProtectionEnabled)

	require.NotNil(t, got.Spec.SnapshotPolicies)
	require.Empty(t, *got.Spec.SnapshotPolicies)

	require.NotNil(t, got.Status.SnapshotPolicies)
	require.Empty(t, got.Status.SnapshotPolicies)
}

func TestCreateV2ExplicitFalseDisablesDefaultProtection(t *testing.T) {
	t.Parallel()

	got := createStorageV2ForSnapshotPolicyTest(t, func(request *openapi.StorageV2Create) {
		request.Spec.DefaultSnapshotProtectionEnabled = ptr.To(false)
	})

	require.Equal(t, ptr.To(false), got.Spec.DefaultSnapshotProtectionEnabled)

	require.NotNil(t, got.Spec.SnapshotPolicies)
	require.Empty(t, *got.Spec.SnapshotPolicies)

	require.NotNil(t, got.Status.SnapshotPolicies)
	require.Empty(t, got.Status.SnapshotPolicies)
}

func TestCreateV2RejectsSystemDefaultPolicyWhenDefaultProtectionEnabled(t *testing.T) {
	t.Parallel()

	policies := openapi.StorageSnapshotPolicyListV2Spec{
		{
			Name: "system-default",
			Schedule: openapi.StorageSnapshotScheduleV2Spec{
				Interval: openapi.StorageSnapshotScheduleIntervalV2Hourly,
			},
			Retention: openapi.StorageSnapshotRetentionV2Spec{Keep: 24},
		},
	}

	_, err := createStorageV2ForSnapshotPolicyResult(t, func(request *openapi.StorageV2Create) {
		request.Spec.SnapshotPolicies = &policies
	})
	require.Error(t, err)
	require.True(t, servererrors.IsUnprocessableContent(err), "expected 422, got: %v", err)
}

func TestCreateV2AllowsDefaultPolicyName(t *testing.T) {
	t.Parallel()

	policies := openapi.StorageSnapshotPolicyListV2Spec{
		{
			Name: "default",
			Schedule: openapi.StorageSnapshotScheduleV2Spec{
				Interval:  openapi.StorageSnapshotScheduleIntervalV2Daily,
				TimeOfDay: ptr.To("04:00Z"),
			},
			Retention: openapi.StorageSnapshotRetentionV2Spec{Keep: 7},
		},
	}

	got := createStorageV2ForSnapshotPolicyTest(t, func(request *openapi.StorageV2Create) {
		request.Spec.SnapshotPolicies = &policies
	})

	require.Equal(t, ptr.To(true), got.Spec.DefaultSnapshotProtectionEnabled)
	require.Equal(t, &policies, got.Spec.SnapshotPolicies)
}

func TestCreateV2RejectsSystemDefaultPolicyWhenDefaultProtectionDisabled(t *testing.T) {
	t.Parallel()

	// system-default is reserved unconditionally, so a caller may not claim it even
	// when default protection is disabled.
	policies := openapi.StorageSnapshotPolicyListV2Spec{
		{
			Name: "system-default",
			Schedule: openapi.StorageSnapshotScheduleV2Spec{
				Interval: openapi.StorageSnapshotScheduleIntervalV2Hourly,
			},
			Retention: openapi.StorageSnapshotRetentionV2Spec{Keep: 24},
		},
	}

	_, err := createStorageV2ForSnapshotPolicyResult(t, func(request *openapi.StorageV2Create) {
		request.Spec.DefaultSnapshotProtectionEnabled = ptr.To(false)
		request.Spec.SnapshotPolicies = &policies
	})
	require.Error(t, err)
	require.True(t, servererrors.IsUnprocessableContent(err), "expected 422, got: %v", err)
}

func TestCreateV2EmptySnapshotPoliciesCreatesNoSnapshotPolicies(t *testing.T) {
	t.Parallel()

	policies := openapi.StorageSnapshotPolicyListV2Spec{}
	got := createStorageV2ForSnapshotPolicyTest(t, func(request *openapi.StorageV2Create) {
		request.Spec.SnapshotPolicies = &policies
	})

	require.NotNil(t, got.Spec.SnapshotPolicies)
	require.Empty(t, *got.Spec.SnapshotPolicies)

	require.NotNil(t, got.Status.SnapshotPolicies)
	require.Empty(t, got.Status.SnapshotPolicies)
}

func TestCreateV2NonEmptySnapshotPoliciesPersistsCallerSuppliedPolicies(t *testing.T) {
	t.Parallel()

	policies := openapi.StorageSnapshotPolicyListV2Spec{
		{
			Name: "hourly",
			Schedule: openapi.StorageSnapshotScheduleV2Spec{
				Interval: openapi.StorageSnapshotScheduleIntervalV2Hourly,
			},
			Retention: openapi.StorageSnapshotRetentionV2Spec{
				Keep: 24,
			},
		},
	}

	got := createStorageV2ForSnapshotPolicyTest(t, func(request *openapi.StorageV2Create) {
		request.Spec.SnapshotPolicies = &policies
	})

	require.NotNil(t, got.Spec.SnapshotPolicies)
	require.Equal(t, policies, *got.Spec.SnapshotPolicies)

	require.NotNil(t, got.Status.SnapshotPolicies)
	require.Equal(t, openapi.StorageSnapshotPolicyListV2Status{
		{
			Name:               "hourly",
			ProvisioningStatus: corev1.ResourceProvisioningStatusPending,
		},
	}, got.Status.SnapshotPolicies)
}

func TestUpdateOmittedSnapshotPoliciesPreservesExistingPolicies(t *testing.T) {
	t.Parallel()

	// A nil configure leaves snapshotPolicies omitted on the update request, which
	// must preserve the policies already stored on the seeded file storage.
	got := updateStorageV2ForSnapshotPolicyTest(t, nil)

	expectedPolicies := openapi.StorageSnapshotPolicyListV2Spec{
		{
			Name: "default",
			Schedule: openapi.StorageSnapshotScheduleV2Spec{
				Interval:  openapi.StorageSnapshotScheduleIntervalV2Daily,
				TimeOfDay: ptr.To("04:00Z"),
			},
			Retention: openapi.StorageSnapshotRetentionV2Spec{
				Keep: 7,
			},
		},
	}

	require.NotNil(t, got.Spec.SnapshotPolicies)
	require.Equal(t, expectedPolicies, *got.Spec.SnapshotPolicies)

	require.NotNil(t, got.Status.SnapshotPolicies)
	require.Equal(t, openapi.StorageSnapshotPolicyListV2Status{
		{
			Name:               "default",
			ProvisioningStatus: corev1.ResourceProvisioningStatusPending,
		},
	}, got.Status.SnapshotPolicies)
}

func TestUpdateEmptySnapshotPoliciesClearsExistingPolicies(t *testing.T) {
	t.Parallel()

	policies := openapi.StorageSnapshotPolicyListV2Spec{}
	got := updateStorageV2ForSnapshotPolicyTest(t, func(request *openapi.StorageV2Update) {
		request.Spec.SnapshotPolicies = &policies
	})

	require.NotNil(t, got.Spec.SnapshotPolicies)
	require.Empty(t, *got.Spec.SnapshotPolicies)

	require.NotNil(t, got.Status.SnapshotPolicies)
	require.Empty(t, got.Status.SnapshotPolicies)
}

func TestUpdateNonEmptySnapshotPoliciesReplacesExistingPolicies(t *testing.T) {
	t.Parallel()

	policies := openapi.StorageSnapshotPolicyListV2Spec{
		{
			Name: "hourly",
			Schedule: openapi.StorageSnapshotScheduleV2Spec{
				Interval: openapi.StorageSnapshotScheduleIntervalV2Hourly,
			},
			Retention: openapi.StorageSnapshotRetentionV2Spec{
				Keep: 24,
			},
		},
	}
	got := updateStorageV2ForSnapshotPolicyTest(t, func(request *openapi.StorageV2Update) {
		request.Spec.SnapshotPolicies = &policies
	})

	require.NotNil(t, got.Spec.SnapshotPolicies)
	require.Equal(t, policies, *got.Spec.SnapshotPolicies)

	require.NotNil(t, got.Status.SnapshotPolicies)
	require.Equal(t, openapi.StorageSnapshotPolicyListV2Status{
		{
			Name:               "hourly",
			ProvisioningStatus: corev1.ResourceProvisioningStatusPending,
		},
	}, got.Status.SnapshotPolicies)
}

func updateStorageV2ForSnapshotPolicyTest(t *testing.T, configure func(*openapi.StorageV2Update)) *openapi.StorageV2Read {
	t.Helper()

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	mockIdentity.EXPECT().
		PutApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDWithResponse(gomock.Any(), identityids.MustParseOrganizationID(testOrganizationID), identityids.MustParseProjectID(testProjectID), identityids.MustParseAllocationID(testAllocationID), gomock.Any()).
		Return(&identityopenapi.PutApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200: &identityopenapi.AllocationResponse{
				Metadata: corev1.ProjectScopedResourceReadMetadata{
					Id: testAllocationID,
				},
			},
		}, nil)

	k8sClient := newFakeClient(t,
		&regionv1.FileStorageClass{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "sc-1",
				Namespace: testNamespace,
				Labels: map[string]string{
					constants.RegionLabel: testRegionID,
				},
			},
		},
		&regionv1.FileStorage{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testFileStorageID,
				Namespace: testNamespace,
				Labels: map[string]string{
					constants.RegionLabel:                    testRegionID,
					coreconstants.NameLabel:                  "test-filestorage",
					coreconstants.OrganizationLabel:          testOrganizationID,
					coreconstants.ProjectLabel:               testProjectID,
					coreconstants.OrganizationPrincipalLabel: testOrganizationID,
					coreconstants.ProjectPrincipalLabel:      testProjectID,
				},
				Annotations: map[string]string{
					coreconstants.AllocationAnnotation:       testAllocationID,
					coreconstants.CreatorAnnotation:          "user-1",
					coreconstants.CreatorPrincipalAnnotation: "actor@example.com",
				},
			},
			Spec: regionv1.FileStorageSpec{
				Size:           *resource.NewQuantity(10*giB, resource.BinarySI),
				StorageClassID: "sc-1",
				NFS: &regionv1.NFS{
					RootSquash: true,
				},
				SnapshotPolicies: []regionv1.FileStorageSnapshotPolicy{
					{
						Name: "default",
						Schedule: regionv1.FileStorageSnapshotPolicySchedule{
							Interval:  regionv1.FileStorageSnapshotPolicyIntervalDaily,
							TimeOfDay: ptr.To("04:00Z"),
						},
						Retention: regionv1.FileStorageSnapshotPolicyRetention{
							Keep: 7,
						},
					},
				},
			},
		},
	)

	client := New(common.ClientArgs{
		Client:    k8sClient,
		Identity:  mockIdentity,
		Namespace: testNamespace,
	})
	ctx := identityauth.NewContext(t.Context(), &identityauth.Info{Userinfo: &identityopenapi.Userinfo{Sub: "user-1"}})
	ctx = principal.NewContext(ctx, &principal.Principal{Actor: "actor@example.com", OrganizationID: testOrganizationID, ProjectID: testProjectID})
	ctx = rbac.NewContext(ctx, &identityopenapi.Acl{
		Global: &identityopenapi.AclEndpoints{
			{
				Name:       "region:filestorage:v2",
				Operations: identityopenapi.AclOperations{identityopenapi.Read, identityopenapi.Update},
			},
		},
	})

	request := &openapi.StorageV2Update{
		Metadata: corev1.ResourceWriteMetadata{Name: "test-filestorage"},
		Spec: openapi.StorageV2Spec{
			SizeGiB: 10,
		},
	}

	if configure != nil {
		configure(request)
	}

	got, err := client.Update(ctx, regionids.MustParseFileStorageID(testFileStorageID), request)
	require.NoError(t, err)

	return got
}

func createStorageV2ForSnapshotPolicyTest(t *testing.T, configure func(*openapi.StorageV2Create)) *openapi.StorageV2Read {
	t.Helper()

	got, err := createStorageV2ForSnapshotPolicyResult(t, configure)
	require.NoError(t, err)

	return got
}

func createStorageV2ForSnapshotPolicyResult(t *testing.T, configure func(*openapi.StorageV2Create)) (*openapi.StorageV2Read, error) {
	t.Helper()

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	mockIdentity.EXPECT().
		PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsWithResponse(gomock.Any(), identityids.MustParseOrganizationID(testOrganizationID), identityids.MustParseProjectID(testProjectID), gomock.Any()).
		Return(&identityopenapi.PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusCreated},
			JSON201: &identityopenapi.AllocationResponse{
				Metadata: corev1.ProjectScopedResourceReadMetadata{
					Id: testAllocationID,
				},
			},
		}, nil).
		AnyTimes()

	_, prefix, err := net.ParseCIDR("10.0.0.0/24")
	require.NoError(t, err)

	network := newTestNetwork()
	network.Labels[constants.RegionLabel] = testRegionID
	network.Labels[coreconstants.OrganizationLabel] = testOrganizationID
	network.Labels[coreconstants.ProjectLabel] = testProjectID
	network.Spec.Prefix = &v1alpha1.IPv4Prefix{IPNet: *prefix}
	network.Status.Conditions = []v1alpha1.Condition{
		{
			Type:   v1alpha1.ConditionAvailable,
			Status: k8sv1.ConditionTrue,
			Reason: v1alpha1.ConditionReasonProvisioned,
		},
	}

	k8sClient := newFakeClient(t,
		&regionv1.Region{ObjectMeta: metav1.ObjectMeta{Name: testRegionID, Namespace: testNamespace}},
		&regionv1.FileStorageClass{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "sc-1",
				Namespace: testNamespace,
				Labels: map[string]string{
					constants.RegionLabel: testRegionID,
				},
			},
		},
		network,
	)

	client := New(common.ClientArgs{
		Client:    k8sClient,
		Identity:  mockIdentity,
		Namespace: testNamespace,
	})

	ctx := identityauth.NewContext(t.Context(), &identityauth.Info{Userinfo: &identityopenapi.Userinfo{Sub: "user-1"}})
	ctx = principal.NewContext(ctx, &principal.Principal{Actor: "actor@example.com", OrganizationID: testOrganizationID, ProjectID: testProjectID})
	ctx = rbac.NewContext(ctx, &identityopenapi.Acl{
		Global: &identityopenapi.AclEndpoints{
			{
				Name:       "region:filestorage:v2",
				Operations: identityopenapi.AclOperations{identityopenapi.Create},
			},
			{
				Name:       "region:networks:v2",
				Operations: identityopenapi.AclOperations{identityopenapi.Read},
			},
		},
	})

	request := &openapi.StorageV2Create{
		Metadata: corev1.ResourceWriteMetadata{Name: "test-filestorage"},
	}
	request.Spec.OrganizationId = testOrganizationID
	request.Spec.ProjectId = testProjectID
	request.Spec.RegionId = regionids.MustParseRegionID(testRegionID)
	request.Spec.StorageClassId = "sc-1"
	request.Spec.SizeGiB = 10
	request.Spec.Attachments = &openapi.StorageAttachmentV2Spec{NetworkIds: openapi.NetworkIDList{testNetworkID}}

	if configure != nil {
		configure(request)
	}

	return client.CreateV2(ctx, request)
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

	network := newTestNetwork()

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
						constants.RegionLabel:                    testRegionID,
						coreconstants.NameLabel:                  "test-filestorage",
						coreconstants.OrganizationLabel:          testOrganizationID,
						coreconstants.ProjectLabel:               testProjectID,
						coreconstants.OrganizationPrincipalLabel: testOrganizationID,
						coreconstants.ProjectPrincipalLabel:      testProjectID,
					},
					Annotations: map[string]string{
						coreconstants.CreatorAnnotation:          "user-1",
						coreconstants.CreatorPrincipalAnnotation: "actor@example.com",
					},
				},
				Spec: regionv1.FileStorageSpec{
					DefaultSnapshotProtectionEnabled: true,
					Size:                             *resource.NewQuantity(10*giB, resource.BinarySI),
					StorageClassID:                   "sc-1",
					Attachments: []regionv1.Attachment{
						{
							NetworkID:      testNetworkID,
							SegmentationID: ptr.To(1111),
							IPRange:        narrowedRange,
						}},
					// Default protection is enabled, so the hidden baseline is
					// materialized into the stored spec.
					SnapshotPolicies: []regionv1.FileStorageSnapshotPolicy{
						{
							Name: "system-default",
							Schedule: regionv1.FileStorageSnapshotPolicySchedule{
								Interval:  regionv1.FileStorageSnapshotPolicyIntervalDaily,
								TimeOfDay: ptr.To("04:00Z"),
							},
							Retention: regionv1.FileStorageSnapshotPolicyRetention{Keep: 7},
						},
					},
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

			got, err := client.generateV2(ctx, tt.input.organizationID, tt.input.projectID, tt.input.regionID, tt.input.request, tt.input.storageClass)

			require.NoError(t, err)
			require.NotNil(t, got)

			// Name is dynamically generated; just assert it's present, then ignore it.
			require.NotEmpty(t, got.Name)
			got.Name = ""

			require.Equal(t, tt.want, got)
		})
	}
}

func TestGenerateV2RoundTripsInlineHourlySnapshotPolicy(t *testing.T) {
	t.Parallel()

	policyList := openapi.StorageSnapshotPolicyListV2Spec{
		{
			Name: "hourly",
			Schedule: openapi.StorageSnapshotScheduleV2Spec{
				Interval: openapi.StorageSnapshotScheduleIntervalV2Hourly,
			},
			Retention: openapi.StorageSnapshotRetentionV2Spec{
				Keep: 24,
			},
		},
	}

	input := (&generateV2InputBuilder{}).Default().WithSnapshotPolicies(policyList).Run()
	client, ctx := newClientAndContext(t, newFakeClient(t, newTestNetwork()), &identityauth.Info{Userinfo: &identityopenapi.Userinfo{Sub: "user-1"}}, &principal.Principal{Actor: "actor@example.com"})

	generated, err := client.generateV2(ctx, input.organizationID, input.projectID, input.regionID, input.request, input.storageClass)
	require.NoError(t, err)

	// Default protection is enabled, so the stored spec is the caller policy
	// followed by the hidden baseline; the public read hides it.
	require.Equal(t, []regionv1.FileStorageSnapshotPolicy{
		{
			Name: "hourly",
			Schedule: regionv1.FileStorageSnapshotPolicySchedule{
				Interval: regionv1.FileStorageSnapshotPolicyIntervalHourly,
			},
			Retention: regionv1.FileStorageSnapshotPolicyRetention{
				Keep: 24,
			},
		},
		{
			Name: "system-default",
			Schedule: regionv1.FileStorageSnapshotPolicySchedule{
				Interval:  regionv1.FileStorageSnapshotPolicyIntervalDaily,
				TimeOfDay: ptr.To("04:00Z"),
			},
			Retention: regionv1.FileStorageSnapshotPolicyRetention{Keep: 7},
		},
	}, generated.Spec.SnapshotPolicies)

	read := convertV2(generated)
	require.NotNil(t, read.Spec.SnapshotPolicies)
	require.Equal(t, policyList, *read.Spec.SnapshotPolicies)
}

func TestGenerateV2EnabledDefaultProtectionMaterializesHiddenBaselineAndReadsEmpty(t *testing.T) {
	t.Parallel()

	// With default protection resolved to enabled upstream, generateV2 must
	// materialize the hidden system-default baseline into the stored spec for the
	// controller to reconcile, yet hide it from public reads.
	input := (&generateV2InputBuilder{}).Default().Run()
	input.request.Spec.DefaultSnapshotProtectionEnabled = true
	client, ctx := newClientAndContext(t, newFakeClient(t, newTestNetwork()), &identityauth.Info{Userinfo: &identityopenapi.Userinfo{Sub: "user-1"}}, &principal.Principal{Actor: "actor@example.com"})

	generated, err := client.generateV2(ctx, input.organizationID, input.projectID, input.regionID, input.request, input.storageClass)
	require.NoError(t, err)
	require.True(t, generated.Spec.DefaultSnapshotProtectionEnabled)
	require.Equal(t, []regionv1.FileStorageSnapshotPolicy{
		{
			Name: "system-default",
			Schedule: regionv1.FileStorageSnapshotPolicySchedule{
				Interval:  regionv1.FileStorageSnapshotPolicyIntervalDaily,
				TimeOfDay: ptr.To("04:00Z"),
			},
			Retention: regionv1.FileStorageSnapshotPolicyRetention{Keep: 7},
		},
	}, generated.Spec.SnapshotPolicies)

	read := convertV2(generated)
	require.NotNil(t, read.Spec.SnapshotPolicies)
	require.Empty(t, *read.Spec.SnapshotPolicies)
	require.NotNil(t, read.Status.SnapshotPolicies)
	require.Empty(t, read.Status.SnapshotPolicies)
}

func TestGenerateV2DisabledDefaultProtectionStoresNoPoliciesAndReadsEmpty(t *testing.T) {
	t.Parallel()

	input := (&generateV2InputBuilder{}).Default().Run()
	input.request.Spec.DefaultSnapshotProtectionEnabled = false
	client, ctx := newClientAndContext(t, newFakeClient(t, newTestNetwork()), &identityauth.Info{Userinfo: &identityopenapi.Userinfo{Sub: "user-1"}}, &principal.Principal{Actor: "actor@example.com"})

	generated, err := client.generateV2(ctx, input.organizationID, input.projectID, input.regionID, input.request, input.storageClass)
	require.NoError(t, err)
	require.False(t, generated.Spec.DefaultSnapshotProtectionEnabled)
	require.Nil(t, generated.Spec.SnapshotPolicies)

	read := convertV2(generated)
	require.NotNil(t, read.Spec.SnapshotPolicies)
	require.Empty(t, *read.Spec.SnapshotPolicies)
	require.NotNil(t, read.Status.SnapshotPolicies)
	require.Empty(t, read.Status.SnapshotPolicies)
}

func TestGetRoundTripsStoredSnapshotPolicies(t *testing.T) {
	t.Parallel()

	storage := &regionv1.FileStorage{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testFileStorageID,
			Labels: map[string]string{
				constants.RegionLabel:                    testRegionID,
				coreconstants.NameLabel:                  "test-filestorage",
				coreconstants.OrganizationLabel:          testOrganizationID,
				coreconstants.ProjectLabel:               testProjectID,
				coreconstants.OrganizationPrincipalLabel: testOrganizationID,
				coreconstants.ProjectPrincipalLabel:      testProjectID,
			},
		},
		Spec: regionv1.FileStorageSpec{
			Size:           *resource.NewQuantity(1*giB, resource.BinarySI),
			StorageClassID: "sc-1",
			NFS: &regionv1.NFS{
				RootSquash: true,
			},
			SnapshotPolicies: []regionv1.FileStorageSnapshotPolicy{
				{
					Name: "hourly",
					Schedule: regionv1.FileStorageSnapshotPolicySchedule{
						Interval: regionv1.FileStorageSnapshotPolicyIntervalHourly,
					},
					Retention: regionv1.FileStorageSnapshotPolicyRetention{
						Keep: 24,
					},
				},
			},
		},
	}

	c, ctx := newClientwithObjectandContext(t, t.Context(), append(defaultFSK8sObjects(), storage)...)

	result, err := c.Get(ctx, regionids.MustParseFileStorageID(storage.Name))
	require.NoError(t, err)
	require.Equal(t, &openapi.StorageSnapshotPolicyListV2Spec{
		{
			Name: "hourly",
			Schedule: openapi.StorageSnapshotScheduleV2Spec{
				Interval: openapi.StorageSnapshotScheduleIntervalV2Hourly,
			},
			Retention: openapi.StorageSnapshotRetentionV2Spec{
				Keep: 24,
			},
		},
	}, result.Spec.SnapshotPolicies)
	require.Equal(t, openapi.StorageSnapshotPolicyListV2Status{
		{
			Name:               "hourly",
			ProvisioningStatus: corev1.ResourceProvisioningStatusPending,
		},
	}, result.Status.SnapshotPolicies)
}

func TestListV2ExposesDefaultSnapshotProtectionEnabled(t *testing.T) {
	t.Parallel()

	enabledStorage := &regionv1.FileStorage{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testFileStorageID,
			Labels: map[string]string{
				constants.RegionLabel:           testRegionID,
				coreconstants.NameLabel:         "enabled-filestorage",
				coreconstants.OrganizationLabel: testOrganizationID,
				coreconstants.ProjectLabel:      testProjectID,
			},
		},
		Spec: regionv1.FileStorageSpec{
			DefaultSnapshotProtectionEnabled: true,
			Size:                             *resource.NewQuantity(1*giB, resource.BinarySI),
			StorageClassID:                   "sc-1",
			NFS:                              &regionv1.NFS{RootSquash: true},
		},
	}

	disabledStorage := &regionv1.FileStorage{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      "55555555-5555-4555-a555-555555555555",
			Labels: map[string]string{
				constants.RegionLabel:           testRegionID,
				coreconstants.NameLabel:         "disabled-filestorage",
				coreconstants.OrganizationLabel: testOrganizationID,
				coreconstants.ProjectLabel:      testProjectID,
			},
		},
		Spec: regionv1.FileStorageSpec{
			DefaultSnapshotProtectionEnabled: false,
			Size:                             *resource.NewQuantity(1*giB, resource.BinarySI),
			StorageClassID:                   "sc-1",
			NFS:                              &regionv1.NFS{RootSquash: true},
		},
	}

	c, ctx := newClientwithObjectandContext(t, t.Context(), append(defaultFSK8sObjects(), enabledStorage, disabledStorage)...)
	organizationIDs := openapi.OrganizationIDQueryParameter{testOrganizationID}
	projectIDs := openapi.ProjectIDQueryParameter{testProjectID}
	regionIDs := openapi.RegionIDQueryParameter{testRegionID}

	result, err := c.ListV2(ctx, openapi.GetApiV2FilestorageParams{
		OrganizationID: &organizationIDs,
		ProjectID:      &projectIDs,
		RegionID:       &regionIDs,
	})
	require.NoError(t, err)
	require.Len(t, result, 2)

	defaultProtectionByID := map[string]bool{}
	for _, storage := range result {
		defaultProtectionByID[storage.Metadata.Id] = ptr.Deref(storage.Spec.DefaultSnapshotProtectionEnabled, false)
	}

	require.True(t, defaultProtectionByID[testFileStorageID])
	require.False(t, defaultProtectionByID[disabledStorage.Name])
}

func TestGetHidesSystemDefaultSnapshotProtectionPolicy(t *testing.T) {
	t.Parallel()

	storage := &regionv1.FileStorage{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testFileStorageID,
			Labels: map[string]string{
				constants.RegionLabel:           testRegionID,
				coreconstants.NameLabel:         "test-filestorage",
				coreconstants.OrganizationLabel: testOrganizationID,
				coreconstants.ProjectLabel:      testProjectID,
			},
		},
		Spec: regionv1.FileStorageSpec{
			DefaultSnapshotProtectionEnabled: true,
			Size:                             *resource.NewQuantity(1*giB, resource.BinarySI),
			StorageClassID:                   "sc-1",
			NFS:                              &regionv1.NFS{RootSquash: true},
			SnapshotPolicies: []regionv1.FileStorageSnapshotPolicy{
				{
					Name: "system-default",
					Schedule: regionv1.FileStorageSnapshotPolicySchedule{
						Interval: regionv1.FileStorageSnapshotPolicyIntervalHourly,
					},
					Retention: regionv1.FileStorageSnapshotPolicyRetention{Keep: 24},
				},
				{
					Name: "hourly",
					Schedule: regionv1.FileStorageSnapshotPolicySchedule{
						Interval: regionv1.FileStorageSnapshotPolicyIntervalHourly,
					},
					Retention: regionv1.FileStorageSnapshotPolicyRetention{Keep: 24},
				},
			},
		},
		Status: regionv1.FileStorageStatus{
			SnapshotPolicies: []regionv1.FileStorageSnapshotPolicyStatus{
				{Name: "system-default"},
				{Name: "hourly"},
			},
		},
	}

	c, ctx := newClientwithObjectandContext(t, t.Context(), append(defaultFSK8sObjects(), storage)...)

	result, err := c.Get(ctx, regionids.MustParseFileStorageID(storage.Name))
	require.NoError(t, err)
	require.Equal(t, ptr.To(true), result.Spec.DefaultSnapshotProtectionEnabled)
	require.Equal(t, &openapi.StorageSnapshotPolicyListV2Spec{
		{
			Name: "hourly",
			Schedule: openapi.StorageSnapshotScheduleV2Spec{
				Interval: openapi.StorageSnapshotScheduleIntervalV2Hourly,
			},
			Retention: openapi.StorageSnapshotRetentionV2Spec{Keep: 24},
		},
	}, result.Spec.SnapshotPolicies)
	require.Equal(t, openapi.StorageSnapshotPolicyListV2Status{
		{
			Name:               "hourly",
			ProvisioningStatus: corev1.ResourceProvisioningStatusPending,
		},
	}, result.Status.SnapshotPolicies)
}

func TestUpdateSagaGenerateSnapshotPolicySemantics(t *testing.T) {
	t.Parallel()

	currentPolicies := []regionv1.FileStorageSnapshotPolicy{
		{
			Name: "daily",
			Schedule: regionv1.FileStorageSnapshotPolicySchedule{
				Interval:  regionv1.FileStorageSnapshotPolicyIntervalDaily,
				TimeOfDay: ptr.To("02:30Z"),
			},
			Retention: regionv1.FileStorageSnapshotPolicyRetention{
				Keep: 7,
			},
		},
	}

	for _, tt := range []struct {
		name                  string
		requestSnapshotPolicy *openapi.StorageSnapshotPolicyListV2Spec
		wantSnapshotPolicies  []regionv1.FileStorageSnapshotPolicy
	}{
		{
			name:                 "omitted snapshotPolicies preserves existing policies",
			wantSnapshotPolicies: currentPolicies,
		},
		{
			name:                  "empty snapshotPolicies clears existing policies",
			requestSnapshotPolicy: &openapi.StorageSnapshotPolicyListV2Spec{},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			input := newDefaultGenerateV2Input()
			request := &openapi.StorageV2Update{
				Metadata: corev1.ResourceWriteMetadata{Name: "test-filestorage"},
				Spec: openapi.StorageV2Spec{
					SizeGiB:          input.request.Spec.SizeGiB,
					SnapshotPolicies: tt.requestSnapshotPolicy,
				},
			}

			current := &regionv1.FileStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testFileStorageID,
					Namespace: testNamespace,
					Labels: map[string]string{
						coreconstants.OrganizationLabel: testOrganizationID,
						coreconstants.ProjectLabel:      testProjectID,
						constants.RegionLabel:           testRegionID,
					},
				},
				Spec: regionv1.FileStorageSpec{
					SnapshotPolicies: currentPolicies,
				},
			}

			client, ctx := newClientAndContext(t, newFakeClient(t), &identityauth.Info{Userinfo: &identityopenapi.Userinfo{Sub: "user-1"}}, &principal.Principal{Actor: "actor@example.com"})
			saga := newUpdateSaga(client, current, request, input.storageClass)

			require.NoError(t, saga.generate(ctx))
			require.Equal(t, tt.wantSnapshotPolicies, saga.updated.Spec.SnapshotPolicies)
		})
	}
}

func TestUpdateSagaDisablingDefaultProtectionPreservesOnlyUserManagedPolicies(t *testing.T) {
	t.Parallel()

	input := newDefaultGenerateV2Input()
	request := &openapi.StorageV2Update{
		Metadata: corev1.ResourceWriteMetadata{Name: "test-filestorage"},
		Spec: openapi.StorageV2Spec{
			DefaultSnapshotProtectionEnabled: ptr.To(false),
			SizeGiB:                          input.request.Spec.SizeGiB,
		},
	}

	current := &regionv1.FileStorage{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testFileStorageID,
			Namespace: testNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel: testOrganizationID,
				coreconstants.ProjectLabel:      testProjectID,
				constants.RegionLabel:           testRegionID,
			},
		},
		Spec: regionv1.FileStorageSpec{
			DefaultSnapshotProtectionEnabled: true,
			SnapshotPolicies: []regionv1.FileStorageSnapshotPolicy{
				{
					Name: "system-default",
					Schedule: regionv1.FileStorageSnapshotPolicySchedule{
						Interval: regionv1.FileStorageSnapshotPolicyIntervalHourly,
					},
					Retention: regionv1.FileStorageSnapshotPolicyRetention{Keep: 24},
				},
				{
					Name: "hourly",
					Schedule: regionv1.FileStorageSnapshotPolicySchedule{
						Interval: regionv1.FileStorageSnapshotPolicyIntervalHourly,
					},
					Retention: regionv1.FileStorageSnapshotPolicyRetention{Keep: 24},
				},
			},
		},
	}

	client, ctx := newClientAndContext(t, newFakeClient(t), &identityauth.Info{Userinfo: &identityopenapi.Userinfo{Sub: "user-1"}}, &principal.Principal{Actor: "actor@example.com"})
	saga := newUpdateSaga(client, current, request, input.storageClass)

	require.NoError(t, saga.generate(ctx))
	require.False(t, saga.updated.Spec.DefaultSnapshotProtectionEnabled)
	require.Equal(t, []regionv1.FileStorageSnapshotPolicy{
		{
			Name: "hourly",
			Schedule: regionv1.FileStorageSnapshotPolicySchedule{
				Interval: regionv1.FileStorageSnapshotPolicyIntervalHourly,
			},
			Retention: regionv1.FileStorageSnapshotPolicyRetention{Keep: 24},
		},
	}, saga.updated.Spec.SnapshotPolicies)
}

// system-default is reserved unconditionally, so an update that claims it as a
// user-managed policy name is rejected regardless of default protection state.
func TestUpdateSagaRejectsReservedSystemDefaultPolicyName(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name              string
		protectionEnabled bool
	}{
		{name: "protection enabled", protectionEnabled: true},
		{name: "protection disabled", protectionEnabled: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			input := newDefaultGenerateV2Input()
			policies := openapi.StorageSnapshotPolicyListV2Spec{
				{
					Name: "system-default",
					Schedule: openapi.StorageSnapshotScheduleV2Spec{
						Interval: openapi.StorageSnapshotScheduleIntervalV2Hourly,
					},
					Retention: openapi.StorageSnapshotRetentionV2Spec{Keep: 24},
				},
			}
			request := &openapi.StorageV2Update{
				Metadata: corev1.ResourceWriteMetadata{Name: "test-filestorage"},
				Spec: openapi.StorageV2Spec{
					DefaultSnapshotProtectionEnabled: ptr.To(tt.protectionEnabled),
					SizeGiB:                          input.request.Spec.SizeGiB,
					SnapshotPolicies:                 &policies,
				},
			}

			current := &regionv1.FileStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testFileStorageID,
					Namespace: testNamespace,
					Labels: map[string]string{
						coreconstants.OrganizationLabel: testOrganizationID,
						coreconstants.ProjectLabel:      testProjectID,
						constants.RegionLabel:           testRegionID,
					},
				},
				Spec: regionv1.FileStorageSpec{
					DefaultSnapshotProtectionEnabled: tt.protectionEnabled,
				},
			}

			client, ctx := newClientAndContext(t, newFakeClient(t), &identityauth.Info{Userinfo: &identityopenapi.Userinfo{Sub: "user-1"}}, &principal.Principal{Actor: "actor@example.com"})
			saga := newUpdateSaga(client, current, request, input.storageClass)

			err := saga.validateRequest(ctx)
			require.Error(t, err)
			require.True(t, servererrors.IsUnprocessableContent(err), "expected 422, got: %v", err)
		})
	}
}

func TestGetProjectsSnapshotPolicyStatusOnParentRead(t *testing.T) {
	t.Parallel()

	storage := &regionv1.FileStorage{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testFileStorageID,
			Labels: map[string]string{
				constants.RegionLabel:                    testRegionID,
				coreconstants.NameLabel:                  "test-filestorage",
				coreconstants.OrganizationLabel:          testOrganizationID,
				coreconstants.ProjectLabel:               testProjectID,
				coreconstants.OrganizationPrincipalLabel: testOrganizationID,
				coreconstants.ProjectPrincipalLabel:      testProjectID,
			},
		},
		Spec: regionv1.FileStorageSpec{
			Size:           *resource.NewQuantity(1*giB, resource.BinarySI),
			StorageClassID: "sc-1",
			NFS: &regionv1.NFS{
				RootSquash: true,
			},
			SnapshotPolicies: []regionv1.FileStorageSnapshotPolicy{
				{
					Name: "hourly",
					Schedule: regionv1.FileStorageSnapshotPolicySchedule{
						Interval: regionv1.FileStorageSnapshotPolicyIntervalHourly,
					},
					Retention: regionv1.FileStorageSnapshotPolicyRetention{
						Keep: 24,
					},
				},
				{
					Name: "daily",
					Schedule: regionv1.FileStorageSnapshotPolicySchedule{
						Interval:  regionv1.FileStorageSnapshotPolicyIntervalDaily,
						TimeOfDay: ptr.To("02:30Z"),
					},
					Retention: regionv1.FileStorageSnapshotPolicyRetention{
						Keep: 7,
					},
				},
			},
		},
		Status: regionv1.FileStorageStatus{
			SnapshotPolicies: []regionv1.FileStorageSnapshotPolicyStatus{
				{
					Name: "stale",
				},
				{
					Name: "daily",
					Conditions: []v1alpha1.Condition{
						{
							Type:               v1alpha1.ConditionAvailable,
							Status:             k8sv1.ConditionTrue,
							LastTransitionTime: metav1.Now(),
							Reason:             v1alpha1.ConditionReasonProvisioned,
							Message:            "snapshot policy is active",
						},
					},
				},
			},
		},
	}

	c, ctx := newClientwithObjectandContext(t, t.Context(), append(defaultFSK8sObjects(), storage)...)

	result, err := c.Get(ctx, regionids.MustParseFileStorageID(storage.Name))
	require.NoError(t, err)
	require.Equal(t, openapi.StorageSnapshotPolicyListV2Status{
		{
			Name:               "hourly",
			ProvisioningStatus: corev1.ResourceProvisioningStatusPending,
		},
		{
			Name:               "daily",
			ProvisioningStatus: corev1.ResourceProvisioningStatusProvisioned,
			Message:            ptr.To("snapshot policy is active"),
		},
	}, result.Status.SnapshotPolicies)
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
					Name:      "55555555-5555-4555-a555-555555555555",
					Labels: map[string]string{
						constants.RegionLabel:                    testRegionID,
						coreconstants.NameLabel:                  "test-filestorage",
						coreconstants.OrganizationLabel:          testOrganizationID,
						coreconstants.ProjectLabel:               testProjectID,
						coreconstants.OrganizationPrincipalLabel: testOrganizationID,
						coreconstants.ProjectPrincipalLabel:      testProjectID,
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
						{NetworkID: testNetworkID},
					},
					NFS: &regionv1.NFS{
						RootSquash: true,
					},
				},
			},
			expected: &openapi.StorageV2Read{
				Metadata: corev1.ProjectScopedResourceReadMetadata{
					ProjectId: "22222222-2222-4222-a222-222222222222",
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

			result, err := c.Get(ctx, regionids.MustParseFileStorageID(tt.input.Name))
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

			got, err := c.generateV2(ctx, tt.input.organizationID, tt.input.projectID, tt.input.regionID, tt.input.request, tt.input.storageClass)

			require.Nil(t, got)
			require.Error(t, err)
		})
	}
}

type generateV2Input struct {
	organizationID identityids.OrganizationID
	projectID      identityids.ProjectID
	regionID       string
	storageClass   *openapi.StorageClassV2Read
	request        *storageV2GenerateRequest
}

type generateV2InputBuilder struct {
	input *generateV2Input
}

func newDefaultGenerateV2Input() *generateV2Input {
	return &generateV2Input{
		organizationID: identityids.MustParseOrganizationID("11111111-1111-4111-a111-111111111111"),
		projectID:      identityids.MustParseProjectID("22222222-2222-4222-a222-222222222222"),
		regionID:       testRegionID,
		storageClass: &openapi.StorageClassV2Read{
			Metadata: corev1.ResourceReadMetadata{
				Id:                 "sc-1",
				Name:               "sc-1",
				HealthStatus:       corev1.ResourceHealthStatusHealthy,
				ProvisioningStatus: corev1.ResourceProvisioningStatusProvisioned,
			},
			Spec: openapi.StorageClassV2Spec{
				Parallelism: DefaultParallelism,
			},
		},
		request: &storageV2GenerateRequest{
			Metadata: corev1.ResourceWriteMetadata{
				Name: "test-filestorage",
			},
			Spec: storageV2GenerateSpec{
				// generateV2 receives an already-resolved request; the create path
				// resolves an omitted flag to enabled, so that is the default here.
				DefaultSnapshotProtectionEnabled: true,
				SizeGiB:                          10,
				Attachments:                      &openapi.StorageAttachmentV2Spec{NetworkIds: openapi.NetworkIDList{testNetworkID}},
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

func (b *generateV2InputBuilder) WithSnapshotPolicies(policies openapi.StorageSnapshotPolicyListV2Spec) *generateV2InputBuilder {
	if b.input == nil {
		b.input = newDefaultGenerateV2Input()
	}

	b.input.request.Spec.SnapshotPolicies = &policies

	return b
}

func (b *generateV2InputBuilder) Run() *generateV2Input {
	return b.input
}

func newClientAndContext(t *testing.T, c client.Client, auth *identityauth.Info, principalInfo *principal.Principal) (*Client, context.Context) {
	t.Helper()

	clientArgs := common.ClientArgs{
		Client:    c,
		Namespace: testNamespace,
	}

	client := New(clientArgs)
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
		ClientArgs: common.ClientArgs{
			Client:    k8sClient,
			Namespace: testNamespace,
		},
	}

	oapiacl := &identityopenapi.Acl{Global: &identityopenapi.AclEndpoints{
		identityopenapi.AclEndpoint{
			Name: "region:filestorage:v2",
			Operations: identityopenapi.AclOperations{
				identityopenapi.Read, identityopenapi.Create, identityopenapi.Update, identityopenapi.Delete,
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
