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
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	corev1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/file-storage/provisioners/types/mock"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	testNamespace = "test-ns"
	testProjectID = "test-project"
	testFSName    = "test-fs"
)

// newFakeClient creates a fake k8s client with the region scheme.
func newFakeClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, regionv1.AddToScheme(scheme))

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

// newTestProvisioner creates a provisioner with the given FileStorage.
func newTestProvisioner(fs *regionv1.FileStorage) *Provisioner {
	return &Provisioner{
		fileStorage: fs,
	}
}

// fileStorageFixture creates a FileStorage with the given attachments.
func fileStorageFixture(attachments []regionv1.Attachment) *regionv1.FileStorage {
	return &regionv1.FileStorage{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testFSName,
			Namespace: testNamespace,
			Labels: map[string]string{
				coreconstants.ProjectLabel: testProjectID,
			},
		},
		Spec: regionv1.FileStorageSpec{
			Attachments: attachments,
		},
	}
}

// networkFixture creates a Network with the given name and prefix.
func networkFixture(name string) *regionv1.Network {
	return &regionv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: regionv1.NetworkSpec{
			Prefix: &corev1.IPv4Prefix{
				IPNet: net.IPNet{
					IP:   net.IP{10, 0, 0, 0},
					Mask: net.IPMask{255, 255, 255, 0},
				},
			},
			DNSNameservers: []corev1.IPv4Address{},
		},
	}
}

// attachmentFixture creates an Attachment with the given network ID and VLAN.
func attachmentFixture(networkID string, vlan int) regionv1.Attachment {
	return regionv1.Attachment{
		NetworkID:      networkID,
		SegmentationID: ptr.To(vlan),
		IPRange: &regionv1.AttachmentIPRange{
			Start: corev1.IPv4Address{IP: net.IP{10, 0, 0, 100}},
			End:   corev1.IPv4Address{IP: net.IP{10, 0, 0, 110}},
		},
	}
}

// TestAttachMissingNetworks_AlreadyAttached tests that when a network is already attached (exists in currentSet),
// the function skips the attachment call and sets the status to Provisioned.
func TestAttachMissingNetworks_AlreadyAttached(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	ctx := log.IntoContext(t.Context(), log.Log)

	// Setup: network VLAN 100 already attached (in currentSet)
	attachment := attachmentFixture("network-1", 100)
	fs := fileStorageFixture([]regionv1.Attachment{attachment})
	network := networkFixture("network-1")

	cli := newFakeClient(t, network)
	driver := mock.NewMockDriver(ctrl)
	provisioner := newTestProvisioner(fs)

	desiredSet := map[int]regionv1.Attachment{
		100: attachment,
	}
	currentSet := map[int]struct{}{
		100: {}, // already attached
	}

	// No driver calls expected - network is already attached
	err := provisioner.attachMissingNetworks(ctx, cli, driver, desiredSet, currentSet, "test-ref")

	require.NoError(t, err)
	// Verify status was set to Provisioned
	require.Len(t, fs.Status.Attachments, 1)
	require.Equal(t, "network-1", fs.Status.Attachments[0].NetworkID)
	require.Equal(t, regionv1.AttachmentProvisioned, fs.Status.Attachments[0].ProvisioningStatus)
}

// TestAttachMissingNetworks_NewAttachment tests that when a network is not yet attached (not in currentSet),
// the function fetches the Network resource, calls driver.AttachNetwork with the network prefix, and sets the status to Provisioned.
func TestAttachMissingNetworks_NewAttachment(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	ctx := log.IntoContext(t.Context(), log.Log)

	// Setup: network VLAN 100 not yet attached (not in currentSet)
	attachment := attachmentFixture("network-1", 100)
	fs := fileStorageFixture([]regionv1.Attachment{attachment})
	network := networkFixture("network-1")

	cli := newFakeClient(t, network)
	driver := mock.NewMockDriver(ctrl)
	provisioner := newTestProvisioner(fs)

	desiredSet := map[int]regionv1.Attachment{
		100: attachment,
	}
	currentSet := map[int]struct{}{} // empty - nothing attached yet

	// Expect AttachNetwork to be called
	driver.EXPECT().
		AttachNetwork(gomock.Any(), testProjectID, testFSName, gomock.Any(), network.Spec.Prefix).
		Return(nil)

	err := provisioner.attachMissingNetworks(ctx, cli, driver, desiredSet, currentSet, "test-ref")

	require.NoError(t, err)
	// Verify status was set to Provisioned
	require.Len(t, fs.Status.Attachments, 1)
	require.Equal(t, "network-1", fs.Status.Attachments[0].NetworkID)
	require.Equal(t, regionv1.AttachmentProvisioned, fs.Status.Attachments[0].ProvisioningStatus)
}

// TestDetachStaleNetworks_StillDesired tests that when a network is still in the desired set,
// the function skips detachment and makes no driver calls.
func TestDetachStaleNetworks_StillDesired(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	ctx := log.IntoContext(t.Context(), log.Log)

	// Setup: network VLAN 100 is in both desired and current sets
	attachment := attachmentFixture("network-1", 100)
	fs := fileStorageFixture([]regionv1.Attachment{attachment})

	cli := newFakeClient(t)
	driver := mock.NewMockDriver(ctrl)
	provisioner := newTestProvisioner(fs)

	desiredSet := map[int]regionv1.Attachment{
		100: attachment, // still desired
	}
	currentSet := map[int]struct{}{
		100: {}, // currently attached
	}

	// No driver calls expected - network is still desired
	err := provisioner.detachStaleNetworks(ctx, cli, driver, desiredSet, currentSet, "test-ref")

	require.NoError(t, err)
}

// TestDetachStaleNetworks_NoLongerDesired tests that when a network is attached but no longer in the desired set,
// the function calls driver.DetachNetwork and removes the attachment status.
func TestDetachStaleNetworks_NoLongerDesired(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	ctx := log.IntoContext(t.Context(), log.Log)

	// Setup: network VLAN 100 is attached but no longer desired
	fs := fileStorageFixture(nil) // no attachments desired
	fs.Status.Attachments = []regionv1.FileStorageAttachmentStatus{
		{NetworkID: "network-1", SegmentationID: ptr.To(100), ProvisioningStatus: regionv1.AttachmentProvisioned},
	}

	cli := newFakeClient(t)
	driver := mock.NewMockDriver(ctrl)
	provisioner := newTestProvisioner(fs)

	desiredSet := map[int]regionv1.Attachment{} // nothing desired
	currentSet := map[int]struct{}{
		100: {}, // currently attached
	}

	// Expect DetachNetwork to be called
	driver.EXPECT().
		DetachNetwork(gomock.Any(), testProjectID, testFSName, 100).
		Return(nil)

	err := provisioner.detachStaleNetworks(ctx, cli, driver, desiredSet, currentSet, "test-ref")

	require.NoError(t, err)
	// Verify status was removed
	require.Empty(t, fs.Status.Attachments)
}
