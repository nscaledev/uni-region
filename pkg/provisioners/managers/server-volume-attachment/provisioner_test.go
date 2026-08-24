/*
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

package servervolumeattachment

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"
	"github.com/unikorn-cloud/region/pkg/provisioners/internal/base"
	"go.uber.org/mock/gomock"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestSafeguardsPersisted(t *testing.T) {
	const reference = "servervolumeattachments.region.unikorn-cloud.org/attachment-a"

	attachment := &unikornv1.ServerVolumeAttachment{}
	server := &unikornv1.Server{}
	volume := &unikornv1.Volume{}
	if safeguardsPersisted(attachment, server, volume, reference) {
		t.Fatal("safeguards must not pass before finalizers are persisted")
	}

	attachment.Finalizers = []string{coreconstants.Finalizer}
	server.Finalizers = []string{reference}
	volume.Finalizers = []string{reference}
	if !safeguardsPersisted(attachment, server, volume, reference) {
		t.Fatal("safeguards must pass after every finalizer is persisted")
	}
}

func TestProvisionWaitsForClaim(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := unikornv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	server := &unikornv1.Server{}
	server.Name, server.Namespace = "server-a", "default"
	volume := &unikornv1.Volume{}
	volume.Name, volume.Namespace = "volume-a", "default"
	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(server, volume).Build()
	p := &Provisioner{attachment: &unikornv1.ServerVolumeAttachment{}}
	p.attachment.Spec.ServerID, p.attachment.Spec.VolumeID, p.attachment.Namespace = "server-a", "volume-a", "default"
	if err := p.Provision(coreclient.NewContext(context.Background(), cli)); !errors.Is(err, provisioners.ErrYield) {
		t.Fatalf("Provision() error = %v, want ErrYield", err)
	}
}

func TestProjection(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := unikornv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	server := &unikornv1.Server{}
	server.Name, server.Namespace = "server-a", "default"
	cli := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(server).WithObjects(server).Build()
	p := &Provisioner{attachment: &unikornv1.ServerVolumeAttachment{}}
	p.attachment.Spec.ServerID, p.attachment.Spec.VolumeID, p.attachment.Namespace = "server-a", "volume-a", "default"
	device := "/dev/vdb"
	ctx := coreclient.NewContext(context.Background(), cli)

	if err := p.project(ctx, cli, unikornv1.AttachmentProvisioned, &device, "attached"); err != nil {
		t.Fatal(err)
	}
	updated := &unikornv1.Server{}
	if err := cli.Get(ctx, client.ObjectKeyFromObject(server), updated); err != nil {
		t.Fatal(err)
	}
	if len(updated.Status.Volumes) != 1 || updated.Status.Volumes[0].ProvisioningStatus != unikornv1.AttachmentProvisioned || updated.Status.Volumes[0].Device == nil || *updated.Status.Volumes[0].Device != device {
		t.Fatalf("unexpected attachment projection: %#v", updated.Status.Volumes)
	}
	if err := p.removeProjection(ctx, cli); err != nil {
		t.Fatal(err)
	}
	if err := cli.Get(ctx, client.ObjectKeyFromObject(server), updated); err != nil {
		t.Fatal(err)
	}
	if len(updated.Status.Volumes) != 0 {
		t.Fatalf("projection not removed: %#v", updated.Status.Volumes)
	}
}

func lifecycleObjects() (*unikornv1.ServerVolumeAttachment, *unikornv1.Server, *unikornv1.Volume, *unikornv1.Identity) {
	attachment := &unikornv1.ServerVolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "attachment-a", Namespace: "default", Finalizers: []string{coreconstants.Finalizer}},
		Spec:       unikornv1.ServerVolumeAttachmentSpec{ServerID: "server-a", VolumeID: "volume-a"},
	}
	server := &unikornv1.Server{ObjectMeta: metav1.ObjectMeta{
		Name: "server-a", Namespace: "default",
		Labels: map[string]string{constants.RegionLabel: "region-a", constants.IdentityLabel: "identity-a"},
	}}
	volume := &unikornv1.Volume{
		ObjectMeta: metav1.ObjectMeta{Name: "volume-a", Namespace: "default"},
		Spec:       unikornv1.VolumeSpec{ClaimRef: &unikornv1.VolumeClaimRef{Kind: unikornv1.VolumeClaimKindServer, ID: server.Name}},
	}
	identity := &unikornv1.Identity{ObjectMeta: metav1.ObjectMeta{Name: "identity-a", Namespace: "default"}}
	identity.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "")

	return attachment, server, volume, identity
}

func lifecycleProvisioner(t *testing.T, attachment *unikornv1.ServerVolumeAttachment) (*Provisioner, *mocktypes.MockProvider) {
	t.Helper()
	controller := gomock.NewController(t)
	provider := mocktypes.NewMockProvider(controller)
	providerSet := mockproviders.NewMockProviders(controller)
	providerSet.EXPECT().LookupCloud("region-a").Return(provider, nil)

	return &Provisioner{attachment: attachment, Base: base.Base{Providers: providerSet}}, provider
}

func TestProvisionPersistsSafeguardsBeforeAttach(t *testing.T) {
	attachment, server, volume, identity := lifecycleObjects()
	cli := lifecycleFixture(t, attachment, server, volume, identity)
	p, provider := lifecycleProvisioner(t, attachment)
	reference := "servervolumeattachments.region.unikorn-cloud.org/attachment-a"
	device := "/dev/vdb"

	provider.EXPECT().AttachVolume(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, actualIdentity *unikornv1.Identity, actualServer *unikornv1.Server, actualVolume *unikornv1.Volume) (*types.ServerVolumeAttachment, error) {
		require.Equal(t, identity.Name, actualIdentity.Name)
		require.Equal(t, server.Name, actualServer.Name)
		require.Equal(t, volume.Name, actualVolume.Name)
		persistedServer, persistedVolume := &unikornv1.Server{}, &unikornv1.Volume{}
		require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(server), persistedServer))
		require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(volume), persistedVolume))
		require.True(t, safeguardsPersisted(attachment, persistedServer, persistedVolume, reference))

		return &types.ServerVolumeAttachment{Device: ptr.To(device)}, nil
	})

	require.NoError(t, p.Provision(coreclient.NewContext(t.Context(), cli)))
}

func TestDeprovisionDetachesBeforeRemovingSafeguards(t *testing.T) {
	attachment, server, volume, identity := lifecycleObjects()
	reference := "servervolumeattachments.region.unikorn-cloud.org/attachment-a"
	server.Finalizers = []string{reference}
	volume.Finalizers = []string{reference}
	cli := lifecycleFixture(t, attachment, server, volume, identity)
	p, provider := lifecycleProvisioner(t, attachment)

	provider.EXPECT().DetachVolume(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, actualIdentity *unikornv1.Identity, actualServer *unikornv1.Server, actualVolume *unikornv1.Volume) error {
		require.Equal(t, identity.Name, actualIdentity.Name)
		require.Equal(t, server.Name, actualServer.Name)
		require.Equal(t, volume.Name, actualVolume.Name)
		persistedServer, persistedVolume := &unikornv1.Server{}, &unikornv1.Volume{}
		require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(server), persistedServer))
		require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(volume), persistedVolume))
		require.True(t, safeguardsPersisted(attachment, persistedServer, persistedVolume, reference))

		return nil
	})

	require.NoError(t, p.Deprovision(coreclient.NewContext(t.Context(), cli)))
	persistedServer, persistedVolume := &unikornv1.Server{}, &unikornv1.Volume{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(server), persistedServer))
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(volume), persistedVolume))
	require.False(t, slices.Contains(persistedServer.Finalizers, reference))
	require.False(t, slices.Contains(persistedVolume.Finalizers, reference))
}
