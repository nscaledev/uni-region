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

package openstack_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack/mock"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"
	serverprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/server"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestLegacyUserDataRecordSurvivesAnnotationPatchFailure(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	server := desiredRebuildServer()
	server.Name = contractServerID
	server.Namespace = contractNamespace
	server.Labels = contractServerLabels()
	server.Spec.UserData = []byte("#cloud-config\nusers: []\n")
	nova := withUserDataHash(novaRebuildServer("ACTIVE", rebuildNewImageID), "")

	compute := mock.NewMockServerInterface(ctrl)
	compute.EXPECT().UpdateServerMetadata(gomock.Any(), "server-1", map[string]string{
		"region:system:user_data_hash": "a8cc7f5ccfcf822d62581acaa581743e4396c6487b0048fddbdc0233d2892fd2",
	}).DoAndReturn(func(_ context.Context, _ string, metadata map[string]string) error {
		nova.Metadata = metadata

		return nil
	})

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2).
		DoAndReturn(func(ctx context.Context, _ *regionv1.Identity, server *regionv1.Server, _ *types.ServerCreateOptions) error {
			_, err := openstack.ReconcileServerImage(ctx, compute, server, nova)

			return err
		})

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(contractRegionID).Return(provider, nil).Times(2)

	base := contractRetryClient(t)
	patches := 0
	cli := fake.NewClientBuilder().WithScheme(base.Scheme()).WithRESTMapper(base.RESTMapper()).
		WithObjects(server, contractIdentity()).WithStatusSubresource(&regionv1.Server{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(ctx context.Context, cli client.WithWatch, object client.Object, patch client.Patch, opts ...client.PatchOption) error {
				patches++
				if patches == 1 {
					return kerrors.NewConflict(schema.GroupResource{Group: regionv1.SchemeGroupVersion.Group, Resource: "servers"}, object.GetName(), nil)
				}

				return cli.Patch(ctx, object, patch, opts...)
			},
		}).Build()
	key := client.ObjectKeyFromObject(server)
	ctx := coreclient.NewContext(t.Context(), cli)

	first := serverprovisioner.New(nil, providers)
	require.NoError(t, cli.Get(ctx, key, first.Object()))
	err := first.Provision(ctx)
	require.True(t, kerrors.IsConflict(err), "annotation persistence must fail the pass")
	require.Equal(t, "a8cc7f5ccfcf822d62581acaa581743e4396c6487b0048fddbdc0233d2892fd2", nova.Metadata["region:system:user_data_hash"])

	stored := &regionv1.Server{}
	require.NoError(t, cli.Get(ctx, key, stored))
	require.NotContains(t, stored.Annotations, "regions.unikorn-cloud.org/user-data-recorded")
	requireNoReconcilerStamp(t, stored)

	second := serverprovisioner.New(nil, providers)
	require.NoError(t, cli.Get(ctx, key, second.Object()))
	require.NoError(t, second.Provision(ctx))
	require.NoError(t, cli.Status().Update(ctx, second.Object()))
	require.NoError(t, cli.Get(ctx, key, stored))
	require.Equal(t, "true", stored.Annotations["regions.unikorn-cloud.org/user-data-recorded"])
	require.Equal(t, "a8cc7f5ccfcf822d62581acaa581743e4396c6487b0048fddbdc0233d2892fd2", nova.Metadata["region:system:user_data_hash"])
	require.Equal(t, 2, patches)
	requireNoReconcilerStamp(t, stored)
}
