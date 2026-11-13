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
	"net/http"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack/mock"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"
	serverprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/server"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// Exercise the real metadata refusal so a plain error cannot retain references.
func TestProvision_RefusedRecordReleasesConsumedReferences(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	server := desiredRebuildServer()
	server.Name = contractServerID
	server.Namespace = contractNamespace
	server.Labels = contractServerLabels()

	droppedGroup := &regionv1.SecurityGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "dropped-group",
			Namespace:  contractNamespace,
			Labels:     map[string]string{constants.IdentityLabel: contractIdentityID},
			Finalizers: []string{"servers.region.unikorn-cloud.org/" + server.Name},
		},
	}

	compute := mock.NewMockServerInterface(ctrl)
	compute.EXPECT().UpdateServerMetadata(gomock.Any(), "server-1", gomock.Any()).
		Return(gophercloud.ErrUnexpectedResponseCode{Actual: http.StatusConflict})

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, _ *regionv1.Identity, server *regionv1.Server, _ *types.ServerCreateOptions) error {
			_, err := openstack.ReconcileServerImage(ctx, compute, server, withUserDataHash(novaRebuildServer("ACTIVE", rebuildNewImageID), ""))

			return err
		})

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(contractRegionID).Return(provider, nil)

	cli := contractRetryClient(t, server, contractIdentity(), droppedGroup)
	prov := serverprovisioner.New(nil, providers)
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(server), prov.Object()))

	err := prov.Provision(coreclient.NewContext(t.Context(), cli))
	updated := &regionv1.SecurityGroup{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(droppedGroup), updated))
	require.Empty(t, updated.Finalizers, "a yielding pass must still release references the spec no longer holds")
	requireTypedYield(t, err, unikornv1core.ConditionReasonProvisioning, "waiting for the provider to accept the user-data record")

	provisioned, ok := prov.Object().(*regionv1.Server)
	require.True(t, ok)
	requireUserDataRecorded(t, provisioned, false)
}

func TestUserDataRecordSurvivesStatusWriteFailure(t *testing.T) {
	t.Parallel()

	for _, rebuild := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy record", true: "rebuild record"}[rebuild], func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			server := desiredRebuildServer()
			server.Name = contractServerID
			server.Namespace = contractNamespace
			server.Labels = contractServerLabels()
			server.Spec.UserData = []byte("#cloud-config\nusers: []\n")
			nova := withUserDataHash(novaRebuildServer("ACTIVE", rebuildNewImageID), "")

			compute := mock.NewMockServerInterface(ctrl)

			if rebuild {
				nova = withUserDataHash(novaRebuildServer("ACTIVE", rebuildNewImageID), "old")

				compute.EXPECT().RebuildServer(gomock.Any(), "server-1", rebuildOptionsFor(server.Spec.UserData)).
					DoAndReturn(func(_ context.Context, _ string, options openstack.ServerRebuildOptions) (*servers.Server, error) {
						nova = withUserDataHash(novaRebuildServer("ACTIVE", rebuildNewImageID), options.Metadata["region:system:user_data_hash"])

						return nova, nil
					})
			} else {
				compute.EXPECT().UpdateServerMetadata(gomock.Any(), "server-1", map[string]string{
					"region:system:user_data_hash": "a8cc7f5ccfcf822d62581acaa581743e4396c6487b0048fddbdc0233d2892fd2",
				}).DoAndReturn(func(_ context.Context, _ string, metadata map[string]string) error {
					nova.Metadata = metadata

					return nil
				})
			}

			provider := mocktypes.NewMockProvider(ctrl)
			provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2).
				DoAndReturn(func(ctx context.Context, _ *regionv1.Identity, server *regionv1.Server, _ *types.ServerCreateOptions) error {
					_, err := openstack.ReconcileServerImage(ctx, compute, server, nova)

					return err
				})

			providers := mockproviders.NewMockProviders(ctrl)
			providers.EXPECT().LookupCloud(contractRegionID).Return(provider, nil).Times(2)

			base := contractRetryClient(t)
			writes := 0
			cli := fake.NewClientBuilder().WithScheme(base.Scheme()).WithRESTMapper(base.RESTMapper()).
				WithObjects(server, contractIdentity()).WithStatusSubresource(&regionv1.Server{}).
				WithInterceptorFuncs(interceptor.Funcs{
					SubResourceUpdate: func(ctx context.Context, cli client.Client, subresource string, object client.Object, opts ...client.SubResourceUpdateOption) error {
						require.Equal(t, "status", subresource)
						writes++
						if writes == 1 {
							return kerrors.NewConflict(schema.GroupResource{Group: regionv1.SchemeGroupVersion.Group, Resource: "servers"}, object.GetName(), nil)
						}

						return cli.SubResource(subresource).Update(ctx, object, opts...)
					},
				}).Build()
			key := client.ObjectKeyFromObject(server)
			ctx := coreclient.NewContext(t.Context(), cli)

			first := serverprovisioner.New(nil, providers)
			require.NoError(t, cli.Get(ctx, key, first.Object()))

			err := first.Provision(ctx)
			if rebuild {
				require.ErrorIs(t, err, provisioners.ErrYield)
			} else {
				require.NoError(t, err)
			}

			require.True(t, kerrors.IsConflict(cli.Status().Update(ctx, first.Object())))
			require.Equal(t, "a8cc7f5ccfcf822d62581acaa581743e4396c6487b0048fddbdc0233d2892fd2", nova.Metadata["region:system:user_data_hash"])

			stored := &regionv1.Server{}
			require.NoError(t, cli.Get(ctx, key, stored))
			require.False(t, stored.UserDataRecorded())
			requireNoReconcilerStamp(t, stored)

			second := serverprovisioner.New(nil, providers)
			require.NoError(t, cli.Get(ctx, key, second.Object()))
			require.NoError(t, second.Provision(ctx))
			require.NoError(t, cli.Status().Update(ctx, second.Object()))
			require.NoError(t, cli.Get(ctx, key, stored))
			condition := meta.FindStatusCondition(stored.Status.Conditions, "UserDataRecorded")
			require.NotNil(t, condition)
			require.Equal(t, metav1.ConditionTrue, condition.Status)
			require.Equal(t, "a8cc7f5ccfcf822d62581acaa581743e4396c6487b0048fddbdc0233d2892fd2", nova.Metadata["region:system:user_data_hash"])
			require.Equal(t, 2, writes)
			requireNoReconcilerStamp(t, stored)
		})
	}
}
