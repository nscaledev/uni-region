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

//nolint:testpackage // The per-client timeout needs direct coverage without a mutable global.
package region

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/openapi"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	mockprovider "github.com/unikorn-cloud/region/pkg/providers/types/mock"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const volumeClassDiscoveryTestNamespace = "volume-class-discovery-test"

func newVolumeClassDiscoveryClient(t *testing.T, timeout time.Duration, regions ...*regionv1.Region) (*Client, *mockproviders.MockProviders, *gomock.Controller) {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, regionv1.AddToScheme(scheme))

	builder := fake.NewClientBuilder().WithScheme(scheme)

	for i := range regions {
		regions[i].Namespace = volumeClassDiscoveryTestNamespace
		builder = builder.WithObjects(regions[i])
	}

	ctrl := gomock.NewController(t)
	providers := mockproviders.NewMockProviders(ctrl)

	return &Client{
		ClientArgs: common.ClientArgs{
			Client:    builder.Build(),
			Namespace: volumeClassDiscoveryTestNamespace,
			Providers: providers,
		},
		volumeClassDiscoveryTimeout: timeout,
	}, providers, ctrl
}

func volumeClassDiscoveryContext(t *testing.T) context.Context {
	t.Helper()

	return rbac.NewContext(t.Context(), &identityapi.Acl{
		Global: &identityapi.AclEndpoints{{
			Name:       volumeClassReadEndpoint,
			Operations: identityapi.AclOperations{identityapi.Read},
		}},
	})
}

func TestListVolumeClassesSkipsTimedOutRegion(t *testing.T) {
	t.Parallel()

	const (
		stalledRegionID = "88888888-8888-4888-a888-888888888888"
		healthyRegionID = "99999999-9999-4999-a999-999999999999"
		volumeClassID   = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
	)

	client, providers, ctrl := newVolumeClassDiscoveryClient(t, 100*time.Millisecond,
		&regionv1.Region{ObjectMeta: metav1.ObjectMeta{Name: stalledRegionID}},
		&regionv1.Region{ObjectMeta: metav1.ObjectMeta{Name: healthyRegionID}},
	)
	stalledProvider := mockprovider.NewMockCommonProvider(ctrl)
	stalledProvider.EXPECT().VolumeClasses(gomock.Any()).DoAndReturn(func(ctx context.Context) (types.VolumeClassList, error) {
		<-ctx.Done()

		return nil, ctx.Err()
	})
	providers.EXPECT().LookupCommon(stalledRegionID).Return(stalledProvider, nil)

	healthyProvider := mockprovider.NewMockCommonProvider(ctrl)
	healthyProvider.EXPECT().VolumeClasses(gomock.Any()).Return(types.VolumeClassList{{
		ID:   volumeClassID,
		Name: "available-class",
	}}, nil)
	providers.EXPECT().LookupCommon(healthyRegionID).Return(healthyProvider, nil)

	result, err := client.ListVolumeClasses(volumeClassDiscoveryContext(t), openapi.GetApiV2VolumeclassesParams{})

	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, volumeClassID, result[0].Metadata.Id)
	require.Equal(t, healthyRegionID, result[0].Spec.RegionId.String())
}

func TestListVolumeClassesReturnsTimedOutFilteredRegion(t *testing.T) {
	t.Parallel()

	const regionID = "88888888-8888-4888-a888-888888888888"

	client, providers, ctrl := newVolumeClassDiscoveryClient(t, 100*time.Millisecond,
		&regionv1.Region{ObjectMeta: metav1.ObjectMeta{Name: regionID}},
	)
	provider := mockprovider.NewMockCommonProvider(ctrl)
	provider.EXPECT().VolumeClasses(gomock.Any()).DoAndReturn(func(ctx context.Context) (types.VolumeClassList, error) {
		<-ctx.Done()

		return nil, ctx.Err()
	})
	providers.EXPECT().LookupCommon(regionID).Return(provider, nil)

	_, err := client.ListVolumeClasses(volumeClassDiscoveryContext(t), openapi.GetApiV2VolumeclassesParams{
		RegionID: &openapi.RegionIDQueryParameter{regionID},
	})

	require.ErrorIs(t, err, context.DeadlineExceeded)
}
