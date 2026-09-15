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

package server_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	httperrors "github.com/unikorn-cloud/core/pkg/server/errors"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/server"
	idstest "github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/openapi"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	srvIdentityID = "99999999-9999-4999-a999-999999999999"
	// srvNewImageID is a second image, distinct from srvImageID, used to
	// request an image change through the v1 API.
	srvNewImageID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

// testSrvIdentity returns an Identity owned by the fixture organization and
// project, as required by the v1 server handler's identity lookup.
func testSrvIdentity() *regionv1.Identity {
	return &regionv1.Identity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      srvIdentityID,
			Namespace: srvNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel: srvOrganizationID,
				coreconstants.ProjectLabel:      srvProjectID,
				constants.RegionLabel:           srvRegionID,
			},
		},
		Spec: regionv1.IdentitySpec{
			Provider: regionv1.ProviderOpenstack,
		},
	}
}

// testServerV1 returns a Server as created through the v1 API: no
// ResourceAPIVersionLabel.
func testServerV1(serverID string) *regionv1.Server {
	resource := testServerV2(serverID)
	delete(resource.Labels, constants.ResourceAPIVersionLabel)

	return resource
}

// TestServerV1UpdateIgnoresImageChange pins the v1 contract that the image is
// immutable after create: an update carrying a different imageId succeeds, the
// stored image is preserved (so the provider never observes image drift and
// never arms a rebuild), and the response reports the retained image. Other
// spec changes in the same request still apply.
func TestServerV1UpdateIgnoresImageChange(t *testing.T) {
	t.Parallel()

	k8sClient := newSrvFakeClient(t, testSrvIdentity(), testSrvNetworkWithProject(srvProjectID), testServerV1(srvServerID)).Build()

	// No provider mocks: the v1 update path discards the request image without
	// consulting the provider, so it must complete without any provider calls.
	c := server.NewClient(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
	})

	userData := []byte("#cloud-config")

	request := &openapi.ServerWrite{
		Metadata: coreapi.ResourceWriteMetadata{Name: "test-server"},
		Spec: openapi.ServerSpec{
			FlavorId: idstest.MustParseFlavorID(srvFlavorID),
			ImageId:  idstest.MustParseImageID(srvNewImageID),
			Networks: openapi.ServerNetworkList{{Id: srvNetworkID}},
			UserData: &userData,
		},
	}

	response, err := c.Update(withPrincipal(t.Context()),
		identityids.MustParseOrganizationID(srvOrganizationID),
		identityids.MustParseProjectID(srvProjectID),
		idstest.MustParseIdentityID(srvIdentityID),
		idstest.MustParseServerID(srvServerID),
		request)
	require.NoError(t, err)
	require.Equal(t, idstest.MustParseImageID(srvImageID), response.Spec.ImageId)

	updated := &regionv1.Server{}
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKey{Namespace: srvNamespace, Name: srvServerID}, updated))
	require.Equal(t, idstest.MustParseImageID(srvImageID), updated.Spec.Image.ID)
	require.Equal(t, userData, updated.Spec.UserData)
}

// TestServerV1UpdateIgnoresNonexistentImage pins that the v1 update does not
// validate the request's imageId at all: the value is discarded in favour of
// the stored image, so a request echoing a since-deleted image must not 404 an
// update that has no image effect. Accept-and-ignore means ignore.
func TestServerV1UpdateIgnoresNonexistentImage(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	k8sClient := newSrvFakeClient(t, testSrvIdentity(), testSrvNetworkWithProject(srvProjectID), testServerV1(srvServerID)).Build()

	// The provider does not know the requested image; a validating update would
	// observe not-found and fail.
	mockProvider := mocktypes.NewMockProvider(ctrl)
	mockProvider.EXPECT().GetImage(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil, coreerrors.ErrResourceNotFound).AnyTimes()

	mockProviders := mockproviders.NewMockProviders(ctrl)
	mockProviders.EXPECT().LookupCloud(gomock.Any()).Return(mockProvider, nil).AnyTimes()

	c := server.NewClient(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Providers: mockProviders,
	})

	request := &openapi.ServerWrite{
		Metadata: coreapi.ResourceWriteMetadata{Name: "test-server"},
		Spec: openapi.ServerSpec{
			FlavorId: idstest.MustParseFlavorID(srvFlavorID),
			ImageId:  idstest.MustParseImageID(srvNewImageID),
			Networks: openapi.ServerNetworkList{{Id: srvNetworkID}},
		},
	}

	response, err := c.Update(withPrincipal(t.Context()),
		identityids.MustParseOrganizationID(srvOrganizationID),
		identityids.MustParseProjectID(srvProjectID),
		idstest.MustParseIdentityID(srvIdentityID),
		idstest.MustParseServerID(srvServerID),
		request)
	require.NoError(t, err)
	require.Equal(t, idstest.MustParseImageID(srvImageID), response.Spec.ImageId)

	updated := &regionv1.Server{}
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKey{Namespace: srvNamespace, Name: srvServerID}, updated))
	require.Equal(t, idstest.MustParseImageID(srvImageID), updated.Spec.Image.ID)
}

// TestServerV1CreateRejectsNonexistentImage pins that the v1 create keeps its
// existence-only image check: an unknown imageId is rejected with HTTP 404.
func TestServerV1CreateRejectsNonexistentImage(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)

	k8sClient := newSrvFakeClient(t, testSrvIdentity()).Build()

	mockProvider := mocktypes.NewMockProvider(ctrl)
	mockProvider.EXPECT().GetImage(gomock.Any(), gomock.Any(), idstest.MustParseImageID(srvNewImageID)).
		Return(nil, coreerrors.ErrResourceNotFound)

	mockProviders := mockproviders.NewMockProviders(ctrl)
	mockProviders.EXPECT().LookupCloud(gomock.Any()).Return(mockProvider, nil)

	c := server.NewClient(common.ClientArgs{
		Client:    k8sClient,
		Namespace: srvNamespace,
		Providers: mockProviders,
	})

	request := &openapi.ServerWrite{
		Metadata: coreapi.ResourceWriteMetadata{Name: "test-server"},
		Spec: openapi.ServerSpec{
			FlavorId: idstest.MustParseFlavorID(srvFlavorID),
			ImageId:  idstest.MustParseImageID(srvNewImageID),
			Networks: openapi.ServerNetworkList{{Id: srvNetworkID}},
		},
	}

	_, err := c.Create(withPrincipal(t.Context()),
		identityids.MustParseOrganizationID(srvOrganizationID),
		identityids.MustParseProjectID(srvProjectID),
		idstest.MustParseIdentityID(srvIdentityID),
		request)
	require.Error(t, err)
	require.True(t, httperrors.IsHTTPNotFound(err), "expected 404 not found, got: %v", err)
}
