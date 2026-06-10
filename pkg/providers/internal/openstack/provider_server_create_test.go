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
	"testing"

	"github.com/stretchr/testify/require"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newServerCreateProviderTestClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme, err := coreclient.NewScheme(unikornv1.AddToScheme)
	require.NoError(t, err)

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func newServerCreateProviderTestFixture(t *testing.T) (*openstack.Provider, *unikornv1.Identity, *unikornv1.Server) {
	t.Helper()

	const (
		namespace        = "default"
		identityName     = "identity"
		openstackProject = "identity-project"
	)

	openstackIdentity := &unikornv1.OpenstackIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      identityName,
		},
		Spec: unikornv1.OpenstackIdentitySpec{
			UserID:    ptr.To("identity-user"),
			Password:  ptr.To("identity-password"),
			ProjectID: ptr.To(openstackProject),
		},
	}

	client := newServerCreateProviderTestClient(t, openstackIdentity)
	region := &unikornv1.Region{
		Spec: unikornv1.RegionSpec{
			Openstack: &unikornv1.RegionOpenstackSpec{
				Endpoint: "https://openstack.example.com",
			},
		},
	}

	provider := openstack.NewTestProviderWithCredentials(client, region, openstack.TestProviderCredentials{
		UserID:    "region-user",
		Password:  "region-password",
		ProjectID: "region-project",
	})

	identity := &unikornv1.Identity{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      identityName,
		},
	}

	server := &unikornv1.Server{}

	return provider, identity, server
}

func TestProviderForServerCreate(t *testing.T) {
	t.Parallel()

	t.Run("UsesServicePrincipalCredentialsForUnpinnedServers", func(t *testing.T) {
		t.Parallel()

		provider, identity, server := newServerCreateProviderTestFixture(t)

		result, err := openstack.ProviderForServerCreate(t.Context(), provider, identity, server)
		require.NoError(t, err)

		passwordProvider, ok := openstack.PasswordProviderDetails(result)
		require.True(t, ok)
		require.Equal(t, "https://openstack.example.com", passwordProvider.Endpoint)
		require.Equal(t, "identity-user", passwordProvider.UserID)
		require.Equal(t, "identity-password", passwordProvider.Password)
		require.Equal(t, "identity-project", passwordProvider.ProjectID)
	})

	t.Run("UsesPrivilegedProjectScopedCredentialsForPinnedServers", func(t *testing.T) {
		t.Parallel()

		provider, identity, server := newServerCreateProviderTestFixture(t)
		server.Spec.InfrastructureRef = ptr.To("node-0")

		result, err := openstack.ProviderForServerCreate(t.Context(), provider, identity, server)
		require.NoError(t, err)

		passwordProvider, ok := openstack.PasswordProviderDetails(result)
		require.True(t, ok)
		require.Equal(t, "https://openstack.example.com", passwordProvider.Endpoint)
		require.Equal(t, "region-user", passwordProvider.UserID)
		require.Equal(t, "region-password", passwordProvider.Password)
		require.Equal(t, "identity-project", passwordProvider.ProjectID)
	})
}
