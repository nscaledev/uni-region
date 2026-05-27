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

//nolint:testpackage
package openstack

import (
	"context"
	"errors"
	"testing"

	"github.com/go-logr/logr"
	"github.com/gophercloud/gophercloud/v2/openstack/baremetal/v1/nodes"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/require"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var errIronicUnavailable = errors.New("ironic unavailable")

func noIronicNode(context.Context, string) (*nodes.Node, error) {
	//nolint:nilnil // A missing Ironic node is a valid queued state, not an error.
	return nil, nil
}

func TestBaremetalBuildProvisioningStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		node *nodes.Node
		want coreapi.ResourceProvisioningStatus
	}{
		{name: "no node", node: nil, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "available", node: &nodes.Node{ProvisionState: "available"}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "manageable", node: &nodes.Node{ProvisionState: "manageable"}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "enroll", node: &nodes.Node{ProvisionState: "enroll"}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "cleaning", node: &nodes.Node{ProvisionState: "cleaning"}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "clean wait", node: &nodes.Node{ProvisionState: "clean wait"}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "verifying", node: &nodes.Node{ProvisionState: "verifying"}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "inspecting", node: &nodes.Node{ProvisionState: "inspecting"}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "inspect wait", node: &nodes.Node{ProvisionState: "inspect wait"}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "adopting", node: &nodes.Node{ProvisionState: "adopting"}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "clean failed", node: &nodes.Node{ProvisionState: "clean failed"}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "clean hold", node: &nodes.Node{ProvisionState: "clean hold"}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "inspect failed", node: &nodes.Node{ProvisionState: "inspect failed"}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "adopt failed", node: &nodes.Node{ProvisionState: "adopt failed"}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "deploying", node: &nodes.Node{ProvisionState: "deploying"}, want: coreapi.ResourceProvisioningStatusProvisioning},
		{name: "wait callback", node: &nodes.Node{ProvisionState: "wait call-back"}, want: coreapi.ResourceProvisioningStatusProvisioning},
		{name: "deploy hold", node: &nodes.Node{ProvisionState: "deploy hold"}, want: coreapi.ResourceProvisioningStatusProvisioning},
		{name: "deploy failed", node: &nodes.Node{ProvisionState: "deploy failed"}, want: coreapi.ResourceProvisioningStatusProvisioning},
		{name: "active", node: &nodes.Node{ProvisionState: "active"}, want: coreapi.ResourceProvisioningStatusProvisioning},
		{name: "error", node: &nodes.Node{ProvisionState: "error"}, want: coreapi.ResourceProvisioningStatusProvisioning},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := baremetalBuildProvisioningStatus(tt.node)

			require.Equal(t, tt.want, got)
		})
	}
}

func TestShouldCallIronicForProvisioningStatusSkipsNonBaremetalBuild(t *testing.T) {
	t.Parallel()

	callIronic := shouldCallIronicForProvisioningStatus(servers.Server{Status: "BUILD"}, false)

	require.False(t, callIronic)
}

func TestUpdateServerProviderProvisioningStatusBaremetalBuildNoNodeQueued(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}
	novaServer := &servers.Server{ID: "nova-id", Status: "BUILD"}

	updateServerProviderProvisioningStatus(t.Context(), logr.Discard(), server, novaServer, true, noIronicNode)

	require.NotNil(t, server.Status.ProviderProvisioningStatus)
	require.Equal(t, coreapi.ResourceProvisioningStatusQueued, *server.Status.ProviderProvisioningStatus)
}

func TestUpdateServerProviderProvisioningStatusBaremetalBuildDeployingProvisioning(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}
	novaServer := &servers.Server{ID: "nova-id", Status: "BUILD"}

	updateServerProviderProvisioningStatus(t.Context(), logr.Discard(), server, novaServer, true,
		func(context.Context, string) (*nodes.Node, error) {
			return &nodes.Node{ProvisionState: "deploying"}, nil
		})

	require.NotNil(t, server.Status.ProviderProvisioningStatus)
	require.Equal(t, coreapi.ResourceProvisioningStatusProvisioning, *server.Status.ProviderProvisioningStatus)
}

func TestUpdateServerProviderProvisioningStatusVMBuildSkipsIronic(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}
	novaServer := &servers.Server{ID: "nova-id", Status: "BUILD"}
	called := false

	updateServerProviderProvisioningStatus(t.Context(), logr.Discard(), server, novaServer, false,
		func(ctx context.Context, _ string) (*nodes.Node, error) {
			called = true

			return noIronicNode(ctx, "")
		})

	require.False(t, called)
	require.Nil(t, server.Status.ProviderProvisioningStatus)
}

func TestUpdateServerProviderProvisioningStatusIronicErrorLeavesOverrideUnset(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}
	novaServer := &servers.Server{ID: "nova-id", Status: "BUILD"}

	updateServerProviderProvisioningStatus(t.Context(), logr.Discard(), server, novaServer, true,
		func(context.Context, string) (*nodes.Node, error) {
			return nil, errIronicUnavailable
		})

	require.Nil(t, server.Status.ProviderProvisioningStatus)
}

func TestUpdateServerProviderProvisioningStatusActiveClearsOverride(t *testing.T) {
	t.Parallel()

	queued := coreapi.ResourceProvisioningStatusQueued
	server := &unikornv1.Server{Status: unikornv1.ServerStatus{ProviderProvisioningStatus: &queued}}
	novaServer := &servers.Server{ID: "nova-id", Status: "ACTIVE"}

	updateServerProviderProvisioningStatus(t.Context(), logr.Discard(), server, novaServer, true, noIronicNode)

	require.Nil(t, server.Status.ProviderProvisioningStatus)
}

func TestBaremetalProvisioningStatusProviderUsesPrivilegedCredentials(t *testing.T) {
	t.Parallel()

	scheme, err := coreclient.NewScheme(unikornv1.AddToScheme)
	require.NoError(t, err)

	servicePrincipalUserID := "service-principal-user"
	servicePrincipalPassword := "service-principal-password"
	projectID := "project-id"

	identity := &unikornv1.Identity{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "identity",
		},
	}
	openstackIdentity := &unikornv1.OpenstackIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: identity.Namespace,
			Name:      identity.Name,
		},
		Spec: unikornv1.OpenstackIdentitySpec{
			UserID:    &servicePrincipalUserID,
			Password:  &servicePrincipalPassword,
			ProjectID: &projectID,
		},
	}

	provider := &Provider{
		client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(openstackIdentity).Build(),
		openstack: &openStackClients{
			_region: &unikornv1.Region{
				Spec: unikornv1.RegionSpec{
					Openstack: &unikornv1.RegionOpenstackSpec{Endpoint: "https://keystone.example.com"},
				},
			},
			_credentials: &providerCredentials{
				userID:   "provider-user",
				password: "provider-password",
			},
		},
	}

	credentialProvider, err := provider.baremetalProvisioningStatusProvider(t.Context(), identity)
	require.NoError(t, err)

	passwordProvider, ok := credentialProvider.(*PasswordProvider)
	require.True(t, ok)
	require.Equal(t, "provider-user", passwordProvider.userID)
	require.Equal(t, "provider-password", passwordProvider.password)
	require.Equal(t, projectID, passwordProvider.projectID)
}

func TestIsBaremetalFlavor(t *testing.T) {
	t.Parallel()

	region := &unikornv1.Region{
		Spec: unikornv1.RegionSpec{
			Openstack: &unikornv1.RegionOpenstackSpec{
				Compute: &unikornv1.RegionOpenstackComputeSpec{
					Flavors: &unikornv1.OpenstackFlavorsSpec{
						Metadata: []unikornv1.FlavorMetadata{
							{ID: "vm", Baremetal: false},
							{ID: "metal", Baremetal: true},
						},
					},
				},
			},
		},
	}

	require.True(t, isBaremetalFlavor(region, "metal"))
	require.False(t, isBaremetalFlavor(region, "vm"))
	require.False(t, isBaremetalFlavor(region, "missing"))
	require.False(t, isBaremetalFlavor(nil, "metal"))
}
