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
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/remoteconsoles"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servergroups"
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
		{name: "available", node: &nodes.Node{ProvisionState: string(nodes.Available)}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "manageable", node: &nodes.Node{ProvisionState: string(nodes.Manageable)}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "enroll", node: &nodes.Node{ProvisionState: string(nodes.Enroll)}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "cleaning", node: &nodes.Node{ProvisionState: string(nodes.Cleaning)}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "clean wait", node: &nodes.Node{ProvisionState: string(nodes.CleanWait)}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "verifying", node: &nodes.Node{ProvisionState: string(nodes.Verifying)}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "inspecting", node: &nodes.Node{ProvisionState: string(nodes.Inspecting)}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "inspect wait", node: &nodes.Node{ProvisionState: string(nodes.InspectWait)}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "adopting", node: &nodes.Node{ProvisionState: string(nodes.Adopting)}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "clean failed", node: &nodes.Node{ProvisionState: string(nodes.CleanFail)}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "clean hold", node: &nodes.Node{ProvisionState: string(nodes.CleanHold)}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "inspect failed", node: &nodes.Node{ProvisionState: string(nodes.InspectFail)}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "adopt failed", node: &nodes.Node{ProvisionState: string(nodes.AdoptFail)}, want: coreapi.ResourceProvisioningStatusQueued},
		{name: "deploying", node: &nodes.Node{ProvisionState: string(nodes.Deploying)}, want: coreapi.ResourceProvisioningStatusProvisioning},
		{name: "wait callback", node: &nodes.Node{ProvisionState: string(nodes.DeployWait)}, want: coreapi.ResourceProvisioningStatusProvisioning},
		{name: "deploy hold", node: &nodes.Node{ProvisionState: string(nodes.DeployHold)}, want: coreapi.ResourceProvisioningStatusProvisioning},
		{name: "deploy failed", node: &nodes.Node{ProvisionState: string(nodes.DeployFail)}, want: coreapi.ResourceProvisioningStatusError},
		{name: "active", node: &nodes.Node{ProvisionState: string(nodes.Active)}, want: coreapi.ResourceProvisioningStatusProvisioning},
		{name: "error", node: &nodes.Node{ProvisionState: string(nodes.Error)}, want: coreapi.ResourceProvisioningStatusError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := baremetalBuildProvisioningStatus(tt.node)

			require.Equal(t, tt.want, got)
		})
	}
}

type stubComputeClient struct {
	server          *servers.Server
	requestedServer *unikornv1.Server
}

func (c *stubComputeClient) CreateKeypair(context.Context, string, string) error  { return nil }
func (c *stubComputeClient) DeleteKeypair(context.Context, string) error          { return nil }
func (c *stubComputeClient) GetFlavors(context.Context) ([]flavors.Flavor, error) { return nil, nil }
func (c *stubComputeClient) CreateServerGroup(context.Context, string) (*servergroups.ServerGroup, error) {
	return nil, nil //nolint:nilnil // unused stub method
}
func (c *stubComputeClient) DeleteServerGroup(context.Context, string) error { return nil }
func (c *stubComputeClient) UpdateQuotas(context.Context, string) error      { return nil }
func (c *stubComputeClient) GetServer(_ context.Context, server *unikornv1.Server) (*servers.Server, error) {
	c.requestedServer = server

	return c.server, nil
}
func (c *stubComputeClient) CreateServer(context.Context, *unikornv1.Server, string, []servers.Network, *string, map[string]string) (*servers.Server, error) {
	return nil, nil //nolint:nilnil // unused stub method
}
func (c *stubComputeClient) DeleteServer(context.Context, string) error       { return nil }
func (c *stubComputeClient) RebootServer(context.Context, string, bool) error { return nil }
func (c *stubComputeClient) StartServer(context.Context, string) error        { return nil }
func (c *stubComputeClient) StopServer(context.Context, string) error         { return nil }
func (c *stubComputeClient) CreateRemoteConsole(context.Context, string) (*remoteconsoles.RemoteConsole, error) {
	return nil, nil //nolint:nilnil // unused stub method
}
func (c *stubComputeClient) ShowConsoleOutput(context.Context, string, *int) (string, error) {
	return "", nil
}
func (c *stubComputeClient) CreateImageFromServer(context.Context, string, *servers.CreateImageOpts) (string, error) {
	return "", nil
}

type recordingBaremetalClient struct {
	instanceUUID string
}

func (c *recordingBaremetalClient) GetNodeByInstanceUUID(_ context.Context, instanceUUID string) (*nodes.Node, error) {
	c.instanceUUID = instanceUUID

	return &nodes.Node{ProvisionState: string(nodes.DeployWait)}, nil
}

func TestUpdateServerStateWithClientsBaremetalBuildUsesProvisioningStatusIronicLookup(t *testing.T) {
	t.Parallel()

	compute := &stubComputeClient{server: &servers.Server{ID: "nova-id", Status: "BUILD"}}
	identity := &unikornv1.Identity{}
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{FlavorID: "metal"}}
	baremetalClient := &recordingBaremetalClient{}
	factoryCalled := false

	provider := &Provider{
		openstack: &openStackClients{
			_region: &unikornv1.Region{
				Spec: unikornv1.RegionSpec{
					Openstack: &unikornv1.RegionOpenstackSpec{
						Compute: &unikornv1.RegionOpenstackComputeSpec{
							Flavors: &unikornv1.OpenstackFlavorsSpec{
								Metadata: []unikornv1.FlavorMetadata{{ID: "metal", Baremetal: true}},
							},
						},
					},
				},
			},
		},
	}

	err := provider.updateServerStateWithClients(t.Context(), identity, server, compute,
		func(_ context.Context, gotIdentity *unikornv1.Identity) (BaremetalInterface, error) {
			require.Same(t, identity, gotIdentity)

			factoryCalled = true

			return baremetalClient, nil
		})

	require.NoError(t, err)
	require.True(t, factoryCalled)
	require.Equal(t, "nova-id", baremetalClient.instanceUUID)
	require.NotNil(t, server.Status.ProviderProvisioningStatus)
	require.Equal(t, coreapi.ResourceProvisioningStatusProvisioning, *server.Status.ProviderProvisioningStatus)
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

func TestUpdateServerProviderProvisioningStatusNovaErrorSetsErrorOverride(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}
	novaServer := &servers.Server{ID: "nova-id", Status: "ERROR"}

	updateServerProviderProvisioningStatus(t.Context(), logr.Discard(), server, novaServer, false, noIronicNode)

	require.NotNil(t, server.Status.ProviderProvisioningStatus)
	require.Equal(t, coreapi.ResourceProvisioningStatusError, *server.Status.ProviderProvisioningStatus)
}

func TestUpdateServerProviderProvisioningStatusNovaErrorSkipsIronic(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}
	novaServer := &servers.Server{ID: "nova-id", Status: "ERROR"}
	called := false

	updateServerProviderProvisioningStatus(t.Context(), logr.Discard(), server, novaServer, true,
		func(ctx context.Context, _ string) (*nodes.Node, error) {
			called = true

			return noIronicNode(ctx, "")
		})

	require.False(t, called)
	require.NotNil(t, server.Status.ProviderProvisioningStatus)
	require.Equal(t, coreapi.ResourceProvisioningStatusError, *server.Status.ProviderProvisioningStatus)
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
