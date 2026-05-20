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
	"time"

	"github.com/gophercloud/gophercloud/v2/openstack/baremetal/v1/nodes"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/remoteconsoles"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servergroups"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/require"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var errIronicUnavailable = errors.New("ironic unavailable")

func TestBaremetalBuildPhase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		node *nodes.Node
		want unikornv1.InstanceLifecyclePhase
	}{
		{name: "no node", node: nil, want: unikornv1.InstanceLifecyclePhaseQueued},
		// Pre-deploy: Ironic is alive but has not started deployment.
		{name: "available", node: &nodes.Node{ProvisionState: string(nodes.Available)}, want: unikornv1.InstanceLifecyclePhaseQueued},
		{name: "manageable", node: &nodes.Node{ProvisionState: string(nodes.Manageable)}, want: unikornv1.InstanceLifecyclePhaseQueued},
		{name: "enroll", node: &nodes.Node{ProvisionState: string(nodes.Enroll)}, want: unikornv1.InstanceLifecyclePhaseQueued},
		{name: "cleaning", node: &nodes.Node{ProvisionState: string(nodes.Cleaning)}, want: unikornv1.InstanceLifecyclePhaseQueued},
		{name: "clean wait", node: &nodes.Node{ProvisionState: string(nodes.CleanWait)}, want: unikornv1.InstanceLifecyclePhaseQueued},
		{name: "clean hold", node: &nodes.Node{ProvisionState: string(nodes.CleanHold)}, want: unikornv1.InstanceLifecyclePhaseQueued},
		{name: "verifying", node: &nodes.Node{ProvisionState: string(nodes.Verifying)}, want: unikornv1.InstanceLifecyclePhaseQueued},
		{name: "inspecting", node: &nodes.Node{ProvisionState: string(nodes.Inspecting)}, want: unikornv1.InstanceLifecyclePhaseQueued},
		{name: "inspect wait", node: &nodes.Node{ProvisionState: string(nodes.InspectWait)}, want: unikornv1.InstanceLifecyclePhaseQueued},
		{name: "adopting", node: &nodes.Node{ProvisionState: string(nodes.Adopting)}, want: unikornv1.InstanceLifecyclePhaseQueued},
		// Deploy: Ironic is actively writing the node, including failure variants.
		// Failures stay in Building; the failure signal lives on the Healthy condition.
		{name: "deploying", node: &nodes.Node{ProvisionState: string(nodes.Deploying)}, want: unikornv1.InstanceLifecyclePhaseBuilding},
		{name: "deploy wait", node: &nodes.Node{ProvisionState: string(nodes.DeployWait)}, want: unikornv1.InstanceLifecyclePhaseBuilding},
		{name: "deploy hold", node: &nodes.Node{ProvisionState: string(nodes.DeployHold)}, want: unikornv1.InstanceLifecyclePhaseBuilding},
		{name: "active", node: &nodes.Node{ProvisionState: string(nodes.Active)}, want: unikornv1.InstanceLifecyclePhaseBuilding},
		{name: "deploy fail", node: &nodes.Node{ProvisionState: string(nodes.DeployFail)}, want: unikornv1.InstanceLifecyclePhaseBuilding},
		{name: "clean fail", node: &nodes.Node{ProvisionState: string(nodes.CleanFail)}, want: unikornv1.InstanceLifecyclePhaseBuilding},
		{name: "inspect fail", node: &nodes.Node{ProvisionState: string(nodes.InspectFail)}, want: unikornv1.InstanceLifecyclePhaseBuilding},
		{name: "adopt fail", node: &nodes.Node{ProvisionState: string(nodes.AdoptFail)}, want: unikornv1.InstanceLifecyclePhaseBuilding},
		{name: "error", node: &nodes.Node{ProvisionState: string(nodes.Error)}, want: unikornv1.InstanceLifecyclePhaseBuilding},
		// Unrecognised state is conservatively Queued.
		{name: "unknown", node: &nodes.Node{ProvisionState: "wat"}, want: unikornv1.InstanceLifecyclePhaseQueued},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := baremetalBuildPhase(tt.node)

			require.Equal(t, tt.want, got)
		})
	}
}

func TestShouldCallIronicForPhaseSkipsNonBaremetalBuild(t *testing.T) {
	t.Parallel()

	require.True(t, shouldCallIronicForPhase(servers.Server{Status: "BUILD"}, true))
	require.False(t, shouldCallIronicForPhase(servers.Server{Status: "BUILD"}, false))
	require.False(t, shouldCallIronicForPhase(servers.Server{Status: "ACTIVE"}, true))
}

func TestSetServerPhaseBuildVMBuilding(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}

	setServerPhase(t.Context(), server, &servers.Server{Status: "BUILD"}, nil)

	require.Equal(t, unikornv1.InstanceLifecyclePhaseBuilding, server.Status.Phase)
}

// TestSetServerPhaseRebuildBuilding proves an in-place image rebuild reports
// Building rather than Running. Nova keeps PowerState RUNNING throughout REBUILD,
// so the REBUILD branch must short-circuit the PowerState switch.
func TestSetServerPhaseRebuildBuilding(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}

	setServerPhase(t.Context(), server, &servers.Server{Status: "REBUILD", PowerState: servers.RUNNING}, nil)

	require.Equal(t, unikornv1.InstanceLifecyclePhaseBuilding, server.Status.Phase)
}

func TestSetServerPhaseBuildBaremetalQueued(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}

	setServerPhase(t.Context(), server, &servers.Server{Status: "BUILD"},
		&nodes.Node{ProvisionState: string(nodes.Available)})

	require.Equal(t, unikornv1.InstanceLifecyclePhaseQueued, server.Status.Phase)
}

func TestSetServerPhaseBuildBaremetalBuilding(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}

	setServerPhase(t.Context(), server, &servers.Server{Status: "BUILD"},
		&nodes.Node{ProvisionState: string(nodes.Deploying)})

	require.Equal(t, unikornv1.InstanceLifecyclePhaseBuilding, server.Status.Phase)
}

func TestSetServerPhaseRunning(t *testing.T) {
	t.Parallel()

	launchedAt := time.Now().Add(-time.Minute)
	server := &unikornv1.Server{}

	setServerPhase(t.Context(), server, &servers.Server{Status: "ACTIVE", PowerState: servers.RUNNING, LaunchedAt: launchedAt}, nil)

	require.Equal(t, unikornv1.InstanceLifecyclePhaseRunning, server.Status.Phase)
	require.NotNil(t, server.Status.ProvisionedAt)
	require.Equal(t, metav1.NewTime(launchedAt), *server.Status.ProvisionedAt, "ProvisionedAt latches the Nova launched_at signal")
}

// TestSetServerPhaseRunningLatchesProvisionedAtOnce proves ProvisionedAt is
// write-once: a later observation with a fresh launched_at must not overwrite the
// original latched value.
func TestSetServerPhaseRunningLatchesProvisionedAtOnce(t *testing.T) {
	t.Parallel()

	provisionedAt := metav1.NewTime(time.Now().Add(-time.Hour))
	server := &unikornv1.Server{}
	server.Status.ProvisionedAt = &provisionedAt

	setServerPhase(t.Context(), server, &servers.Server{Status: "ACTIVE", PowerState: servers.RUNNING, LaunchedAt: time.Now()}, nil)

	require.Equal(t, unikornv1.InstanceLifecyclePhaseRunning, server.Status.Phase)
	require.Equal(t, provisionedAt, *server.Status.ProvisionedAt, "ProvisionedAt must not be overwritten once latched")
}

// TestSetServerPhaseLatchesProvisionedAtWithoutRunningPowerState proves the latch
// is driven by Nova launched_at, not the live power state. A booted server that
// does not report PowerState RUNNING (e.g. a baremetal node surfacing NOSTATE
// while Nova-ACTIVE) must still be recorded as provisioned.
func TestSetServerPhaseLatchesProvisionedAtWithoutRunningPowerState(t *testing.T) {
	t.Parallel()

	launchedAt := time.Now().Add(-time.Minute)
	server := &unikornv1.Server{}

	setServerPhase(t.Context(), server, &servers.Server{Status: "ACTIVE", PowerState: servers.NOSTATE, LaunchedAt: launchedAt}, nil)

	require.NotNil(t, server.Status.ProvisionedAt, "a booted server must latch regardless of live power state")
	require.Equal(t, metav1.NewTime(launchedAt), *server.Status.ProvisionedAt)
}

// TestSetServerPhaseStoppedStillLatchesProvisionedAt proves a booted server later
// observed stopped is still recorded as provisioned: it holds data, so the rebuild
// guard must protect it, and legacy stopped servers backfill the latch.
func TestSetServerPhaseStoppedStillLatchesProvisionedAt(t *testing.T) {
	t.Parallel()

	launchedAt := time.Now().Add(-time.Hour)
	server := &unikornv1.Server{}

	setServerPhase(t.Context(), server, &servers.Server{Status: "SHUTOFF", PowerState: servers.SHUTDOWN, LaunchedAt: launchedAt}, nil)

	require.Equal(t, unikornv1.InstanceLifecyclePhaseStopped, server.Status.Phase)
	require.NotNil(t, server.Status.ProvisionedAt, "a booted-then-stopped server must remain provisioned")
}

// TestSetServerPhaseBuildDoesNotLatchProvisionedAt proves a server that has not
// yet booted (no Nova launched_at) is not considered provisioned, keeping it
// eligible for delete-and-retry while Ironic provisioning is still flaky.
func TestSetServerPhaseBuildDoesNotLatchProvisionedAt(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}

	setServerPhase(t.Context(), server, &servers.Server{Status: "BUILD"}, nil)

	require.Nil(t, server.Status.ProvisionedAt, "a building server must not be considered provisioned")
}

func TestSetServerPhaseStopped(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{}

	setServerPhase(t.Context(), server, &servers.Server{Status: "SHUTOFF", PowerState: servers.SHUTDOWN}, nil)

	require.Equal(t, unikornv1.InstanceLifecyclePhaseStopped, server.Status.Phase)
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
func (c *stubComputeClient) DeleteServer(context.Context, string) error { return nil }
func (c *stubComputeClient) RebuildServer(context.Context, string, string) (*servers.Server, error) {
	return nil, nil //nolint:nilnil // unused stub method
}
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
	instanceUUID   string
	provisionState nodes.ProvisionState
}

func (c *recordingBaremetalClient) GetNodeByInstanceUUID(_ context.Context, instanceUUID string) (*nodes.Node, error) {
	c.instanceUUID = instanceUUID

	return &nodes.Node{ProvisionState: string(c.provisionState)}, nil
}

// TestUpdateServerStateWithClientsBaremetalBuildSetsPhaseFromIronicLookup is the
// end-to-end wiring test: a baremetal Nova BUILD server triggers an Ironic
// lookup and the resulting Phase is what baremetalBuildPhase returned.
func TestUpdateServerStateWithClientsBaremetalBuildSetsPhaseFromIronicLookup(t *testing.T) {
	t.Parallel()

	compute := &stubComputeClient{server: &servers.Server{ID: "nova-id", Status: "BUILD"}}
	identity := &unikornv1.Identity{}
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{FlavorID: "metal"}}
	baremetalClient := &recordingBaremetalClient{provisionState: nodes.Available}
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
	require.Equal(t, unikornv1.InstanceLifecyclePhaseQueued, server.Status.Phase)
}

// TestUpdateServerStateWithClientsVMBuildSkipsIronicAndBuilds confirms VMs
// never call the Ironic factory and land on Building.
func TestUpdateServerStateWithClientsVMBuildSkipsIronicAndBuilds(t *testing.T) {
	t.Parallel()

	compute := &stubComputeClient{server: &servers.Server{ID: "nova-id", Status: "BUILD"}}
	identity := &unikornv1.Identity{}
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{FlavorID: "vm"}}
	factoryCalled := false

	provider := &Provider{
		openstack: &openStackClients{
			_region: &unikornv1.Region{
				Spec: unikornv1.RegionSpec{
					Openstack: &unikornv1.RegionOpenstackSpec{
						Compute: &unikornv1.RegionOpenstackComputeSpec{
							Flavors: &unikornv1.OpenstackFlavorsSpec{
								Metadata: []unikornv1.FlavorMetadata{{ID: "vm", Baremetal: false}},
							},
						},
					},
				},
			},
		},
	}

	err := provider.updateServerStateWithClients(t.Context(), identity, server, compute,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			factoryCalled = true

			return nil, errIronicUnavailable
		})

	require.NoError(t, err)
	require.False(t, factoryCalled)
	require.Equal(t, unikornv1.InstanceLifecyclePhaseBuilding, server.Status.Phase)
}

// TestUpdateServerStateWithClientsBaremetalIronicFailureDegradesToBuilding
// confirms a failed Ironic client construction (or lookup) leaves Phase at
// Building, matching the VM default — the monitor must not block reconciles.
func TestUpdateServerStateWithClientsBaremetalIronicFailureDegradesToBuilding(t *testing.T) {
	t.Parallel()

	compute := &stubComputeClient{server: &servers.Server{ID: "nova-id", Status: "BUILD"}}
	identity := &unikornv1.Identity{}
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{FlavorID: "metal"}}

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
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return nil, errIronicUnavailable
		})

	require.NoError(t, err)
	require.Equal(t, unikornv1.InstanceLifecyclePhaseBuilding, server.Status.Phase)
}

func TestBaremetalPhaseProviderUsesPrivilegedCredentials(t *testing.T) {
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

	credentialProvider, err := provider.baremetalPhaseProvider(t.Context(), identity)
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
