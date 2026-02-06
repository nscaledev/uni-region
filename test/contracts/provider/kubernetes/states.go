//go:build integration

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

package kubernetes_test

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/google/uuid"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// defaultTestNamespace is the default namespace for contract testing resources.
	defaultTestNamespace = "default"

	// Test secrets.
	testKubeconfigSecret = "k8s-kubeconfig" //nolint:gosec // Test fixture, not real credentials

	// Test IDs.
	testOrganizationID = "test-org-id"
	testProjectID      = "test-project-id"
	testRegionID       = "test-region-id"
)

const (
	// State parameter keys.
	ParamOrganizationID = "organizationID"
	ParamProjectID      = "projectID"
	ParamRegionID       = "regionID"
	ParamServerID       = "serverID"
	ParamIdentityID     = "identityID"
	ParamNetworkID      = "networkID"
)

var (
	// ErrUnknownState is returned when an unknown state is requested.
	ErrUnknownState = errors.New("unknown state")

	// nodeClassIDNamespace is the namespace UUID for generating deterministic node class IDs.
	nodeClassIDNamespace = uuid.NameSpaceURL //nolint:gochecknoglobals // Standard namespace for resource identifiers
)

// nodeClassToUUID generates a deterministic UUID v5 from a node class name.
// This ensures flavor IDs are in UUID format as expected by consumer contracts.
func nodeClassToUUID(nodeClass string) string {
	id := uuid.NewSHA1(nodeClassIDNamespace, []byte("node-class:"+nodeClass))
	return id.String()
}

// StateManager coordinates setup and teardown of state for contract verification.
// It delegates to specialized managers for different resource types.
type StateManager struct {
	regionManager   *RegionStateManager
	identityManager *IdentityStateManager
	namespace       string
}

// NewStateManager creates a new state manager.
func NewStateManager(client client.Client) *StateManager {
	namespace := getTestNamespace()

	return &StateManager{
		regionManager:   NewRegionStateManager(client, namespace),
		identityManager: NewIdentityStateManager(client, namespace),
		namespace:       namespace,
	}
}

// getTestNamespace returns the namespace for test resources.
func getTestNamespace() string {
	if ns := os.Getenv("TEST_NAMESPACE"); ns != "" {
		return ns
	}

	return defaultTestNamespace
}

// getStringParam extracts a string parameter from state parameters.
func getStringParam(params map[string]interface{}, key string, defaultValue string) string {
	if val, ok := params[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}

	return defaultValue
}

// unwrapPactParams extracts actual parameters from Pact's "params" wrapper.
func unwrapPactParams(params map[string]interface{}) map[string]interface{} {
	if wrappedParams, ok := params["params"].(map[string]interface{}); ok {
		return wrappedParams
	}

	return params
}

// HandleRegionExistsState sets up a test region for uni-kubernetes tests.
func (sm *StateManager) HandleRegionExistsState(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	regionID := getStringParam(actualParams, ParamRegionID, testRegionID)

	fmt.Printf(">>> State handler: HandleRegionExistsState(setup=%v, regionID=%s)\n", setup, regionID)

	if setup {
		// Use OpenStack region for region detail tests
		return sm.regionManager.setupOpenstackRegion(ctx, regionID)
	}

	return sm.cleanupAllResources(ctx)
}

// HandleProjectExistsInRegionState sets up a test region with project access.
func (sm *StateManager) HandleProjectExistsInRegionState(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	regionID := getStringParam(actualParams, ParamRegionID, testRegionID)
	projectID := getStringParam(actualParams, ParamProjectID, testProjectID)

	fmt.Printf(">>> State handler: HandleProjectExistsInRegionState(setup=%v, regionID=%s, projectID=%s)\n", setup, regionID, projectID)

	if setup {
		// Create an OpenStack region for identity creation tests
		return sm.regionManager.setupOpenstackRegion(ctx, regionID)
	}

	return sm.cleanupAllResources(ctx)
}

// HandleServerExistsInProjectState sets up a test region, project, and server.
func (sm *StateManager) HandleServerExistsInProjectState(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	regionID := getStringParam(actualParams, ParamRegionID, testRegionID)
	projectID := getStringParam(actualParams, ParamProjectID, testProjectID)
	serverID := getStringParam(actualParams, ParamServerID, "test-server-id")

	fmt.Printf(">>> State handler: HandleServerExistsInProjectState(setup=%v, regionID=%s, projectID=%s, serverID=%s)\n",
		setup, regionID, projectID, serverID)

	if setup {
		// Create a test region
		// Note: Actual server resources would be created by the provider
		// For contract testing, we just need the region to exist
		return sm.regionManager.setupRegion(ctx, regionID)
	}

	return sm.cleanupAllResources(ctx)
}

// HandleIdentityExistsState sets up state for identity deletion tests.
func (sm *StateManager) HandleIdentityExistsState(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	regionID := getStringParam(actualParams, ParamRegionID, "d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f8a")
	projectID := getStringParam(actualParams, ParamProjectID, testProjectID)
	identityID := getStringParam(actualParams, ParamIdentityID, "test-identity-id")
	organizationID := getStringParam(actualParams, ParamOrganizationID, testOrganizationID)

	fmt.Printf(">>> State handler: HandleIdentityExistsState(setup=%v, regionID=%s, projectID=%s, identityID=%s)\n",
		setup, regionID, projectID, identityID)

	if setup {
		// Create a test region
		if err := sm.regionManager.setupRegion(ctx, regionID); err != nil {
			return err
		}
		// Create a test identity
		return sm.identityManager.setupIdentity(ctx, identityID, projectID, regionID, organizationID)
	}

	return sm.cleanupAllResources(ctx)
}

// HandleIdentityExistsWithPhysicalNetState sets up state for network creation tests.
func (sm *StateManager) HandleIdentityExistsWithPhysicalNetState(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	// Consumer doesn't provide regionID in params for identity tests, use default
	regionID := getStringParam(actualParams, ParamRegionID, "d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f8a")
	projectID := getStringParam(actualParams, ParamProjectID, testProjectID)
	identityID := getStringParam(actualParams, ParamIdentityID, "test-identity-id")
	organizationID := getStringParam(actualParams, ParamOrganizationID, testOrganizationID)

	fmt.Printf(">>> State handler: HandleIdentityExistsWithPhysicalNetState(setup=%v, regionID=%s, projectID=%s, identityID=%s)\n",
		setup, regionID, projectID, identityID)

	if setup {
		// Create a test region
		if err := sm.regionManager.setupRegion(ctx, regionID); err != nil {
			return err
		}
		// Create a test identity with physical network support
		return sm.identityManager.setupIdentity(ctx, identityID, projectID, regionID, organizationID)
	}

	return sm.cleanupAllResources(ctx)
}

// HandleIdentityIsProvisionedState sets up state for getting provisioned identity.
func (sm *StateManager) HandleIdentityIsProvisionedState(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	regionID := getStringParam(actualParams, ParamRegionID, "d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f8a")
	projectID := getStringParam(actualParams, ParamProjectID, testProjectID)
	identityID := getStringParam(actualParams, ParamIdentityID, "test-identity-id")
	organizationID := getStringParam(actualParams, ParamOrganizationID, testOrganizationID)

	fmt.Printf(">>> State handler: HandleIdentityIsProvisionedState(setup=%v, regionID=%s, projectID=%s, identityID=%s)\n",
		setup, regionID, projectID, identityID)

	if setup {
		// Create a test region
		if err := sm.regionManager.setupRegion(ctx, regionID); err != nil {
			return err
		}
		// Create a provisioned test identity
		return sm.identityManager.setupProvisionedIdentity(ctx, identityID, projectID, regionID, organizationID)
	}

	return sm.cleanupAllResources(ctx)
}

// HandleNetworkIsProvisionedState sets up state for getting provisioned network.
func (sm *StateManager) HandleNetworkIsProvisionedState(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	regionID := getStringParam(actualParams, ParamRegionID, "d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f8a")
	projectID := getStringParam(actualParams, ParamProjectID, testProjectID)
	identityID := getStringParam(actualParams, ParamIdentityID, "test-identity-id")
	networkID := getStringParam(actualParams, ParamNetworkID, "test-network-id")
	organizationID := getStringParam(actualParams, ParamOrganizationID, testOrganizationID)

	fmt.Printf(">>> State handler: HandleNetworkIsProvisionedState(setup=%v, regionID=%s, projectID=%s, identityID=%s, networkID=%s)\n",
		setup, regionID, projectID, identityID, networkID)

	if setup {
		// Create a test region
		if err := sm.regionManager.setupRegion(ctx, regionID); err != nil {
			return err
		}
		// Create a provisioned test identity
		if err := sm.identityManager.setupProvisionedIdentity(ctx, identityID, projectID, regionID, organizationID); err != nil {
			return err
		}
		// Create a provisioned test network
		return sm.identityManager.setupProvisionedNetwork(ctx, networkID, identityID, projectID, regionID, organizationID)
	}

	return sm.cleanupAllResources(ctx)
}

// HandleRegionHasExternalNetworksState sets up state for listing external networks.
func (sm *StateManager) HandleRegionHasExternalNetworksState(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	regionID := getStringParam(actualParams, ParamRegionID, testRegionID)
	regionType := getStringParam(actualParams, "regionType", "kubernetes")

	fmt.Printf(">>> State handler: HandleRegionHasExternalNetworksState(setup=%v, regionID=%s, regionType=%s)\n", setup, regionID, regionType)

	if setup {
		return sm.regionManager.setupRegionWithType(ctx, regionID, regionType)
	}

	return sm.cleanupAllResources(ctx)
}

// HandleRegionHasFlavorsState sets up state for listing flavors.
func (sm *StateManager) HandleRegionHasFlavorsState(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	regionID := getStringParam(actualParams, ParamRegionID, testRegionID)

	fmt.Printf(">>> State handler: HandleRegionHasFlavorsState(setup=%v, regionID=%s)\n", setup, regionID)

	if setup {
		// Setup region first
		if err := sm.regionManager.setupRegion(ctx, regionID); err != nil {
			return err
		}
		// Create mock nodes for flavor testing
		return sm.regionManager.createMockNodes(ctx)
	}

	// Cleanup both nodes and regions
	sm.regionManager.cleanupMockNodes(ctx)

	return sm.cleanupAllResources(ctx)
}

// HandleRegionHasImagesState sets up state for listing images.
func (sm *StateManager) HandleRegionHasImagesState(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	regionID := getStringParam(actualParams, ParamRegionID, testRegionID)
	regionType := getStringParam(actualParams, "regionType", "kubernetes")

	fmt.Printf(">>> State handler: HandleRegionHasImagesState(setup=%v, regionID=%s, regionType=%s)\n", setup, regionID, regionType)

	if setup {
		return sm.regionManager.setupRegionWithType(ctx, regionID, regionType)
	}

	return sm.cleanupAllResources(ctx)
}

// HandleOrganizationHasRegionsState sets up state for listing regions.
func (sm *StateManager) HandleOrganizationHasRegionsState(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	orgID := getStringParam(actualParams, ParamOrganizationID, testOrganizationID)

	fmt.Printf(">>> State handler: HandleOrganizationHasRegionsState(setup=%v, orgID=%s)\n", setup, orgID)

	if setup {
		// Create a test region for this organization
		return sm.regionManager.setupRegionWithOrg(ctx, testRegionID, orgID)
	}

	return sm.cleanupAllResources(ctx)
}

// cleanupAllResources deletes all test resources in the namespace.
func (sm *StateManager) cleanupAllResources(ctx context.Context) error {
	// Clean up identities and networks
	if err := sm.identityManager.cleanupIdentitiesAndNetworks(ctx); err != nil {
		return err
	}

	// Clean up regions
	return sm.regionManager.cleanupAllRegions(ctx)
}
