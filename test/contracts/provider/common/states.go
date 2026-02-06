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

package common

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/google/uuid"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// DefaultTestNamespace is the default namespace for contract testing resources.
	DefaultTestNamespace = "default"

	// TestKubeconfigSecret is the default kubeconfig secret name for tests.
	TestKubeconfigSecret = "k8s-kubeconfig" //nolint:gosec // Test fixture, not real credentials

	// Default test resource IDs - exported for reuse in other test packages.
	TestOrganizationID = "test-org-id"
	TestProjectID      = "test-project-id"
	TestRegionID       = "test-region-id"
)

const (
	// Test region names for different provider scenarios.
	RegionUSWest1    = "us-west-1"
	RegionOpenStack  = "openstack-region"
	RegionKubernetes = "k8s-region"

	// Secret names for test fixtures - exported for reuse.
	SecretTestCredentials      = "test-credentials"
	SecretOpenStackCredentials = "openstack-credentials" //nolint:gosec // Test fixture, not real credentials
	SecretK8sKubeconfig        = "k8s-kubeconfig"        //nolint:gosec // Test fixture, not real credentials

	// Test endpoints for OpenStack regions.
	EndpointOpenStackTest = "https://test.example.com:5000"
	EndpointOpenStackMain = "https://openstack.example.com:5000"
)

const (
	// Pact state names - these must match the consumer contract states.
	// Used by compute provider tests.
	StateOrganizationExists          = "organization exists"
	StateOrganizationHasRegions      = "organization has regions"
	StateOrganizationHasNoRegions    = "organization has no regions"
	StateOrganizationDoesNotExist    = "organization does not exist"
	StateOrganizationHasMixedRegions = "organization has mixed regions"

	// Used by kubernetes provider tests.
	StateRegionExists                  = "region exists"
	StateProjectExistsInRegion         = "project exists in region"
	StateServerExistsInProject         = "server exists in project"
	StateIdentityExists                = "identity exists"
	StateIdentityExistsWithPhysicalNet = "identity exists with physical network support"
	StateIdentityIsProvisioned         = "identity is provisioned"
	StateNetworkIsProvisioned          = "network is provisioned"
	StateRegionHasExternalNetworks     = "region has external networks"
	StateRegionHasFlavors              = "region has flavors"
	StateRegionHasImages               = "region has images"

	// State parameter keys.
	ParamOrganizationID = "organizationID"
	ParamProjectID      = "projectID"
	ParamRegionID       = "regionID"
	ParamServerID       = "serverID"
	ParamIdentityID     = "identityID"
	ParamNetworkID      = "networkID"
	ParamRegionType     = "regionType"
	ParamRegionCount    = "regionCount"

	// Region type parameter values.
	RegionTypeOpenStack  = "openstack"
	RegionTypeKubernetes = "kubernetes"
	RegionTypeMixed      = "mixed"
)

var (
	// ErrUnknownState is returned when an unknown state is requested.
	ErrUnknownState = errors.New("unknown state")

	// ErrUnknownRegionType is returned when an unknown region type is specified.
	ErrUnknownRegionType = errors.New("unknown region type")

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

	return DefaultTestNamespace
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

// RegionBuilder builds test regions following the builder pattern.
// This eliminates code duplication and makes region creation consistent.
type RegionBuilder struct {
	region *unikornv1.Region
}

// newRegionBuilder creates a new region builder with basic metadata.
func newRegionBuilder(name, namespace string) *RegionBuilder {
	return &RegionBuilder{
		region: &unikornv1.Region{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				Labels: map[string]string{
					coreconstants.NameLabel: name,
				},
			},
		},
	}
}

// withOpenStack configures the region as OpenStack type.
func (b *RegionBuilder) withOpenStack(endpoint, secretName string) *RegionBuilder {
	b.region.Spec.Provider = unikornv1.ProviderOpenstack
	b.region.Spec.Openstack = &unikornv1.RegionOpenstackSpec{
		Endpoint: endpoint,
		ServiceAccountSecret: &unikornv1.NamespacedObject{
			Namespace: b.region.Namespace,
			Name:      secretName,
		},
	}

	return b
}

// withKubernetes configures the region as Kubernetes type.
func (b *RegionBuilder) withKubernetes(kubeconfigSecret string) *RegionBuilder{
	b.region.Spec.Provider = unikornv1.ProviderKubernetes
	b.region.Spec.Kubernetes = &unikornv1.RegionKubernetesSpec{
		KubeconfigSecret: &unikornv1.NamespacedObject{
			Namespace: b.region.Namespace,
			Name:      kubeconfigSecret,
		},
	}

	return b
}

// build returns the configured region.
func (b *RegionBuilder) build() *unikornv1.Region {
	return b.region
}

// HandleRegionExistsState sets up a test region for uni-kubernetes tests.
func (sm *StateManager) HandleRegionExistsState(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	regionID := getStringParam(actualParams, ParamRegionID, TestRegionID)

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
	regionID := getStringParam(actualParams, ParamRegionID, TestRegionID)
	projectID := getStringParam(actualParams, ParamProjectID, TestProjectID)

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
	regionID := getStringParam(actualParams, ParamRegionID, TestRegionID)
	projectID := getStringParam(actualParams, ParamProjectID, TestProjectID)
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
	projectID := getStringParam(actualParams, ParamProjectID, TestProjectID)
	identityID := getStringParam(actualParams, ParamIdentityID, "test-identity-id")
	organizationID := getStringParam(actualParams, ParamOrganizationID, TestOrganizationID)

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
	projectID := getStringParam(actualParams, ParamProjectID, TestProjectID)
	identityID := getStringParam(actualParams, ParamIdentityID, "test-identity-id")
	organizationID := getStringParam(actualParams, ParamOrganizationID, TestOrganizationID)

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
	projectID := getStringParam(actualParams, ParamProjectID, TestProjectID)
	identityID := getStringParam(actualParams, ParamIdentityID, "test-identity-id")
	organizationID := getStringParam(actualParams, ParamOrganizationID, TestOrganizationID)

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
	projectID := getStringParam(actualParams, ParamProjectID, TestProjectID)
	identityID := getStringParam(actualParams, ParamIdentityID, "test-identity-id")
	networkID := getStringParam(actualParams, ParamNetworkID, "test-network-id")
	organizationID := getStringParam(actualParams, ParamOrganizationID, TestOrganizationID)

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
	regionID := getStringParam(actualParams, ParamRegionID, TestRegionID)
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
	regionID := getStringParam(actualParams, ParamRegionID, TestRegionID)

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
	regionID := getStringParam(actualParams, ParamRegionID, TestRegionID)
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
	orgID := getStringParam(actualParams, ParamOrganizationID, TestOrganizationID)

	fmt.Printf(">>> State handler: HandleOrganizationHasRegionsState(setup=%v, orgID=%s)\n", setup, orgID)

	if setup {
		// Create a test region for this organization
		return sm.regionManager.setupRegionWithOrg(ctx, TestRegionID, orgID)
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

// HandleOrganizationState is the main parameterized state handler for compute tests.
// It uses state parameters to determine what setup to perform.
func (sm *StateManager) HandleOrganizationState(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	orgID := getStringParam(actualParams, ParamOrganizationID, "test-org")
	regionType := getStringParam(actualParams, ParamRegionType, "")

	fmt.Printf(">>> State handler: HandleOrganizationState(setup=%v, orgID=%s, regionType=%s)\n", setup, orgID, regionType)

	if setup {
		return sm.setupRegions(ctx, orgID, regionType)
	}

	fmt.Printf("Cleaning up regions for org %s\n", orgID)

	return sm.cleanupAllResources(ctx)
}

// setupRegions creates regions based on the regionType parameter.
func (sm *StateManager) setupRegions(ctx context.Context, orgID, regionType string) error {
	if err := sm.regionManager.cleanupAllRegions(ctx); err != nil {
		return err
	}

	switch regionType {
	case RegionTypeOpenStack:
		return sm.createOpenStackRegion(ctx, orgID)
	case RegionTypeKubernetes:
		return sm.createKubernetesRegion(ctx, orgID)
	case RegionTypeMixed:
		return sm.createMixedRegions(ctx, orgID)
	case "":
		fmt.Printf("No regions to create for org %s\n", orgID)
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrUnknownRegionType, regionType)
	}
}

// createOpenStackRegion creates a single OpenStack region.
func (sm *StateManager) createOpenStackRegion(ctx context.Context, orgID string) error {
	fmt.Printf("Creating OpenStack region %s for org %s\n", RegionUSWest1, orgID)

	region := newRegionBuilder(RegionUSWest1, sm.namespace).
		withOpenStack(EndpointOpenStackTest, SecretTestCredentials).
		build()

	return sm.regionManager.createRegion(ctx, region)
}

// createKubernetesRegion creates a single Kubernetes region.
func (sm *StateManager) createKubernetesRegion(ctx context.Context, orgID string) error {
	fmt.Printf("Creating Kubernetes region %s for org %s\n", RegionKubernetes, orgID)

	region := newRegionBuilder(RegionKubernetes, sm.namespace).
		withKubernetes(SecretK8sKubeconfig).
		build()

	return sm.regionManager.createRegion(ctx, region)
}

// createMixedRegions creates both OpenStack and Kubernetes regions.
func (sm *StateManager) createMixedRegions(ctx context.Context, orgID string) error {
	fmt.Printf("Creating mixed regions for org %s\n", orgID)

	// Create OpenStack region
	openstackRegion := newRegionBuilder(RegionOpenStack, sm.namespace).
		withOpenStack(EndpointOpenStackMain, SecretOpenStackCredentials).
		build()

	if err := sm.regionManager.createRegion(ctx, openstackRegion); err != nil {
		return err
	}

	// Create Kubernetes region
	k8sRegion := newRegionBuilder(RegionKubernetes, sm.namespace).
		withKubernetes(SecretK8sKubeconfig).
		build()

	return sm.regionManager.createRegion(ctx, k8sRegion)
}
