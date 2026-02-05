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
	"net"
	"os"
	"time"

	"github.com/google/uuid"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

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

// StateManager handles setting up and tearing down state for contract verification.
type StateManager struct {
	client    client.Client
	namespace string
}

// NewStateManager creates a new state manager.
func NewStateManager(client client.Client) *StateManager {
	return &StateManager{
		client:    client,
		namespace: getTestNamespace(),
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
		return sm.setupOpenstackRegion(ctx, regionID)
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
		return sm.setupOpenstackRegion(ctx, regionID)
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
		return sm.setupRegion(ctx, regionID)
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
		if err := sm.setupRegion(ctx, regionID); err != nil {
			return err
		}
		// Create a test identity
		return sm.setupIdentity(ctx, identityID, projectID, regionID, organizationID)
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
		if err := sm.setupRegion(ctx, regionID); err != nil {
			return err
		}
		// Create a test identity with physical network support
		return sm.setupIdentity(ctx, identityID, projectID, regionID, organizationID)
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
		if err := sm.setupRegion(ctx, regionID); err != nil {
			return err
		}
		// Create a provisioned test identity
		return sm.setupProvisionedIdentity(ctx, identityID, projectID, regionID, organizationID)
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
		if err := sm.setupRegion(ctx, regionID); err != nil {
			return err
		}
		// Create a provisioned test identity
		if err := sm.setupProvisionedIdentity(ctx, identityID, projectID, regionID, organizationID); err != nil {
			return err
		}
		// Create a provisioned test network
		return sm.setupProvisionedNetwork(ctx, networkID, identityID, projectID, regionID, organizationID)
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
		return sm.setupRegionWithType(ctx, regionID, regionType)
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
		if err := sm.setupRegion(ctx, regionID); err != nil {
			return err
		}
		// Create mock nodes for flavor testing
		return sm.createMockNodes(ctx)
	}

	// Cleanup both nodes and regions
	sm.cleanupMockNodes(ctx)

	return sm.cleanupAllResources(ctx)
}

// HandleRegionHasImagesState sets up state for listing images.
func (sm *StateManager) HandleRegionHasImagesState(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	regionID := getStringParam(actualParams, ParamRegionID, testRegionID)
	regionType := getStringParam(actualParams, "regionType", "kubernetes")

	fmt.Printf(">>> State handler: HandleRegionHasImagesState(setup=%v, regionID=%s, regionType=%s)\n", setup, regionID, regionType)

	if setup {
		return sm.setupRegionWithType(ctx, regionID, regionType)
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
		return sm.setupRegionWithOrg(ctx, testRegionID, orgID)
	}

	return sm.cleanupAllResources(ctx)
}

// createOpenstackServiceAccountSecret creates a mock OpenStack service account secret.
func (sm *StateManager) createOpenstackServiceAccountSecret(ctx context.Context) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "openstack-service-account",
			Namespace: sm.namespace,
		},
		StringData: map[string]string{
			"domain-id":  "default",
			"user-id":    "mock-user-id",
			"password":   "mock-password",
			"project-id": "mock-project-id",
		},
	}

	// Try to create the secret, ignore if it already exists
	if err := sm.client.Create(ctx, secret); err != nil {
		// Check if error is "already exists"
		if !kerrors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create openstack service account secret: %w", err)
		}
	}

	return nil
}

// setupRegionWithType creates a region based on the specified type.
// This implements provider-aware contracts where the consumer specifies which provider to test.
func (sm *StateManager) setupRegionWithType(ctx context.Context, regionName string, regionType string) error {
	if regionType == "openstack" {
		return sm.setupOpenstackRegion(ctx, regionName)
	}

	return sm.setupRegion(ctx, regionName)
}

// setupRegion creates a Kubernetes region for testing.
func (sm *StateManager) setupRegion(ctx context.Context, regionName string) error {
	// Clean up any existing regions first
	if err := sm.cleanupAllRegions(ctx); err != nil {
		return err
	}

	fmt.Printf("Creating Kubernetes region %s for uni-kubernetes tests\n", regionName)

	// Create a region with mock node configurations for flavor testing
	cpuCount := 4
	gpuPhysicalCount := 1
	gpuLogicalCount := 1

	memory8Gi := resource.MustParse("8Gi")
	disk100Gi := resource.MustParse("100Gi")
	memory16Gi := resource.MustParse("16Gi")
	disk200Gi := resource.MustParse("200Gi")

	region := &unikornv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      regionName,
			Namespace: sm.namespace,
			Labels: map[string]string{
				coreconstants.NameLabel: "us-west-2", // Consumer expects this name
			},
		},
		Spec: unikornv1.RegionSpec{
			Provider: unikornv1.ProviderKubernetes, // Default to Kubernetes for simple tests
			Kubernetes: &unikornv1.RegionKubernetesSpec{
				KubeconfigSecret: &unikornv1.NamespacedObject{
					Namespace: sm.namespace,
					Name:      testKubeconfigSecret,
				},
				// Add mock nodes for flavor testing
				// Use UUIDs for node IDs to match consumer contract expectations
				Nodes: []unikornv1.RegionKubernetesNodeSpec{
					{
						ID:   nodeClassToUUID("standard-4"),
						Name: "Standard 4 CPU",
						CPU: &unikornv1.CPUSpec{
							Count: &cpuCount,
						},
						Memory: &memory8Gi,
						Disk:   &disk100Gi,
					},
					{
						ID:   nodeClassToUUID("gpu-node"),
						Name: "GPU Node",
						CPU: &unikornv1.CPUSpec{
							Count: &cpuCount,
						},
						Memory: &memory16Gi,
						Disk:   &disk200Gi,
						GPU: &unikornv1.GPUSpec{
							Vendor:        "NVIDIA",
							Model:         "Tesla T4",
							Memory:        &memory16Gi,
							PhysicalCount: gpuPhysicalCount,
							LogicalCount:  gpuLogicalCount,
						},
					},
				},
			},
		},
	}

	return sm.createRegion(ctx, region)
}

// setupRegionWithOrg creates an OpenStack region with organization label.
func (sm *StateManager) setupRegionWithOrg(ctx context.Context, regionName, organizationID string) error {
	// Clean up any existing regions first
	if err := sm.cleanupAllRegions(ctx); err != nil {
		return err
	}

	// Create OpenStack service account secret
	if err := sm.createOpenstackServiceAccountSecret(ctx); err != nil {
		return err
	}

	fmt.Printf("Creating OpenStack region %s for organization %s\n", regionName, organizationID)

	region := &unikornv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      regionName,
			Namespace: sm.namespace,
			Labels: map[string]string{
				coreconstants.NameLabel:         "us-west-2", // Consumer expects this name
				coreconstants.OrganizationLabel: organizationID,
			},
		},
		Spec: unikornv1.RegionSpec{
			Provider: unikornv1.ProviderOpenstack,
			Openstack: &unikornv1.RegionOpenstackSpec{
				ServiceAccountSecret: &unikornv1.NamespacedObject{
					Namespace: sm.namespace,
					Name:      "openstack-service-account",
				},
				Network: &unikornv1.RegionOpenstackNetworkSpec{
					ProviderNetworks: &unikornv1.ProviderNetworks{
						Network: ptr.To("provider-network"),
					},
				},
			},
		},
	}

	return sm.createRegion(ctx, region)
}

// setupOpenstackRegion creates an OpenStack region for tests that need OpenStack provider.
func (sm *StateManager) setupOpenstackRegion(ctx context.Context, regionName string) error {
	// Clean up any existing regions first
	if err := sm.cleanupAllRegions(ctx); err != nil {
		return err
	}

	// Create OpenStack service account secret
	if err := sm.createOpenstackServiceAccountSecret(ctx); err != nil {
		return err
	}

	fmt.Printf("Creating OpenStack region %s for uni-kubernetes tests\n", regionName)

	region := &unikornv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      regionName,
			Namespace: sm.namespace,
			Labels: map[string]string{
				coreconstants.NameLabel: "us-west-2",
			},
		},
		Spec: unikornv1.RegionSpec{
			Provider: unikornv1.ProviderOpenstack,
			Openstack: &unikornv1.RegionOpenstackSpec{
				ServiceAccountSecret: &unikornv1.NamespacedObject{
					Namespace: sm.namespace,
					Name:      "openstack-service-account",
				},
				Network: &unikornv1.RegionOpenstackNetworkSpec{
					ProviderNetworks: &unikornv1.ProviderNetworks{
						Network: ptr.To("provider-network"),
					},
				},
			},
		},
	}

	return sm.createRegion(ctx, region)
}

// createMockNodes creates mock Kubernetes nodes for flavor testing.
// These nodes have the node-class label that the provider uses to discover flavors.
func (sm *StateManager) createMockNodes(ctx context.Context) error {
	const nodeClassLabel = "kubernetes.region.unikorn-cloud.org/node-class"

	// Create standard node with UUID label to match region spec
	standardNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node-standard-4",
			Labels: map[string]string{
				nodeClassLabel: nodeClassToUUID("standard-4"),
			},
		},
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("8Gi"),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("8Gi"),
			},
			Conditions: []corev1.NodeCondition{
				{
					Type:   corev1.NodeReady,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}

	if err := sm.client.Create(ctx, standardNode); err != nil {
		return fmt.Errorf("failed to create standard node: %w", err)
	}

	fmt.Printf("Created mock node %s with class %s\n", standardNode.Name, nodeClassToUUID("standard-4"))

	// Create GPU node with UUID label to match region spec
	gpuNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node-gpu",
			Labels: map[string]string{
				nodeClassLabel: nodeClassToUUID("gpu-node"),
			},
		},
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("16Gi"),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("16Gi"),
			},
			Conditions: []corev1.NodeCondition{
				{
					Type:   corev1.NodeReady,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}

	if err := sm.client.Create(ctx, gpuNode); err != nil {
		return fmt.Errorf("failed to create GPU node: %w", err)
	}

	fmt.Printf("Created mock node %s with class %s\n", gpuNode.Name, nodeClassToUUID("gpu-node"))

	return nil
}

// cleanupMockNodes deletes all mock nodes created for testing.
func (sm *StateManager) cleanupMockNodes(ctx context.Context) {
	nodeList := &corev1.NodeList{}

	// List all nodes
	if err := sm.client.List(ctx, nodeList); err != nil {
		fmt.Printf("Warning: failed to list nodes: %v\n", err)
		return
	}

	// Delete test nodes
	deletedCount := 0

	for i := range nodeList.Items {
		node := &nodeList.Items[i]
		// Only delete our test nodes
		if node.Name == "test-node-standard-4" || node.Name == "test-node-gpu" {
			if err := sm.client.Delete(ctx, node); err != nil {
				fmt.Printf("Warning: failed to delete node %s: %v\n", node.Name, err)
			} else {
				fmt.Printf("Deleted mock node %s\n", node.Name)

				deletedCount++
			}
		}
	}

	if deletedCount == 0 {
		fmt.Printf("No mock nodes to clean up\n")
	}
}

// createRegion creates a region resource in Kubernetes.
func (sm *StateManager) createRegion(ctx context.Context, region *unikornv1.Region) error {
	// Set creation timestamp
	now := metav1.NewTime(time.Now())
	region.CreationTimestamp = now

	// Try to create the region
	if err := sm.client.Create(ctx, region); err != nil {
		return fmt.Errorf("failed to create region %s: %w", region.Name, err)
	}

	fmt.Printf("Created region %s in namespace %s\n", region.Name, sm.namespace)

	// Read the region back to ensure it has a UID assigned by Kubernetes
	createdRegion := &unikornv1.Region{}
	if err := sm.client.Get(ctx, client.ObjectKey{Namespace: sm.namespace, Name: region.Name}, createdRegion); err != nil {
		return fmt.Errorf("failed to read created region %s: %w", region.Name, err)
	}

	// Copy the UID and other metadata back
	region.UID = createdRegion.UID
	region.ResourceVersion = createdRegion.ResourceVersion

	fmt.Printf("Region %s assigned UID: %s\n", region.Name, region.UID)

	return nil
}

// cleanupAllRegions deletes all regions in the namespace.
func (sm *StateManager) cleanupAllRegions(ctx context.Context) error {
	regionList := &unikornv1.RegionList{}

	// List all regions in the namespace
	if err := sm.client.List(ctx, regionList, client.InNamespace(sm.namespace)); err != nil {
		fmt.Printf("Warning: failed to list regions in namespace %s: %v\n", sm.namespace, err)
		return nil
	}

	if len(regionList.Items) == 0 {
		fmt.Printf("No regions to clean up in namespace %s\n", sm.namespace)
		return nil
	}

	fmt.Printf("Cleaning up %d region(s) in namespace %s\n", len(regionList.Items), sm.namespace)

	// Delete each region
	for i := range regionList.Items {
		region := &regionList.Items[i]
		if err := sm.client.Delete(ctx, region); err != nil {
			fmt.Printf("Warning: failed to delete region %s: %v\n", region.Name, err)
		} else {
			fmt.Printf("Deleted region %s\n", region.Name)
		}
	}

	return nil
}

// setupIdentity creates a test identity resource with OpenStack provider for contract testing.
func (sm *StateManager) setupIdentity(ctx context.Context, identityName, projectID string, regionID string, organizationID string) error {
	fmt.Printf("Creating identity %s for project %s in region %s\n", identityName, projectID, regionID)

	// Create main Identity CRD with OpenStack provider
	identity := &unikornv1.Identity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      identityName,
			Namespace: sm.namespace,
			Labels: map[string]string{
				coreconstants.NameLabel:         "kubernetes-cluster-test", // Consumer expects this name
				coreconstants.OrganizationLabel: organizationID,
				coreconstants.ProjectLabel:      projectID,
				constants.RegionLabel:           regionID,
			},
		},
		Spec: unikornv1.IdentitySpec{
			Provider: unikornv1.ProviderOpenstack, // Use OpenStack for contract testing
		},
	}

	if err := sm.client.Create(ctx, identity); err != nil {
		return fmt.Errorf("failed to create identity %s: %w", identityName, err)
	}

	// Create OpenstackIdentity CRD with mock data for contract testing
	// Use values that match consumer contract expectations
	openstackIdentity := &unikornv1.OpenstackIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      identityName,
			Namespace: sm.namespace,
			Labels: map[string]string{
				coreconstants.NameLabel:         "kubernetes-cluster-test",
				coreconstants.OrganizationLabel: organizationID,
				coreconstants.ProjectLabel:      projectID,
			},
		},
		Spec: unikornv1.OpenstackIdentitySpec{
			Cloud:         ptr.To("openstack"),
			UserID:        ptr.To("user-id"),
			ProjectID:     ptr.To("project-id"),
			ServerGroupID: ptr.To("server-group-id"),
			SSHKeyName:    ptr.To("ssh-key-name"),
			CloudConfig:   []byte("encoded-cloud-config"),
		},
	}

	if err := sm.client.Create(ctx, openstackIdentity); err != nil {
		return fmt.Errorf("failed to create openstack identity %s: %w", identityName, err)
	}

	fmt.Printf("Created identity %s with OpenStack provider\n", identityName)

	return nil
}

// setupProvisionedIdentity creates a provisioned test identity resource.
func (sm *StateManager) setupProvisionedIdentity(ctx context.Context, identityName, projectID, regionID, organizationID string) error {
	if err := sm.setupIdentity(ctx, identityName, projectID, regionID, organizationID); err != nil {
		return err
	}

	// Update status to mark as provisioned
	identity := &unikornv1.Identity{}
	if err := sm.client.Get(ctx, client.ObjectKey{Namespace: sm.namespace, Name: identityName}, identity); err != nil {
		return fmt.Errorf("failed to get identity %s: %w", identityName, err)
	}

	// Mark as provisioned
	now := metav1.NewTime(time.Now())
	identity.Status.Conditions = []unikornv1core.Condition{
		{
			Type:               unikornv1core.ConditionAvailable,
			Status:             corev1.ConditionTrue,
			Reason:             "Provisioned",
			LastTransitionTime: now,
		},
	}

	if err := sm.client.Status().Update(ctx, identity); err != nil {
		fmt.Printf("Warning: failed to update identity status: %v\n", err)
	}

	fmt.Printf("Identity %s marked as provisioned\n", identityName)

	return nil
}

// setupProvisionedNetwork creates a provisioned test network resource.
func (sm *StateManager) setupProvisionedNetwork(ctx context.Context, networkName, identityID, projectID, regionID, organizationID string) error {
	fmt.Printf("Creating network %s for identity %s\n", networkName, identityID)

	// Parse network prefix
	_, ipNet, err := net.ParseCIDR("192.168.0.0/24")
	if err != nil {
		return fmt.Errorf("failed to parse CIDR: %w", err)
	}

	// Parse DNS nameserver
	dnsIP := net.ParseIP("8.8.8.8")

	network := &unikornv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Name:      networkName,
			Namespace: sm.namespace,
			Labels: map[string]string{
				coreconstants.NameLabel:         networkName,
				coreconstants.OrganizationLabel: organizationID,
				coreconstants.ProjectLabel:      projectID,
				constants.RegionLabel:           regionID,
				constants.IdentityLabel:         identityID,
			},
		},
		Spec: unikornv1.NetworkSpec{
			Provider: unikornv1.ProviderOpenstack, // Use OpenStack for contract testing
			Prefix: &unikornv1core.IPv4Prefix{
				IPNet: *ipNet,
			},
			DNSNameservers: []unikornv1core.IPv4Address{
				{IP: dnsIP},
			},
		},
	}

	if err := sm.client.Create(ctx, network); err != nil {
		return fmt.Errorf("failed to create network %s: %w", networkName, err)
	}

	// Update status to mark as provisioned with OpenStack data for contract testing
	if err := sm.client.Get(ctx, client.ObjectKey{Namespace: sm.namespace, Name: networkName}, network); err != nil {
		return fmt.Errorf("failed to get network %s: %w", networkName, err)
	}

	now := metav1.NewTime(time.Now())
	network.Status.Conditions = []unikornv1core.Condition{
		{
			Type:               unikornv1core.ConditionAvailable,
			Status:             corev1.ConditionTrue,
			Reason:             "Provisioned",
			LastTransitionTime: now,
		},
	}

	// Add OpenStack-specific status for contract testing
	// Use values that match consumer contract expectations
	network.Status.Openstack = &unikornv1.NetworkStatusOpenstack{
		NetworkID: ptr.To("openstack-network-id"),
		SubnetID:  ptr.To("openstack-subnet-id"),
	}

	if err := sm.client.Status().Update(ctx, network); err != nil {
		fmt.Printf("Warning: failed to update network status: %v\n", err)
	}

	fmt.Printf("Created and provisioned network %s with OpenStack status\n", networkName)

	return nil
}

// cleanupAllResources deletes all test resources in the namespace.
func (sm *StateManager) cleanupAllResources(ctx context.Context) error {
	// Clean up networks
	networkList := &unikornv1.NetworkList{}
	if err := sm.client.List(ctx, networkList, client.InNamespace(sm.namespace)); err == nil {
		for i := range networkList.Items {
			network := &networkList.Items[i]
			if err := sm.client.Delete(ctx, network); err != nil {
				fmt.Printf("Warning: failed to delete network %s: %v\n", network.Name, err)
			} else {
				fmt.Printf("Deleted network %s\n", network.Name)
			}
		}
	}

	// Clean up openstack identities
	openstackIdentityList := &unikornv1.OpenstackIdentityList{}
	if err := sm.client.List(ctx, openstackIdentityList, client.InNamespace(sm.namespace)); err == nil {
		for i := range openstackIdentityList.Items {
			openstackIdentity := &openstackIdentityList.Items[i]
			if err := sm.client.Delete(ctx, openstackIdentity); err != nil {
				fmt.Printf("Warning: failed to delete openstack identity %s: %v\n", openstackIdentity.Name, err)
			} else {
				fmt.Printf("Deleted openstack identity %s\n", openstackIdentity.Name)
			}
		}
	}

	// Clean up identities
	identityList := &unikornv1.IdentityList{}
	if err := sm.client.List(ctx, identityList, client.InNamespace(sm.namespace)); err == nil {
		for i := range identityList.Items {
			identity := &identityList.Items[i]
			if err := sm.client.Delete(ctx, identity); err != nil {
				fmt.Printf("Warning: failed to delete identity %s: %v\n", identity.Name, err)
			} else {
				fmt.Printf("Deleted identity %s\n", identity.Name)
			}
		}
	}

	// Clean up regions
	return sm.cleanupAllRegions(ctx)
}
