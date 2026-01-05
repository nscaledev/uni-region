/*
Copyright 2025 the Unikorn Authors.

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

package compute_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// defaultTestNamespace is the default namespace for contract testing resources.
	defaultTestNamespace = "default"

	// Region names.
	regionUSWest1    = "us-west-1"
	regionOpenStack  = "openstack-region"
	regionKubernetes = "k8s-region"

	// Secret names for test fixtures.
	secretTestCredentials      = "test-credentials"
	secretOpenStackCredentials = "openstack-credentials" //nolint:gosec // Test fixture, not real credentials
	secretK8sKubeconfig        = "k8s-kubeconfig"        //nolint:gosec // Test fixture, not real credentials

	// Endpoints.
	endpointOpenStackTest = "https://test.example.com:5000"
	endpointOpenStackMain = "https://openstack.example.com:5000"
)

const (
	// Pact state names - these must match the consumer contract states.
	StateOrganizationExists          = "organization exists"
	StateOrganizationHasRegions      = "organization has regions"
	StateOrganizationHasNoRegions    = "organization has no regions"
	StateOrganizationDoesNotExist    = "organization does not exist"
	StateOrganizationHasMixedRegions = "organization has mixed regions"

	// State parameter keys.
	ParamOrganizationID = "organizationID"
	ParamRegionType     = "regionType"
	ParamRegionCount    = "regionCount"

	// Region type parameter values.
	RegionTypeOpenStack  = "openstack"
	RegionTypeKubernetes = "kubernetes"
	RegionTypeMixed      = "mixed"
)

var (
	// ErrUnknownRegionType is returned when an unknown region type is specified.
	ErrUnknownRegionType = errors.New("unknown region type")
)

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
// It can be overridden via TEST_NAMESPACE environment variable.
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
					constants.NameLabel: name,
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
func (b *RegionBuilder) withKubernetes(kubeconfigSecret string) *RegionBuilder {
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

// HandleOrganizationState is the main parameterized state handler.
// It uses state parameters to determine what setup to perform.
func (sm *StateManager) HandleOrganizationState(ctx context.Context, setup bool, params map[string]interface{}) error {
	// Pact wraps parameters in a "params" key, so we need to unwrap them
	actualParams := params
	if wrappedParams, ok := params["params"].(map[string]interface{}); ok {
		actualParams = wrappedParams
	}

	orgID := getStringParam(actualParams, ParamOrganizationID, "test-org")
	regionType := getStringParam(actualParams, ParamRegionType, "")

	fmt.Printf(">>> State handler: HandleOrganizationState(setup=%v, orgID=%s, regionType=%s, params=%+v)\n",
		setup, orgID, regionType, params)

	if setup {
		// Clean up any existing test regions first
		if err := sm.cleanupAllRegions(ctx); err != nil {
			return err
		}

		// Create regions based on regionType parameter
		switch regionType {
		case RegionTypeOpenStack:
			return sm.createOpenStackRegion(ctx, orgID)
		case RegionTypeKubernetes:
			return sm.createKubernetesRegion(ctx, orgID)
		case RegionTypeMixed:
			return sm.createMixedRegions(ctx, orgID)
		case "":
			// No regions - just cleanup was done above
			fmt.Printf("No regions to create for org %s\n", orgID)
			return nil
		default:
			return fmt.Errorf("%w: %s", ErrUnknownRegionType, regionType)
		}
	}

	// Teardown - clean up all regions
	fmt.Printf("Cleaning up regions for org %s\n", orgID)

	return sm.cleanupAllRegions(ctx)
}

// createOpenStackRegion creates a single OpenStack region.
func (sm *StateManager) createOpenStackRegion(ctx context.Context, orgID string) error {
	fmt.Printf("Creating OpenStack region %s for org %s\n", regionUSWest1, orgID)

	region := newRegionBuilder(regionUSWest1, sm.namespace).
		withOpenStack(endpointOpenStackTest, secretTestCredentials).
		build()

	return sm.createRegion(ctx, region)
}

// createKubernetesRegion creates a single Kubernetes region.
func (sm *StateManager) createKubernetesRegion(ctx context.Context, orgID string) error {
	fmt.Printf("Creating Kubernetes region %s for org %s\n", regionKubernetes, orgID)

	region := newRegionBuilder(regionKubernetes, sm.namespace).
		withKubernetes(secretK8sKubeconfig).
		build()

	return sm.createRegion(ctx, region)
}

// createMixedRegions creates both OpenStack and Kubernetes regions.
func (sm *StateManager) createMixedRegions(ctx context.Context, orgID string) error {
	fmt.Printf("Creating mixed regions for org %s\n", orgID)

	// Create OpenStack region
	openstackRegion := newRegionBuilder(regionOpenStack, sm.namespace).
		withOpenStack(endpointOpenStackMain, secretOpenStackCredentials).
		build()

	if err := sm.createRegion(ctx, openstackRegion); err != nil {
		return err
	}

	// Create Kubernetes region
	k8sRegion := newRegionBuilder(regionKubernetes, sm.namespace).
		withKubernetes(secretK8sKubeconfig).
		build()

	return sm.createRegion(ctx, k8sRegion)
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
	// This is important because ResourceReadMetadata uses the UID for the ID field
	createdRegion := &unikornv1.Region{}
	if err := sm.client.Get(ctx, client.ObjectKey{Namespace: sm.namespace, Name: region.Name}, createdRegion); err != nil {
		return fmt.Errorf("failed to read created region %s: %w", region.Name, err)
	}

	// Copy the UID and other metadata back to the original region object
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
		// If the list fails (e.g., CRD doesn't exist), just log and continue
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
