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

// HandleOrganizationWithOpenStackRegions sets up regions with OpenStack provider.
// Note: The region service doesn't actually filter by organization - it returns all regions in the namespace.
// The organizationID is only used for RBAC checks, not for filtering regions.
func (sm *StateManager) HandleOrganizationWithOpenStackRegions(ctx context.Context, setup bool, orgID string) error {
	fmt.Printf(">>> State handler: HandleOrganizationWithOpenStackRegions(setup=%v, orgID=%s)\n", setup, orgID)

	if setup {
		// Clean up any existing test regions first
		if err := sm.cleanupAllRegions(ctx); err != nil {
			return err
		}

		fmt.Printf("Creating OpenStack region %s for org %s\n", regionUSWest1, orgID)

		// Create a simple OpenStack region with minimal required fields
		region := newRegionBuilder(regionUSWest1, sm.namespace).
			withOpenStack(endpointOpenStackTest, secretTestCredentials).
			build()

		return sm.createRegion(ctx, region)
	}

	fmt.Printf("Cleaning up regions for org %s\n", orgID)

	return sm.cleanupAllRegions(ctx)
}

// HandleOrganizationWithNoRegions ensures no regions exist.
func (sm *StateManager) HandleOrganizationWithNoRegions(ctx context.Context, setup bool, orgID string) error {
	fmt.Printf(">>> State handler: HandleOrganizationWithNoRegions(setup=%v, orgID=%s)\n", setup, orgID)

	if setup {
		fmt.Printf("Ensuring no regions exist for org %s\n", orgID)
		// Just ensure all regions are deleted
		return sm.cleanupAllRegions(ctx)
	}

	return nil
}

// HandleOrganizationDoesNotExist ensures no regions exist.
func (sm *StateManager) HandleOrganizationDoesNotExist(ctx context.Context, setup bool, orgID string) error {
	fmt.Printf(">>> State handler: HandleOrganizationDoesNotExist(setup=%v, orgID=%s)\n", setup, orgID)

	if setup {
		fmt.Printf("Setting up non-existent org state for org %s (empty region list)\n", orgID)
		return sm.cleanupAllRegions(ctx)
	}

	return nil
}

// HandleOrganizationExists sets up a basic state with no regions.
func (sm *StateManager) HandleOrganizationExists(ctx context.Context, setup bool, orgID string) error {
	fmt.Printf(">>> State handler: HandleOrganizationExists(setup=%v, orgID=%s)\n", setup, orgID)

	if setup {
		fmt.Printf("Setting up basic state for org %s (no regions)\n", orgID)
		// Ensure no regions exist
		return sm.cleanupAllRegions(ctx)
	}

	return nil
}

// HandleOrganizationWithMixedRegions sets up both OpenStack and Kubernetes regions.
func (sm *StateManager) HandleOrganizationWithMixedRegions(ctx context.Context, setup bool, orgID string) error {
	fmt.Printf(">>> State handler: HandleOrganizationWithMixedRegions(setup=%v, orgID=%s)\n", setup, orgID)

	if setup {
		// Clean up first
		if err := sm.cleanupAllRegions(ctx); err != nil {
			return err
		}

		fmt.Printf("Creating OpenStack region %s for org %s\n", regionOpenStack, orgID)

		// Create OpenStack region using builder
		openstackRegion := newRegionBuilder(regionOpenStack, sm.namespace).
			withOpenStack(endpointOpenStackMain, secretOpenStackCredentials).
			build()

		if err := sm.createRegion(ctx, openstackRegion); err != nil {
			return err
		}

		fmt.Printf("Creating Kubernetes region %s for org %s\n", regionKubernetes, orgID)

		// Create Kubernetes region using builder
		k8sRegion := newRegionBuilder(regionKubernetes, sm.namespace).
			withKubernetes(secretK8sKubeconfig).
			build()

		return sm.createRegion(ctx, k8sRegion)
	}

	fmt.Printf("Cleaning up mixed regions for org %s\n", orgID)

	return sm.cleanupAllRegions(ctx)
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
