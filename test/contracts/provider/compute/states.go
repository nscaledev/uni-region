/*
Copyright 2024-2025 the Unikorn Authors.

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
	"time"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
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
		namespace: "default",
	}
}

// HandleOrganizationWithOpenStackRegions sets up regions with OpenStack provider.
// Note: The region service doesn't actually filter by organization - it returns all regions in the namespace.
// The organizationID is only used for RBAC checks, not for filtering regions.
func (sm *StateManager) HandleOrganizationWithOpenStackRegions(ctx context.Context, setup bool, orgID string) error {
	if setup {
		// Clean up any existing test regions first
		if err := sm.cleanupAllRegions(ctx); err != nil {
			return err
		}

		// Create a simple OpenStack region with minimal required fields
		return sm.createRegion(ctx, &unikornv1.Region{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "us-west-1",
				Namespace: sm.namespace,
				Labels: map[string]string{
					constants.NameLabel: "us-west-1",
				},
			},
			Spec: unikornv1.RegionSpec{
				Provider: unikornv1.ProviderOpenstack,
				Openstack: &unikornv1.RegionOpenstackSpec{
					Endpoint: "https://test.example.com:5000",
					ServiceAccountSecret: &unikornv1.NamespacedObject{
						Namespace: sm.namespace,
						Name:      "test-credentials",
					},
				},
			},
		})
	}

	return sm.cleanupAllRegions(ctx)
}

// HandleOrganizationWithNoRegions ensures no regions exist.
func (sm *StateManager) HandleOrganizationWithNoRegions(ctx context.Context, setup bool, orgID string) error {
	if setup {
		// Just ensure all regions are deleted
		return sm.cleanupAllRegions(ctx)
	}

	return nil
}

// HandleOrganizationDoesNotExist ensures no regions exist.
// Note: In the actual API, if an organization doesn't exist, the RBAC check fails.
// But for contract testing without auth, we just return an empty list (200).
// The consumer test expects a 404, which indicates a discrepancy between
// the consumer expectations and provider behavior.
func (sm *StateManager) HandleOrganizationDoesNotExist(ctx context.Context, setup bool, orgID string) error {
	if setup {
		// Ensure no regions exist - this will result in a 200 with empty list
		// NOT a 404 as the consumer expects, which will cause verification to fail
		// This is correct - it highlights the contract mismatch
		return sm.cleanupAllRegions(ctx)
	}

	return nil
}

// HandleOrganizationExists sets up a basic state with no regions.
func (sm *StateManager) HandleOrganizationExists(ctx context.Context, setup bool, orgID string) error {
	if setup {
		// Ensure no regions exist
		return sm.cleanupAllRegions(ctx)
	}

	return nil
}

// HandleOrganizationWithMixedRegions sets up both OpenStack and Kubernetes regions.
func (sm *StateManager) HandleOrganizationWithMixedRegions(ctx context.Context, setup bool, orgID string) error {
	if setup {
		// Clean up first
		if err := sm.cleanupAllRegions(ctx); err != nil {
			return err
		}

		// Create OpenStack region with required fields
		if err := sm.createRegion(ctx, &unikornv1.Region{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "openstack-region",
				Namespace: sm.namespace,
				Labels: map[string]string{
					constants.NameLabel: "openstack-region",
				},
			},
			Spec: unikornv1.RegionSpec{
				Provider: unikornv1.ProviderOpenstack,
				Openstack: &unikornv1.RegionOpenstackSpec{
					Endpoint: "https://openstack.example.com:5000",
					ServiceAccountSecret: &unikornv1.NamespacedObject{
						Namespace: sm.namespace,
						Name:      "openstack-credentials",
					},
				},
			},
		}); err != nil {
			return err
		}

		// Create Kubernetes region with required fields
		return sm.createRegion(ctx, &unikornv1.Region{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "k8s-region",
				Namespace: sm.namespace,
				Labels: map[string]string{
					constants.NameLabel: "k8s-region",
				},
			},
			Spec: unikornv1.RegionSpec{
				Provider: unikornv1.ProviderKubernetes,
				Kubernetes: &unikornv1.RegionKubernetesSpec{
					KubeconfigSecret: &unikornv1.NamespacedObject{
						Namespace: sm.namespace,
						Name:      "k8s-kubeconfig",
					},
				},
			},
		})
	}

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

	// Read the region back to ensure it has a UID assigned by Kubernetes
	// This is important because ResourceReadMetadata uses the UID for the ID field
	createdRegion := &unikornv1.Region{}
	if err := sm.client.Get(ctx, client.ObjectKey{Namespace: sm.namespace, Name: region.Name}, createdRegion); err != nil {
		return fmt.Errorf("failed to read created region %s: %w", region.Name, err)
	}

	// Copy the UID and other metadata back to the original region object
	region.UID = createdRegion.UID
	region.ResourceVersion = createdRegion.ResourceVersion

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

	// Delete each region
	for i := range regionList.Items {
		region := &regionList.Items[i]
		if err := sm.client.Delete(ctx, region); err != nil {
			fmt.Printf("Warning: failed to delete region %s: %v\n", region.Name, err)
		}
	}

	return nil
}
