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
	"fmt"
	"os"
	"time"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// RegionStateManager manages region setup and teardown for contract testing.
type RegionStateManager struct {
	client    client.Client
	namespace string
}

// NewRegionStateManager creates a new region state manager.
func NewRegionStateManager(client client.Client, namespace string) *RegionStateManager {
	return &RegionStateManager{
		client:    client,
		namespace: namespace,
	}
}

// setupRegionWithType creates a region based on the specified type.
// This implements provider-aware contracts where the consumer specifies which provider to test.
func (rm *RegionStateManager) setupRegionWithType(ctx context.Context, regionName string, regionType string) error {
	if regionType == "openstack" {
		return rm.setupOpenstackRegion(ctx, regionName)
	}

	return rm.setupRegion(ctx, regionName)
}

// setupRegion creates a Kubernetes region for testing.
func (rm *RegionStateManager) setupRegion(ctx context.Context, regionName string) error {
	// Clean up any existing regions first
	if err := rm.cleanupAllRegions(ctx); err != nil {
		return err
	}

	// Create kubeconfig secret so the Kubernetes provider can connect to the cluster
	if err := rm.createKubeconfigSecret(ctx); err != nil {
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
			Namespace: rm.namespace,
			Labels: map[string]string{
				coreconstants.NameLabel: "us-west-2", // Consumer expects this name
			},
		},
		Spec: unikornv1.RegionSpec{
			Provider: unikornv1.ProviderKubernetes, // Default to Kubernetes for simple tests
			Kubernetes: &unikornv1.RegionKubernetesSpec{
				KubeconfigSecret: &unikornv1.NamespacedObject{
					Namespace: rm.namespace,
					Name:      TestKubeconfigSecret,
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

	return rm.createRegion(ctx, region)
}

// setupRegionWithOrg creates an OpenStack region with organization label.
func (rm *RegionStateManager) setupRegionWithOrg(ctx context.Context, regionName, organizationID string) error {
	// Clean up any existing regions first
	if err := rm.cleanupAllRegions(ctx); err != nil {
		return err
	}

	// Create OpenStack service account secret
	if err := rm.createOpenstackServiceAccountSecret(ctx); err != nil {
		return err
	}

	fmt.Printf("Creating OpenStack region %s for organization %s\n", regionName, organizationID)

	region := &unikornv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      regionName,
			Namespace: rm.namespace,
			Labels: map[string]string{
				coreconstants.NameLabel:         "us-west-2", // Consumer expects this name
				coreconstants.OrganizationLabel: organizationID,
			},
		},
		Spec: unikornv1.RegionSpec{
			Provider: unikornv1.ProviderOpenstack,
			Openstack: &unikornv1.RegionOpenstackSpec{
				ServiceAccountSecret: &unikornv1.NamespacedObject{
					Namespace: rm.namespace,
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

	return rm.createRegion(ctx, region)
}

// setupOpenstackRegion creates an OpenStack region for tests that need OpenStack provider.
func (rm *RegionStateManager) setupOpenstackRegion(ctx context.Context, regionName string) error {
	// Clean up any existing regions first
	if err := rm.cleanupAllRegions(ctx); err != nil {
		return err
	}

	// Create OpenStack service account secret
	if err := rm.createOpenstackServiceAccountSecret(ctx); err != nil {
		return err
	}

	fmt.Printf("Creating OpenStack region %s for uni-kubernetes tests\n", regionName)

	region := &unikornv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      regionName,
			Namespace: rm.namespace,
			Labels: map[string]string{
				coreconstants.NameLabel: "us-west-2",
			},
		},
		Spec: unikornv1.RegionSpec{
			Provider: unikornv1.ProviderOpenstack,
			Openstack: &unikornv1.RegionOpenstackSpec{
				ServiceAccountSecret: &unikornv1.NamespacedObject{
					Namespace: rm.namespace,
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

	return rm.createRegion(ctx, region)
}

// createMockNodes creates mock Kubernetes nodes for flavor testing.
// These nodes have the node-class label that the provider uses to discover flavors.
func (rm *RegionStateManager) createMockNodes(ctx context.Context) error {
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

	if err := rm.client.Create(ctx, standardNode); err != nil {
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

	if err := rm.client.Create(ctx, gpuNode); err != nil {
		return fmt.Errorf("failed to create GPU node: %w", err)
	}

	fmt.Printf("Created mock node %s with class %s\n", gpuNode.Name, nodeClassToUUID("gpu-node"))

	return nil
}

// cleanupMockNodes deletes all mock nodes created for testing.
func (rm *RegionStateManager) cleanupMockNodes(ctx context.Context) {
	nodeList := &corev1.NodeList{}

	// List all nodes
	if err := rm.client.List(ctx, nodeList); err != nil {
		fmt.Printf("Warning: failed to list nodes: %v\n", err)
		return
	}

	// Delete test nodes
	deletedCount := 0

	for i := range nodeList.Items {
		node := &nodeList.Items[i]
		// Only delete our test nodes
		if node.Name == "test-node-standard-4" || node.Name == "test-node-gpu" {
			if err := rm.client.Delete(ctx, node); err != nil {
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

// createOpenstackServiceAccountSecret creates a mock OpenStack service account secret.
func (rm *RegionStateManager) createOpenstackServiceAccountSecret(ctx context.Context) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "openstack-service-account",
			Namespace: rm.namespace,
		},
		StringData: map[string]string{
			"domain-id":  "default",
			"user-id":    "mock-user-id",
			"password":   "mock-password",
			"project-id": "mock-project-id",
		},
	}

	// Try to create the secret, ignore if it already exists
	if err := rm.client.Create(ctx, secret); err != nil {
		// Check if error is "already exists"
		if !kerrors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create openstack service account secret: %w", err)
		}
	}

	return nil
}

// createKubeconfigSecret creates a secret containing the current kubeconfig.
// This allows the Kubernetes provider to connect back to the kind cluster for flavor discovery.
func (rm *RegionStateManager) createKubeconfigSecret(ctx context.Context) error {
	// Get the kubeconfig path
	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath == "" {
		kubeconfigPath = clientcmd.RecommendedHomeFile
	}

	// Load and serialize the kubeconfig
	config, err := clientcmd.LoadFromFile(kubeconfigPath)
	if err != nil {
		return fmt.Errorf("failed to load kubeconfig from %s: %w", kubeconfigPath, err)
	}

	kubeconfigBytes, err := clientcmd.Write(*config)
	if err != nil {
		return fmt.Errorf("failed to serialize kubeconfig: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      TestKubeconfigSecret,
			Namespace: rm.namespace,
		},
		Data: map[string][]byte{
			"kubeconfig": kubeconfigBytes,
		},
	}

	if err := rm.client.Create(ctx, secret); err != nil {
		if !kerrors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create kubeconfig secret: %w", err)
		}
	}

	return nil
}

// createRegion creates a region resource in Kubernetes.
func (rm *RegionStateManager) createRegion(ctx context.Context, region *unikornv1.Region) error {
	// Set creation timestamp
	now := metav1.NewTime(time.Now())
	region.CreationTimestamp = now

	// Try to create the region
	if err := rm.client.Create(ctx, region); err != nil {
		return fmt.Errorf("failed to create region %s: %w", region.Name, err)
	}

	fmt.Printf("Created region %s in namespace %s\n", region.Name, rm.namespace)

	// Read the region back to ensure it has a UID assigned by Kubernetes
	createdRegion := &unikornv1.Region{}
	if err := rm.client.Get(ctx, client.ObjectKey{Namespace: rm.namespace, Name: region.Name}, createdRegion); err != nil {
		return fmt.Errorf("failed to read created region %s: %w", region.Name, err)
	}

	// Copy the UID and other metadata back
	region.UID = createdRegion.UID
	region.ResourceVersion = createdRegion.ResourceVersion

	fmt.Printf("Region %s assigned UID: %s\n", region.Name, region.UID)

	return nil
}

// cleanupAllRegions deletes all regions in the namespace.
func (rm *RegionStateManager) cleanupAllRegions(ctx context.Context) error {
	regionList := &unikornv1.RegionList{}

	// List all regions in the namespace
	if err := rm.client.List(ctx, regionList, client.InNamespace(rm.namespace)); err != nil {
		fmt.Printf("Warning: failed to list regions in namespace %s: %v\n", rm.namespace, err)
		return nil
	}

	if len(regionList.Items) == 0 {
		fmt.Printf("No regions to clean up in namespace %s\n", rm.namespace)
		return nil
	}

	fmt.Printf("Cleaning up %d region(s) in namespace %s\n", len(regionList.Items), rm.namespace)

	// Delete each region
	for i := range regionList.Items {
		region := &regionList.Items[i]
		if err := rm.client.Delete(ctx, region); err != nil {
			fmt.Printf("Warning: failed to delete region %s: %v\n", region.Name, err)
		} else {
			fmt.Printf("Deleted region %s\n", region.Name)
		}
	}

	return nil
}
