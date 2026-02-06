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
	"fmt"
	"net"
	"time"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// IdentityStateManager manages identity and network setup for contract testing.
type IdentityStateManager struct {
	client    client.Client
	namespace string
}

// NewIdentityStateManager creates a new identity state manager.
func NewIdentityStateManager(client client.Client, namespace string) *IdentityStateManager {
	return &IdentityStateManager{
		client:    client,
		namespace: namespace,
	}
}

// setupIdentity creates a test identity resource with OpenStack provider for contract testing.
func (im *IdentityStateManager) setupIdentity(ctx context.Context, identityName, projectID string, regionID string, organizationID string) error {
	fmt.Printf("Creating identity %s for project %s in region %s\n", identityName, projectID, regionID)

	// Create main Identity CRD with OpenStack provider
	identity := &unikornv1.Identity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      identityName,
			Namespace: im.namespace,
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

	if err := im.client.Create(ctx, identity); err != nil {
		return fmt.Errorf("failed to create identity %s: %w", identityName, err)
	}

	// Create OpenstackIdentity CRD with mock data for contract testing
	// Use values that match consumer contract expectations
	openstackIdentity := &unikornv1.OpenstackIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      identityName,
			Namespace: im.namespace,
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

	if err := im.client.Create(ctx, openstackIdentity); err != nil {
		return fmt.Errorf("failed to create openstack identity %s: %w", identityName, err)
	}

	fmt.Printf("Created identity %s with OpenStack provider\n", identityName)

	return nil
}

// setupProvisionedIdentity creates a provisioned test identity resource.
func (im *IdentityStateManager) setupProvisionedIdentity(ctx context.Context, identityName, projectID, regionID, organizationID string) error {
	if err := im.setupIdentity(ctx, identityName, projectID, regionID, organizationID); err != nil {
		return err
	}

	// Update status to mark as provisioned
	identity := &unikornv1.Identity{}
	if err := im.client.Get(ctx, client.ObjectKey{Namespace: im.namespace, Name: identityName}, identity); err != nil {
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

	if err := im.client.Status().Update(ctx, identity); err != nil {
		fmt.Printf("Warning: failed to update identity status: %v\n", err)
	}

	fmt.Printf("Identity %s marked as provisioned\n", identityName)

	return nil
}

// setupProvisionedNetwork creates a provisioned test network resource.
func (im *IdentityStateManager) setupProvisionedNetwork(ctx context.Context, networkName, identityID, projectID, regionID, organizationID string) error {
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
			Namespace: im.namespace,
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

	if err := im.client.Create(ctx, network); err != nil {
		return fmt.Errorf("failed to create network %s: %w", networkName, err)
	}

	// Update status to mark as provisioned with OpenStack data for contract testing
	if err := im.client.Get(ctx, client.ObjectKey{Namespace: im.namespace, Name: networkName}, network); err != nil {
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

	if err := im.client.Status().Update(ctx, network); err != nil {
		fmt.Printf("Warning: failed to update network status: %v\n", err)
	}

	fmt.Printf("Created and provisioned network %s with OpenStack status\n", networkName)

	return nil
}

// cleanupIdentitiesAndNetworks cleans up all identity and network resources.
func (im *IdentityStateManager) cleanupIdentitiesAndNetworks(ctx context.Context) error {
	// Clean up networks
	networkList := &unikornv1.NetworkList{}
	if err := im.client.List(ctx, networkList, client.InNamespace(im.namespace)); err == nil {
		for i := range networkList.Items {
			network := &networkList.Items[i]
			if err := im.client.Delete(ctx, network); err != nil {
				fmt.Printf("Warning: failed to delete network %s: %v\n", network.Name, err)
			} else {
				fmt.Printf("Deleted network %s\n", network.Name)
			}
		}
	}

	// Clean up openstack identities
	openstackIdentityList := &unikornv1.OpenstackIdentityList{}
	if err := im.client.List(ctx, openstackIdentityList, client.InNamespace(im.namespace)); err == nil {
		for i := range openstackIdentityList.Items {
			openstackIdentity := &openstackIdentityList.Items[i]
			if err := im.client.Delete(ctx, openstackIdentity); err != nil {
				fmt.Printf("Warning: failed to delete openstack identity %s: %v\n", openstackIdentity.Name, err)
			} else {
				fmt.Printf("Deleted openstack identity %s\n", openstackIdentity.Name)
			}
		}
	}

	// Clean up identities
	identityList := &unikornv1.IdentityList{}
	if err := im.client.List(ctx, identityList, client.InNamespace(im.namespace)); err == nil {
		for i := range identityList.Items {
			identity := &identityList.Items[i]
			if err := im.client.Delete(ctx, identity); err != nil {
				fmt.Printf("Warning: failed to delete identity %s: %v\n", identity.Name, err)
			} else {
				fmt.Printf("Deleted identity %s\n", identity.Name)
			}
		}
	}

	return nil
}
