/*
Copyright 2024-2025 the Unikorn Authors.
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

package v1alpha1

import (
	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"
)

// Paused implements the ReconcilePauser interface.
func (c *Identity) Paused() bool {
	return c.Spec.Pause
}

// StatusConditionRead scans the status conditions for an existing condition whose type
// matches.
func (c *Identity) StatusConditionRead(t unikornv1core.ConditionType) (*unikornv1core.Condition, error) {
	return unikornv1core.GetCondition(c.Status.Conditions, t)
}

// StatusConditionWrite either adds or updates a condition in the cluster manager status.
// If the condition, status and message match an existing condition the update is
// ignored.
func (c *Identity) StatusConditionWrite(t unikornv1core.ConditionType, status corev1.ConditionStatus, reason unikornv1core.ConditionReason, message string) {
	unikornv1core.UpdateCondition(&c.Status.Conditions, t, status, reason, message)
}

// ResourceLabels generates a set of labels to uniquely identify the resource
// if it were to be placed in a single global namespace.
func (c *Identity) ResourceLabels() (labels.Set, error) {
	//nolint:nilnil
	return nil, nil
}

// Paused implements the ReconcilePauser interface.
func (c *Network) Paused() bool {
	return c.Spec.Pause
}

// StatusConditionRead scans the status conditions for an existing condition whose type
// matches.
func (c *Network) StatusConditionRead(t unikornv1core.ConditionType) (*unikornv1core.Condition, error) {
	return unikornv1core.GetCondition(c.Status.Conditions, t)
}

// StatusConditionWrite either adds or updates a condition in the cluster manager status.
// If the condition, status and message match an existing condition the update is
// ignored.
func (c *Network) StatusConditionWrite(t unikornv1core.ConditionType, status corev1.ConditionStatus, reason unikornv1core.ConditionReason, message string) {
	unikornv1core.UpdateCondition(&c.Status.Conditions, t, status, reason, message)
}

// ResourceLabels generates a set of labels to uniquely identify the resource
// if it were to be placed in a single global namespace.
func (c *Network) ResourceLabels() (labels.Set, error) {
	//nolint:nilnil
	return nil, nil
}

// EffectiveReservations returns the reservations the provider should use when
// reconciling a network.  Explicit reservations win; otherwise the defaults apply.
func (c *Network) EffectiveReservations() *NetworkReservations {
	if c.Spec.Reservations != nil {
		return c.Spec.Reservations.DeepCopy()
	}

	return &NetworkReservations{
		PrefixLength:                 constants.DefaultNetworkReservationPrefixLength,
		ProviderReservedPrefixLength: ptr.To(constants.DefaultNetworkProviderReservedPrefixLength),
	}
}

// Paused implements the ReconcilePauser interface.
func (c *SecurityGroup) Paused() bool {
	return c.Spec.Pause
}

// StatusConditionRead scans the status conditions for an existing condition whose type
// matches.
func (c *SecurityGroup) StatusConditionRead(t unikornv1core.ConditionType) (*unikornv1core.Condition, error) {
	return unikornv1core.GetCondition(c.Status.Conditions, t)
}

// StatusConditionWrite either adds or updates a condition in the cluster manager status.
// If the condition, status and message match an existing condition the update is
// ignored.
func (c *SecurityGroup) StatusConditionWrite(t unikornv1core.ConditionType, status corev1.ConditionStatus, reason unikornv1core.ConditionReason, message string) {
	unikornv1core.UpdateCondition(&c.Status.Conditions, t, status, reason, message)
}

// ResourceLabels generates a set of labels to uniquely identify the resource
// if it were to be placed in a single global namespace.
func (c *SecurityGroup) ResourceLabels() (labels.Set, error) {
	//nolint:nilnil
	return nil, nil
}

// Paused implements the ReconcilePauser interface.
func (c *LoadBalancer) Paused() bool {
	return c.Spec.Pause
}

// StatusConditionRead scans the status conditions for an existing condition whose type
// matches.
func (c *LoadBalancer) StatusConditionRead(t unikornv1core.ConditionType) (*unikornv1core.Condition, error) {
	return unikornv1core.GetCondition(c.Status.Conditions, t)
}

// StatusConditionWrite either adds or updates a condition in the cluster manager status.
// If the condition, status and message match an existing condition the update is
// ignored.
func (c *LoadBalancer) StatusConditionWrite(t unikornv1core.ConditionType, status corev1.ConditionStatus, reason unikornv1core.ConditionReason, message string) {
	unikornv1core.UpdateCondition(&c.Status.Conditions, t, status, reason, message)
}

// ResourceLabels generates a set of labels to uniquely identify the resource
// if it were to be placed in a single global namespace.
func (c *LoadBalancer) ResourceLabels() (labels.Set, error) {
	//nolint:nilnil
	return nil, nil
}

// Paused implements the ReconcilePauser interface.
func (c *Server) Paused() bool {
	return c.Spec.Pause
}

// StatusConditionRead scans the status conditions for an existing condition whose type
// matches.
func (c *Server) StatusConditionRead(t unikornv1core.ConditionType) (*unikornv1core.Condition, error) {
	return unikornv1core.GetCondition(c.Status.Conditions, t)
}

// StatusConditionWrite either adds or updates a condition in the cluster manager status.
// If the condition, status and message match an existing condition the update is
// ignored.
func (c *Server) StatusConditionWrite(t unikornv1core.ConditionType, status corev1.ConditionStatus, reason unikornv1core.ConditionReason, message string) {
	unikornv1core.UpdateCondition(&c.Status.Conditions, t, status, reason, message)
}

func (c *Server) ProviderCreateGateConfigured(conditionType string) bool {
	for _, gate := range c.Spec.ProviderCreateGates {
		if gate.ConditionType == conditionType {
			return true
		}
	}

	return false
}

func (c *Server) ProviderCreateGateStatusRead(conditionType string) (*ServerProviderCreateGateStatus, bool) {
	for i := range c.Status.ProviderCreateGates {
		if c.Status.ProviderCreateGates[i].ConditionType == conditionType {
			return &c.Status.ProviderCreateGates[i], true
		}
	}

	return nil, false
}

func (c *Server) ProviderCreateGateStatusWrite(conditionType string, status corev1.ConditionStatus, actor, reason, message string) {
	now := metav1.Now()
	gate := ServerProviderCreateGateStatus{
		ConditionType:      conditionType,
		Status:             status,
		LastTransitionTime: now,
		Actor:              actor,
		Reason:             reason,
		Message:            message,
	}

	existing, ok := c.ProviderCreateGateStatusRead(conditionType)
	if !ok {
		c.Status.ProviderCreateGates = append(c.Status.ProviderCreateGates, gate)

		return
	}

	if existing.Status == status {
		gate.LastTransitionTime = existing.LastTransitionTime
	}

	*existing = gate
}

func (c *Server) RemainingProviderCreateGates() []string {
	out := make([]string, 0, len(c.Spec.ProviderCreateGates))

	for _, gate := range c.Spec.ProviderCreateGates {
		status, ok := c.ProviderCreateGateStatusRead(gate.ConditionType)
		if !ok || status.Status != corev1.ConditionTrue {
			out = append(out, gate.ConditionType)
		}
	}

	return out
}

func (c *Server) ProviderCreateGatesReady() bool {
	return len(c.RemainingProviderCreateGates()) == 0
}

func (c *Server) ProviderCreateGatesReset(actor, reason, message string) {
	for _, gate := range c.Spec.ProviderCreateGates {
		c.ProviderCreateGateStatusWrite(gate.ConditionType, corev1.ConditionUnknown, actor, reason, message)
	}
}

// ResourceLabels generates a set of labels to uniquely identify the resource
// if it were to be placed in a single global namespace.
func (c *Server) ResourceLabels() (labels.Set, error) {
	//nolint:nilnil
	return nil, nil
}

func (s *RegionOpenstackNetworkSpec) UseProviderNetworks() bool {
	return s != nil && s.ProviderNetworks != nil && s.ProviderNetworks.Network != nil
}

// Paused implements the ReconcilePauser interface.
func (s *FileStorage) Paused() bool {
	return s.Spec.Pause
}

// StatusConditionRead scans the status conditions for an existing condition whose type
// matches.
func (s *FileStorage) StatusConditionRead(t unikornv1core.ConditionType) (*unikornv1core.Condition, error) {
	return unikornv1core.GetCondition(s.Status.Conditions, t)
}

// StatusConditionWrite either adds or updates a condition in the cluster manager status.
// If the condition, status and message match an existing condition the update is
// ignored.
func (s *FileStorage) StatusConditionWrite(t unikornv1core.ConditionType, status corev1.ConditionStatus, reason unikornv1core.ConditionReason, message string) {
	unikornv1core.UpdateCondition(&s.Status.Conditions, t, status, reason, message)
}

// ResourceLabels generates a set of labels to uniquely identify the resource
// if it were to be placed in a single global namespace.
func (s *FileStorage) ResourceLabels() (labels.Set, error) {
	//nolint:nilnil
	return nil, nil
}

// StaticName generates a fixed and unique name for a region, used for naming
// resources that are dynamically defined for a region.
func (r *Region) StaticName() string {
	return string(r.Spec.Provider) + "." + r.Name
}

// VLANSpec returns allocatable VLANs for a region, if any are defined.
func (r *Region) VLANSpec() *VLANSpec {
	switch r.Spec.Provider {
	// These do nothing.  You should get a compile time failure if something
	// is not defined ala Rust.
	case ProviderKubernetes:
	case ProviderOpenstack:
		if r.Spec.Openstack != nil && r.Spec.Openstack.Network != nil && r.Spec.Openstack.Network.ProviderNetworks != nil {
			return r.Spec.Openstack.Network.ProviderNetworks.VLAN
		}
	case ProviderSimulated:
	}

	return nil
}
