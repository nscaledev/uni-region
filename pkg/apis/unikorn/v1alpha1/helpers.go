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
	"fmt"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/constants"
	regionids "github.com/unikorn-cloud/region/pkg/ids"

	corev1 "k8s.io/api/core/v1"
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

// ResourceLabels generates a set of labels to uniquely identify the resource
// if it were to be placed in a single global namespace.
func (c *Server) ResourceLabels() (labels.Set, error) {
	//nolint:nilnil
	return nil, nil
}

// organizationIDFromLabels recovers a typed organization ID from a resource's
// labels. It returns an error if the label is missing or is not a valid UUID, so
// callers fail closed with a clean error rather than panicking or making an
// authorization decision on a malformed value.
func organizationIDFromLabels(labels map[string]string) (identityids.OrganizationID, error) {
	id, err := identityids.ParseOrganizationID(labels[coreconstants.OrganizationLabel])
	if err != nil {
		return identityids.OrganizationID{}, fmt.Errorf("%w: invalid organization ID in resource labels", err)
	}

	return id, nil
}

// organizationAndProjectIDFromLabels recovers both the typed organization and
// project IDs from a resource's labels, with the same fail-closed semantics as
// organizationIDFromLabels. The two are recovered together because every
// project-scoped check needs both and a malformed value is a 500 either way, so
// the API surface gains nothing from discriminating which one was bad.
func organizationAndProjectIDFromLabels(labels map[string]string) (identityids.OrganizationID, identityids.ProjectID, error) {
	organizationID, err := organizationIDFromLabels(labels)
	if err != nil {
		return identityids.OrganizationID{}, identityids.ProjectID{}, err
	}

	projectID, err := identityids.ParseProjectID(labels[coreconstants.ProjectLabel])
	if err != nil {
		return identityids.OrganizationID{}, identityids.ProjectID{}, fmt.Errorf("%w: invalid project ID in resource labels", err)
	}

	return organizationID, projectID, nil
}

// OrganizationID returns the server's owning organization ID as a typed identifier.
func (c *Server) OrganizationID() (identityids.OrganizationID, error) {
	return organizationIDFromLabels(c.Labels)
}

// OrganizationAndProjectID returns the server's owning organization and project
// IDs as typed identifiers.
func (c *Server) OrganizationAndProjectID() (identityids.OrganizationID, identityids.ProjectID, error) {
	return organizationAndProjectIDFromLabels(c.Labels)
}

// FlavorID returns the server's flavor as a typed identifier. It returns an
// error if the stored value is not a valid UUID, so read paths surface a clean
// error rather than panicking.
func (c *Server) FlavorID() (regionids.FlavorID, error) {
	id, err := regionids.ParseFlavorID(c.Spec.FlavorID)
	if err != nil {
		return regionids.FlavorID{}, fmt.Errorf("%w: invalid flavor ID on server", err)
	}

	return id, nil
}

// ImageID returns the server's image as a typed identifier. It returns an error
// if the image is unset or its stored value is not a valid UUID, so read paths
// surface a clean error rather than panicking.
func (c *Server) ImageID() (regionids.ImageID, error) {
	if c.Spec.Image == nil {
		return regionids.ImageID{}, fmt.Errorf("%w: server has no image", coreerrors.ErrConsistency)
	}

	id, err := regionids.ParseImageID(c.Spec.Image.ID)
	if err != nil {
		return regionids.ImageID{}, fmt.Errorf("%w: invalid image ID on server", err)
	}

	return id, nil
}

// OrganizationID returns the network's owning organization ID as a typed identifier.
func (c *Network) OrganizationID() (identityids.OrganizationID, error) {
	return organizationIDFromLabels(c.Labels)
}

// OrganizationAndProjectID returns the network's owning organization and project
// IDs as typed identifiers.
func (c *Network) OrganizationAndProjectID() (identityids.OrganizationID, identityids.ProjectID, error) {
	return organizationAndProjectIDFromLabels(c.Labels)
}

// OrganizationID returns the security group's owning organization ID as a typed identifier.
func (c *SecurityGroup) OrganizationID() (identityids.OrganizationID, error) {
	return organizationIDFromLabels(c.Labels)
}

// OrganizationAndProjectID returns the security group's owning organization and
// project IDs as typed identifiers.
func (c *SecurityGroup) OrganizationAndProjectID() (identityids.OrganizationID, identityids.ProjectID, error) {
	return organizationAndProjectIDFromLabels(c.Labels)
}

// OrganizationID returns the load balancer's owning organization ID as a typed identifier.
func (c *LoadBalancer) OrganizationID() (identityids.OrganizationID, error) {
	return organizationIDFromLabels(c.Labels)
}

// OrganizationAndProjectID returns the load balancer's owning organization and
// project IDs as typed identifiers.
func (c *LoadBalancer) OrganizationAndProjectID() (identityids.OrganizationID, identityids.ProjectID, error) {
	return organizationAndProjectIDFromLabels(c.Labels)
}

// OrganizationID returns the SSH certificate authority's owning organization ID as a typed identifier.
func (c *SSHCertificateAuthority) OrganizationID() (identityids.OrganizationID, error) {
	return organizationIDFromLabels(c.Labels)
}

// OrganizationAndProjectID returns the SSH certificate authority's owning
// organization and project IDs as typed identifiers.
func (c *SSHCertificateAuthority) OrganizationAndProjectID() (identityids.OrganizationID, identityids.ProjectID, error) {
	return organizationAndProjectIDFromLabels(c.Labels)
}

// OrganizationID returns the file storage's owning organization ID as a typed identifier.
func (s *FileStorage) OrganizationID() (identityids.OrganizationID, error) {
	return organizationIDFromLabels(s.Labels)
}

// OrganizationAndProjectID returns the file storage's owning organization and
// project IDs as typed identifiers.
func (s *FileStorage) OrganizationAndProjectID() (identityids.OrganizationID, identityids.ProjectID, error) {
	return organizationAndProjectIDFromLabels(s.Labels)
}

// OrganizationID returns the identity's owning organization ID as a typed identifier.
func (c *Identity) OrganizationID() (identityids.OrganizationID, error) {
	return organizationIDFromLabels(c.Labels)
}

// OrganizationAndProjectID returns the identity's owning organization and project
// IDs as typed identifiers.
func (c *Identity) OrganizationAndProjectID() (identityids.OrganizationID, identityids.ProjectID, error) {
	return organizationAndProjectIDFromLabels(c.Labels)
}

// Static assertions that the project-scoped resources satisfy the identity
// scope-reader interfaces (which embed OrganizationScopeReader), so a drift in
// the accessor signatures becomes a compile error.
var (
	_ identityids.ProjectScopeReader = (*Server)(nil)
	_ identityids.ProjectScopeReader = (*Network)(nil)
	_ identityids.ProjectScopeReader = (*SecurityGroup)(nil)
	_ identityids.ProjectScopeReader = (*LoadBalancer)(nil)
	_ identityids.ProjectScopeReader = (*SSHCertificateAuthority)(nil)
	_ identityids.ProjectScopeReader = (*FileStorage)(nil)
	_ identityids.ProjectScopeReader = (*Identity)(nil)
)

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
