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
func (c *Identity) StatusConditionRead(t unikornv1core.ConditionType) (*metav1.Condition, error) {
	return unikornv1core.GetCondition(c.Status.Conditions, t)
}

// SetProvisioningCondition sets the Available condition with a reason drawn from
// the provisioning vocabulary.
func (c *Identity) SetProvisioningCondition(status corev1.ConditionStatus, reason unikornv1core.ProvisioningConditionReason, message string) {
	unikornv1core.UpdateCondition(&c.Status.Conditions, unikornv1core.ConditionAvailable, status, string(reason), message)
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
func (c *Network) StatusConditionRead(t unikornv1core.ConditionType) (*metav1.Condition, error) {
	return unikornv1core.GetCondition(c.Status.Conditions, t)
}

// SetProvisioningCondition sets the Available condition with a reason drawn from
// the provisioning vocabulary.
func (c *Network) SetProvisioningCondition(status corev1.ConditionStatus, reason unikornv1core.ProvisioningConditionReason, message string) {
	unikornv1core.UpdateCondition(&c.Status.Conditions, unikornv1core.ConditionAvailable, status, string(reason), message)
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
func (c *SecurityGroup) StatusConditionRead(t unikornv1core.ConditionType) (*metav1.Condition, error) {
	return unikornv1core.GetCondition(c.Status.Conditions, t)
}

// SetProvisioningCondition sets the Available condition with a reason drawn from
// the provisioning vocabulary.
func (c *SecurityGroup) SetProvisioningCondition(status corev1.ConditionStatus, reason unikornv1core.ProvisioningConditionReason, message string) {
	unikornv1core.UpdateCondition(&c.Status.Conditions, unikornv1core.ConditionAvailable, status, string(reason), message)
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
func (c *LoadBalancer) StatusConditionRead(t unikornv1core.ConditionType) (*metav1.Condition, error) {
	return unikornv1core.GetCondition(c.Status.Conditions, t)
}

// SetProvisioningCondition sets the Available condition with a reason drawn from
// the provisioning vocabulary.
func (c *LoadBalancer) SetProvisioningCondition(status corev1.ConditionStatus, reason unikornv1core.ProvisioningConditionReason, message string) {
	unikornv1core.UpdateCondition(&c.Status.Conditions, unikornv1core.ConditionAvailable, status, string(reason), message)
}

// ResourceLabels generates a set of labels to uniquely identify the resource
// if it were to be placed in a single global namespace.
func (c *LoadBalancer) ResourceLabels() (labels.Set, error) {
	//nolint:nilnil
	return nil, nil
}

// Paused implements the ReconcilePauser interface.
func (c *Volume) Paused() bool {
	return c.Spec.Pause
}

// StatusConditionRead scans the status conditions for an existing condition whose type
// matches.
func (c *Volume) StatusConditionRead(t unikornv1core.ConditionType) (*metav1.Condition, error) {
	return unikornv1core.GetCondition(c.Status.Conditions, t)
}

// SetProvisioningCondition sets the Available condition with a reason drawn from
// the provisioning vocabulary.
func (c *Volume) SetProvisioningCondition(status corev1.ConditionStatus, reason unikornv1core.ProvisioningConditionReason, message string) {
	unikornv1core.UpdateCondition(&c.Status.Conditions, unikornv1core.ConditionAvailable, status, string(reason), message)
}

// ResourceLabels generates a set of labels to uniquely identify the resource
// if it were to be placed in a single global namespace.
func (c *Volume) ResourceLabels() (labels.Set, error) {
	//nolint:nilnil
	return nil, nil
}

// Paused implements the ReconcilePauser interface.
func (c *Server) Paused() bool {
	return c.Spec.Pause
}

// StatusConditionRead scans the status conditions for an existing condition whose type
// matches.
func (c *Server) StatusConditionRead(t unikornv1core.ConditionType) (*metav1.Condition, error) {
	return unikornv1core.GetCondition(c.Status.Conditions, t)
}

// SetProvisioningCondition sets the Available condition with a reason drawn from
// the provisioning vocabulary.
func (c *Server) SetProvisioningCondition(status corev1.ConditionStatus, reason unikornv1core.ProvisioningConditionReason, message string) {
	unikornv1core.UpdateCondition(&c.Status.Conditions, unikornv1core.ConditionAvailable, status, string(reason), message)
}

// SetHealthCondition sets the Healthy condition with a reason drawn from the
// health vocabulary. A server is the only region resource that carries a health
// verdict (derived from the provider's observed server state); it is an
// informational signal and nothing gates on it.
func (c *Server) SetHealthCondition(status corev1.ConditionStatus, reason unikornv1core.HealthConditionReason, message string) {
	unikornv1core.UpdateCondition(&c.Status.Conditions, unikornv1core.ConditionHealthy, status, string(reason), message)
}

// SetActiveCondition sets the generic core Active condition to a server lifecycle
// state. Unlike the provisioning and health axes — whose status and message are
// independent of the reason — the Active condition's status and message are pure
// projections of its reason (see ActiveConditionReason.ConditionStatus and
// Message), so this setter takes only the reason and derives the rest. That makes
// an inconsistent (status, reason) pair unrepresentable.
func (c *Server) SetActiveCondition(reason ActiveConditionReason) {
	unikornv1core.UpdateCondition(&c.Status.Conditions, unikornv1core.ConditionActive, reason.ConditionStatus(), string(reason), reason.Message())
}

// GetActiveCondition reads the Active condition, narrowing its reason to the
// server's domain-owned lifecycle/power vocabulary via core's generic typed
// handling.
func GetActiveCondition(r unikornv1core.StatusConditionReader) (*unikornv1core.TypedCondition[ActiveConditionReason], error) {
	return unikornv1core.GetTypedCondition[ActiveConditionReason](r, unikornv1core.ConditionActive)
}

// ConditionStatus projects a lifecycle reason onto the Active condition's boolean
// status: a server is Active (True) only when it is running; every other state
// (pending, queued, building, stopping, stopped, errored) is not-running (False).
// ConditionStatus projects a reason onto the boolean Active status: True only
// when Running, False for every other reason.
//
// Active=False means "not currently running/live", NOT "unhealthy": a
// deliberately Stopped server is False here yet perfectly healthy. Consumers
// gate on the reason, never on this boolean as a health signal; health is the
// separate Healthy condition.
func (r ActiveConditionReason) ConditionStatus() corev1.ConditionStatus {
	if r == ActiveConditionReasonRunning {
		return corev1.ConditionTrue
	}

	return corev1.ConditionFalse
}

// Message returns a user-facing description of a lifecycle state. The Active
// condition's message is a pure function of its reason (the provisioning and
// health axes, by contrast, carry independent operator detail), so it is derived
// here rather than supplied by callers.
func (r ActiveConditionReason) Message() string {
	switch r {
	case ActiveConditionReasonPending:
		return "the server is awaiting provider scheduling"
	case ActiveConditionReasonQueued:
		return "the server is queued awaiting hardware"
	case ActiveConditionReasonBuilding:
		return "the server is being built"
	case ActiveConditionReasonRebuilding:
		return "the server is being rebuilt"
	case ActiveConditionReasonRunning:
		return "the server is running"
	case ActiveConditionReasonStopping:
		return "the server is stopping"
	case ActiveConditionReasonStopped:
		return "the server is stopped"
	case ActiveConditionReasonError:
		return "the server is in an error state"
	}

	return ""
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

// regionIDFromLabels recovers the typed region ID from a resource's labels, with
// the same fail-closed semantics as organizationIDFromLabels: a malformed stored
// value is a consistency bug, so it surfaces as an error rather than propagating
// an unchecked string.
func regionIDFromLabels(labels map[string]string) (regionids.RegionID, error) {
	id, err := regionids.ParseRegionID(labels[constants.RegionLabel])
	if err != nil {
		return regionids.RegionID{}, fmt.Errorf("%w: invalid region ID in resource labels", err)
	}

	return id, nil
}

// OrganizationID returns the server's owning organization ID as a typed identifier.
func (c *Server) OrganizationID() (identityids.OrganizationID, error) {
	return organizationIDFromLabels(c.Labels)
}

// RegionID returns the server's owning region ID as a typed identifier.
func (c *Server) RegionID() (regionids.RegionID, error) {
	return regionIDFromLabels(c.Labels)
}

// OrganizationAndProjectID returns the server's owning organization and project
// IDs as typed identifiers.
func (c *Server) OrganizationAndProjectID() (identityids.OrganizationID, identityids.ProjectID, error) {
	return organizationAndProjectIDFromLabels(c.Labels)
}

// ResolvedSSHInjection returns the effective create-time SSH injection mode.
// Older servers predate this field, so fall back to the legacy contract:
// CA-backed servers use the CA path, all others use the identity keypair.
func (c *Server) ResolvedSSHInjection() ServerSSHInjection {
	if c.Spec.SSHInjection != nil {
		return *c.Spec.SSHInjection
	}

	if c.Spec.SSHCertificateAuthorityID != nil {
		return ServerSSHInjectionCA
	}

	return ServerSSHInjectionIdentityKeypair
}

// UsesIdentitySSHKey returns true when Region requested identity-scoped SSH
// keypair injection for this server.
func (c *Server) UsesIdentitySSHKey() bool {
	return c.ResolvedSSHInjection() == ServerSSHInjectionIdentityKeypair
}

// ImageID returns the server's image as a typed identifier. It returns an error
// if the image is unset, so read paths surface a clean error rather than
// dereferencing a nil image. The ID itself is already a typed, UUID-validated
// field on the spec.
func (c *Server) ImageID() (regionids.ImageID, error) {
	if c.Spec.Image == nil {
		return regionids.ImageID{}, fmt.Errorf("%w: server has no image", coreerrors.ErrConsistency)
	}

	return c.Spec.Image.ID, nil
}

// RebuildPending reports whether the server carries any recorded rebuild
// intent that has not settled-and-cleared: while the marker exists — in ANY
// state, including armed-but-unaccepted Initiated — the desired image is not
// fully realized, so read paths must report the spec as not settled (an
// armed rebuild that Nova persistently 409s is provisioning, not
// provisioned).
func (c *Server) RebuildPending() bool {
	return c.Status.Rebuild != nil
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

// NetworkID returns the network's own ID as a typed identifier, recovered
// fail-closed from its resource name (the network is named after its UUID).
func (c *Network) NetworkID() (regionids.NetworkID, error) {
	id, err := regionids.ParseNetworkID(c.Name)
	if err != nil {
		return regionids.NetworkID{}, fmt.Errorf("%w: invalid network ID in resource name", err)
	}

	return id, nil
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

// OrganizationID returns the volume's owning organization ID as a typed identifier.
func (c *Volume) OrganizationID() (identityids.OrganizationID, error) {
	return organizationIDFromLabels(c.Labels)
}

// OrganizationAndProjectID returns the volume's owning organization and project
// IDs as typed identifiers.
func (c *Volume) OrganizationAndProjectID() (identityids.OrganizationID, identityids.ProjectID, error) {
	return organizationAndProjectIDFromLabels(c.Labels)
}

// NetworkID returns the volume's anchoring network ID as a typed identifier.
func (c *Volume) NetworkID() (regionids.NetworkID, error) {
	id, err := regionids.ParseNetworkID(c.Spec.NetworkID)
	if err != nil {
		return regionids.NetworkID{}, fmt.Errorf("%w: invalid network ID on volume", err)
	}

	return id, nil
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
	_ identityids.ProjectScopeReader = (*Volume)(nil)
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
func (s *FileStorage) StatusConditionRead(t unikornv1core.ConditionType) (*metav1.Condition, error) {
	return unikornv1core.GetCondition(s.Status.Conditions, t)
}

// SetProvisioningCondition sets the Available condition with a reason drawn from
// the provisioning vocabulary.
func (s *FileStorage) SetProvisioningCondition(status corev1.ConditionStatus, reason unikornv1core.ProvisioningConditionReason, message string) {
	unikornv1core.UpdateCondition(&s.Status.Conditions, unikornv1core.ConditionAvailable, status, string(reason), message)
}

// StatusConditionRead lets a snapshot policy status be read through the typed
// condition accessors (GetAvailableCondition et al): it carries its own
// conditions, so it satisfies StatusConditionReader even though it is a
// subresource rather than a top-level managed resource.
func (s *FileStorageSnapshotPolicyStatus) StatusConditionRead(t unikornv1core.ConditionType) (*metav1.Condition, error) {
	return unikornv1core.GetCondition(s.Conditions, t)
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
