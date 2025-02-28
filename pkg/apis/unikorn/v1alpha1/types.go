/*
Copyright 2022-2024 EscherCloud.
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

package v1alpha1

import (
	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Provider is used to communicate the cloud type.
// +kubebuilder:validation:Enum=openstack
type Provider string

const (
	ProviderOpenstack Provider = "openstack"
)

// RegionList is a typed list of regions.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type RegionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Region `json:"items"`
}

// Region defines a geographical region where clusters can be provisioned.
// A region defines the endpoints that can be used to derive information
// about the provider for that region.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="display name",type="string",JSONPath=".metadata.labels['unikorn-cloud\\.org/name']"
// +kubebuilder:printcolumn:name="provider",type="string",JSONPath=".spec.provider"
// +kubebuilder:printcolumn:name="status",type="string",JSONPath=".status.conditions[?(@.type==\"Available\")].reason"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type Region struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              RegionSpec   `json:"spec"`
	Status            RegionStatus `json:"status,omitempty"`
}

// RegionSpec defines metadata about the region.
type RegionSpec struct {
	// Tags are aribrary user data.
	Tags unikornv1core.TagList `json:"tags,omitempty"`
	// Type defines the provider type.
	Provider Provider `json:"provider"`
	// Openstack is provider specific configuration for the region.
	Openstack *RegionOpenstackSpec `json:"openstack,omitempty"`
}

type RegionOpenstackSpec struct {
	// Endpoint is the Keystone URL e.g. https://foo.bar:5000.
	Endpoint string `json:"endpoint"`
	// ServiceAccountSecretName points to the secret containing credentials
	// required to perform the tasks the provider needs to perform.
	ServiceAccountSecret *NamespacedObject `json:"serviceAccountSecret"`
	// Identity is configuration for the identity service.
	Identity *RegionOpenstackIdentitySpec `json:"identity,omitempty"`
	// Compute is configuration for the compute service.
	Compute *RegionOpenstackComputeSpec `json:"compute,omitempty"`
	// Image is configuration for the image service.
	Image *RegionOpenstackImageSpec `json:"image,omitempty"`
	// Network is configuration for the network service.
	Network *RegionOpenstackNetworkSpec `json:"network,omitempty"`
}

type NamespacedObject struct {
	// Namespace is the namespace in which the object resides.
	Namespace string `json:"namespace"`
	// Name is the name of the object.
	Name string `json:"name"`
}

type RegionOpenstackIdentitySpec struct {
	// ClusterRoles are the roles required to be assigned to an application
	// credential in order to provision, scale and deprovision a cluster, along
	// with any required for CNI/CSI functionality.
	ClusterRoles []string `json:"clusterRoles,omitempty"`
}

type RegionOpenstackComputeSpec struct {
	// ServerGroupPolicy defines the anti-affinity policy to use for
	// scheduling cluster nodes.  Defaults to "soft-anti-affinity".
	ServerGroupPolicy *string `json:"serverGroupPolicy,omitempty"`
	// Flavors defines how flavors are filtered and reported to
	// clients.  If not defined, then all flavors are exported.
	Flavors *OpenstackFlavorsSpec `json:"flavors,omitempty"`
}

// +kubebuilder:validation:Enum=All;None
type OpenstackFlavorSelectionPolicy string

const (
	OpenstackFlavorSelectionPolicySelectAll  OpenstackFlavorSelectionPolicy = "All"
	OpenstackFlavorSelectionPolicySelectNone OpenstackFlavorSelectionPolicy = "None"
)

type OpenstackFlavorsSpec struct {
	// Selector allows flavors to be manually selected for inclusion.  The selected
	// set is a boolean intersection of all defined filters in the selector.
	// Note that there are some internal rules that will fiter out flavors such as
	// if the flavor does not have enough resource to function correctly.
	Selector *FlavorSelector `json:"selector,omitempty"`
	// Metadata allows flavors to be explicitly augmented with additional metadata.
	// This acknowledges the fact that OpenStack is inadequate acting as a source
	// of truth for machine topology, and needs external input to describe things
	// like add on peripherals.
	Metadata []FlavorMetadata `json:"metadata,omitempty"`
}

type FlavorSelector struct {
	// IDs is an explicit list of allowed flavors IDs.  If not specified,
	// then all flavors are considered.
	IDs []string `json:"ids,omitempty"`
}

type FlavorMetadata struct {
	// ID is the immutable Openstack identifier for the flavor.
	ID string `json:"id"`
	// Baremetal indicates that this is a baremetal flavor, as opposed to a
	// virtualized one in case this affects image selection or even how instances
	// are provisioned.
	Baremetal bool `json:"baremetal,omitempty"`
	// CPU defines additional CPU metadata.
	CPU *CPUSpec `json:"cpu,omitempty"`
	// Memory allows the memory amount to be overridden.
	Memory *resource.Quantity `json:"memory,omitempty"`
	// GPU defines additional GPU metadata.  When provided it will enable selection
	// of images based on GPU vendor and model.
	GPU *GPUSpec `json:"gpu,omitempty"`
}

type CPUSpec struct {
	// Count allows you to override the number of CPUs.  Usually this wouldn't
	// be necessary, but alas some operators may not set this correctly for baremetal
	// flavors to make horizon display overcommit correctly...
	Count *int `json:"count,omitempty"`
	// Family is a free-form string that can communicate the CPU family to clients
	// e.g. "Xeon Platinum 8160T (Skylake)", and allows users to make scheduling
	// decisions based on CPU architecture and performance etc.
	Family *string `json:"family,omitempty"`
}

// +kubebuilder:validation:Enum=NVIDIA;AMD
type GPUVendor string

const (
	NVIDIA GPUVendor = "NVIDIA"
	AMD    GPUVendor = "AMD"
)

type GPUSpec struct {
	// Vendor is the GPU vendor, used for coarse grained flavor and image
	// selection.
	Vendor GPUVendor `json:"vendor"`
	// Model is a free-form model name that corresponds to the supported models
	// property included on images, and must be an exact match e.g. H100.
	Model string `json:"model"`
	// PhysicalCount is the number of physical cards in the flavor.
	// This is primarily for end users, so it's not confusing.
	PhysicalCount int `json:"physicalCount"`
	// LogicalCount is the number of logical GPUs e.g. an AMD MI250 is 2 MI200s.
	// This is primarily for scheduling e.g. autoscaling.
	LogicalCount int `json:"logicalCount"`
	// Memory is the amount of memory each logical GPU has access to.
	Memory *resource.Quantity `json:"memory"`
}

type RegionOpenstackImageSpec struct {
	// Selector defines a set of rules to lookup images.
	// If not specified, all images are selected.
	Selector *ImageSelector `json:"selector,omitempty"`
}

type ImageSelector struct {
	// Properties defines the set of properties an image needs to have to
	// be selected.
	Properties []string `json:"properties,omitempty"`
	// SigningKey defines a PEM encoded public ECDSA signing key used to verify
	// the image is trusted.  If specified, an image must contain the "digest"
	// property, the value of which must be a base64 encoded ECDSA signature of
	// the SHA256 hash of the image ID.
	SigningKey []byte `json:"signingKey,omitempty"`
}

type RegionOpenstackNetworkSpec struct {
	// ExternalNetworks allows external network options to be specified.
	ExternalNetworks *ExternalNetworks `json:"externalNetworks,omitempty"`
	// ProviderNetworks allows provider networks to be configured.
	ProviderNetworks *ProviderNetworks `json:"providerNetworks,omitempty"`
}

type ExternalNetworks struct {
	// Selector defines a set of rules to lookup external networks.
	// In none is specified, all external networks are selected.
	Selector *NetworkSelector `json:"selector,omitempty"`
}

type NetworkSelector struct {
	// IDs is an explicit list of network IDs.
	IDs []string `json:"ids,omitempty"`
	// Tags is an implicit selector of networks with a set of all specified tags.
	Tags []string `json:"tags,omitempty"`
}

type ProviderNetworks struct {
	// Network is the neutron provider specific network name used
	// to provision provider networks e.g. VLANs for bare metal clusters.
	Network *string `json:"physicalNetwork,omitempty"`
	// VLAN is the VLAN configuration.  If not specified and a VLAN provider
	// network is requested then the ID will be allocated between 1-6094
	// inclusive.
	VLAN *VLANSpec `json:"vlan,omitempty"`
}

type VLANSpec struct {
	// Segements allow blocks of VLAN IDs to be allocated from.  In a multi
	// tenant system, it's possible and perhaps necessary, that this controller
	// be limited to certain ranges to avoid split brain scenarios when another
	// user or system is allocating VLAN IDs for itself.
	// +kubebuilder:validation:MinItems=1
	Segments []VLANSegment `json:"segments,omitempty"`
}

type VLANSegment struct {
	// StartID is VLAN ID at the start of the range.
	// +kubebuilder:validation:Minimum=1
	StartID int `json:"startId"`
	// EndID is the VLAN ID at the end of the range.
	// +kubebuilder:validation:Maximum=4094
	EndID int `json:"endId"`
}

// RegionStatus defines the status of the region.
type RegionStatus struct {
	// Current service state of a region.
	Conditions []unikornv1core.Condition `json:"conditions,omitempty"`
}

// IdentityList is a typed list of identities.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type IdentityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Identity `json:"items"`
}

// Identity defines an on-demand cloud identity.  The region controller must
// create any resources necessary to provide dynamic provisioning of clusters
// e.g. compute, storage and networking.  This resource is used for persistence
// of information by the controller and not for manual lifecycle management.
// Any credentials should not be stored unless absolutely necessary, and should
// be passed to a client on initial identity creation only.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="provider",type="string",JSONPath=".spec.provider"
// +kubebuilder:printcolumn:name="status",type="string",JSONPath=".status.conditions[?(@.type==\"Available\")].reason"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type Identity struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              IdentitySpec   `json:"spec"`
	Status            IdentityStatus `json:"status,omitempty"`
}

// IdentitySpec stores any state necessary to manage identity.
type IdentitySpec struct {
	// Pause, if true, will inhibit reconciliation.
	Pause bool `json:"pause,omitempty"`
	// Tags are an abitrary list of key/value pairs that a client
	// may populate to store metadata for the resource.
	Tags unikornv1core.TagList `json:"tags,omitempty"`
	// Provider defines the provider type.
	Provider Provider `json:"provider"`
}

type IdentityStatus struct {
	// Current service state of a cluster manager.
	Conditions []unikornv1core.Condition `json:"conditions,omitempty"`
}

// OpenstackIdentityList is a typed list of identities.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OpenstackIdentityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenstackIdentity `json:"items"`
}

// OpenstackIdentity has no controller, its a database record of state.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:printcolumn:name="provider",type="string",JSONPath=".spec.provider"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type OpenstackIdentity struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OpenstackIdentitySpec   `json:"spec"`
	Status            OpenstackIdentityStatus `json:"status,omitempty"`
}

type OpenstackIdentitySpec struct {
	// CloudConfig is a client compatible cloud configuration.
	CloudConfig []byte `json:"cloudConfig,omitempty"`
	// Cloud is the cloud name in the cloud config to use.
	Cloud *string `json:"cloud,omitempty"`
	// UserID is the ID of the user created for the identity.
	UserID *string `json:"userID,omitempty"`
	// Password is the login for the user.
	Password *string `json:"password,omitempty"`
	// ProjectID is the ID of the project created for the identity.
	ProjectID *string `json:"projectID,omitempty"`
	// ApplicationCredentialID is the ID of the user's application credential.
	ApplicationCredentialID *string `json:"applicationCredentialID,omitempty"`
	// ApplicationCredentialSecret is the one-time secret for the application credential.
	ApplicationCredentialSecret *string `json:"applicationCredentialSecret,omitempty"`
	// ServerGroupID is the ID of the server group created for the identity.
	ServerGroupID *string `json:"serverGroupID,omitempty"`
	// SSHKeyName is the ssh key that may be injected into clusters by consuming services.
	SSHKeyName *string `json:"sshKeyName,omitempty"`
	// SSHPrivateKey is a PEM encoded private key.
	SSHPrivateKey []byte `json:"sshPrivateKey,omitempty"`
}

type OpenstackIdentityStatus struct{}

// NetworkList s a typed list of physical networks.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type NetworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Network `json:"items"`
}

// Network defines a physical network beloning to an identity.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="status",type="string",JSONPath=".status.conditions[?(@.type==\"Available\")].reason"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type Network struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              NetworkSpec   `json:"spec"`
	Status            NetworkStatus `json:"status,omitempty"`
}

type NetworkSpec struct {
	// Pause, if true, will inhibit reconciliation.
	Pause bool `json:"pause,omitempty"`
	// Tags are an abitrary list of key/value pairs that a client
	// may populate to store metadata for the resource.
	Tags unikornv1core.TagList `json:"tags,omitempty"`
	// Provider defines the provider type.
	Provider Provider `json:"provider"`
	// Prefix is the IPv4 address prefix.
	Prefix *unikornv1core.IPv4Prefix `json:"prefix"`
	// DNSNameservers are a set of DNS nameservrs for the network.
	DNSNameservers []unikornv1core.IPv4Address `json:"dnsNameservers"`
}

type NetworkStatus struct {
	// Current service state of a cluster manager.
	Conditions []unikornv1core.Condition `json:"conditions,omitempty"`
}

// OpenstackNetworkList s a typed list of physical networks.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OpenstackNetworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenstackNetwork `json:"items"`
}

// OpenstackNetwork defines a physical network beloning to an identity.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type OpenstackNetwork struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OpenstackNetworkSpec   `json:"spec"`
	Status            OpenstackNetworkStatus `json:"status,omitempty"`
}

type OpenstackNetworkSpec struct {
	// NetworkID is the network ID.
	NetworkID *string `json:"networkID,omitempty"`
	// VlanID is the ID if the VLAN for IPAM.
	VlanID *int `json:"vlanID,omitempty"`
	// SubnetID is the subnet ID.
	SubnetID *string `json:"subnetID,omitempty"`
	// RouterID is the router ID.
	RouterID *string `json:"routerID,omitempty"`
	// RouterSubnetInterfaceAdded tells us if this step has been accomplished.
	RouterSubnetInterfaceAdded bool `json:"routerSubnetInterfaceAdded,omitempty"`
}

type OpenstackNetworkStatus struct {
}

// VLANAllocationList is a typed list of VLAN allocations.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type VLANAllocationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VLANAllocation `json:"items"`
}

// VLANAllocation is used to manage VLAN allocations.  Only a single instance is
// allowed per region.  As this is a custom resource, we are guaranteed atomicity
// due to Kubernetes' speculative locking implementation.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type VLANAllocation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              VLANAllocationSpec   `json:"spec"`
	Status            VLANAllocationStatus `json:"status,omitempty"`
}

type VLANAllocationSpec struct {
	// Allocations are an explcit set of VLAN allocations.
	Allocations []VLANAllocationEntry `json:"allocations,omitempty"`
}

type VLANAllocationEntry struct {
	// ID is the VLAN ID.
	ID int `json:"id"`
	// NetworkID is the physical network/provider specific physical network
	// identifier that owns this entry.
	NetworkID string `json:"physicalNetworkID"`
}

type VLANAllocationStatus struct {
}

// QuotaList is a typed list of quotas.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type QuotaList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Quota `json:"items"`
}

// Quota defines resource limits for identities.
// We don't want to be concerned with Hertz and bytes, instead we want to
// expose higher level primitives like flavors and how many they are.  This
// removes a lot of the burden from clients.  Where we have to be careful is
// with overheads, e.g. a machine implicitly defines CPUs, memory and storage,
// but this will also need networks, NICs and other supporting resources.
// Quotas are scoped to identities, and also to a specific client, as this avoids
// having to worry about IPC and split brain concerns.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type Quota struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              QuotaSpec   `json:"spec"`
	Status            QuotaStatus `json:"status,omitempty"`
}

type QuotaSpec struct {
	// Tags are aribrary user data.
	Tags unikornv1core.TagList `json:"tags,omitempty"`
	// Flavors is a list of flavors and their count.
	// +listType=map
	// +listMapKey=id
	Flavors []FlavorQuota `json:"flavors,omitempty"`
}

type FlavorQuota struct {
	// ID is the flavor ID.
	ID string `json:"id"`
	// Count is the number of instances that are required.
	// For certain services that can do rolling upgrades, be aware that this
	// may need a little overhead to cater for that.  For example the Kubernetes
	// service will do a one-in-one-out upgrade of the control plane.
	Count int `json:"count"`
}

type QuotaStatus struct {
}

// SecurityGroupList is a typed list of security groups.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type SecurityGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecurityGroup `json:"items"`
}

// SecurityGroup defines a security group beloning to an identity.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="status",type="string",JSONPath=".status.conditions[?(@.type==\"Available\")].reason"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type SecurityGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SecurityGroupSpec   `json:"spec"`
	Status            SecurityGroupStatus `json:"status,omitempty"`
}

type SecurityGroupSpec struct {
	// Pause, if true, will inhibit reconciliation.
	Pause bool `json:"pause,omitempty"`
	// Tags are an abitrary list of key/value pairs that a client
	// may populate to store metadata for the resource.
	// Tags are aribrary user data.
	Tags unikornv1core.TagList `json:"tags,omitempty"`
	// Provider defines the provider type.
	Provider Provider `json:"provider"`
}

type SecurityGroupStatus struct {
	// Current service state of a security group.
	Conditions []unikornv1core.Condition `json:"conditions,omitempty"`
}

// OpenstackSecurityGroupList is a typed list of security groups.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OpenstackSecurityGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenstackSecurityGroup `json:"items"`
}

// OpenstackSecurityGroup has no controller, its a database record of state.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type OpenstackSecurityGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OpenstackSecurityGroupSpec   `json:"spec"`
	Status            OpenstackSecurityGroupStatus `json:"status,omitempty"`
}

type OpenstackSecurityGroupSpec struct {
	// SecurityGroupID is the security group ID.
	SecurityGroupID *string `json:"securityGroupID,omitempty"`
}

type OpenstackSecurityGroupStatus struct {
}

// SecurityGroupRuleList is a typed list of security group rules.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type SecurityGroupRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecurityGroupRule `json:"items"`
}

// SecurityGroupRule defines a security group rule beloning to a security group.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="status",type="string",JSONPath=".status.conditions[?(@.type==\"Available\")].reason"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type SecurityGroupRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SecurityGroupRuleSpec   `json:"spec"`
	Status            SecurityGroupRuleStatus `json:"status,omitempty"`
}

type SecurityGroupRuleSpec struct {
	// Pause, if true, will inhibit reconciliation.
	Pause bool `json:"pause,omitempty"`
	// Tags are aribrary user data.
	Tags unikornv1core.TagList `json:"tags,omitempty"`
	// Direction is the direction of the rule.
	Direction *SecurityGroupRuleDirection `json:"direction"`
	// Protocol is the protocol of the rule.
	Protocol *SecurityGroupRuleProtocol `json:"protocol"`
	// Port is the port or range of ports.
	Port *SecurityGroupRulePort `json:"port"`
	// CIDR is the CIDR block to allow traffic from.
	CIDR *unikornv1core.IPv4Prefix `json:"cidr"`
}

type SecurityGroupRuleStatus struct {
	// Current service state of a security group rule.
	Conditions []unikornv1core.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:validation:Enum=tcp;udp
type SecurityGroupRuleProtocol string

// +kubebuilder:validation:Enum=ingress;egress
type SecurityGroupRuleDirection string

const (
	TCP     SecurityGroupRuleProtocol  = "tcp"
	UDP     SecurityGroupRuleProtocol  = "udp"
	Ingress SecurityGroupRuleDirection = "ingress"
	Egress  SecurityGroupRuleDirection = "egress"
)

type SecurityGroupRulePortRange struct {
	// Start is the start of the range.
	// +kubebuilder:validation:Minimum=1
	Start int `json:"start"`
	// End is the end of the range.
	// +kubebuilder:validation:Maximum=65535
	End int `json:"end"`
}

// +kubebuilder:validation:XValidation:message="at least one of number or range must be defined",rule=(has(self.number) || has(self.range))
type SecurityGroupRulePort struct {
	// Number is the port number.
	Number *int `json:"number,omitempty"`
	// Range is the port range.
	Range *SecurityGroupRulePortRange `json:"range,omitempty"`
}

// OpenstackSecurityGroupRuleList is a typed list of security groups.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OpenstackSecurityGroupRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenstackSecurityGroupRule `json:"items"`
}

// OpenstackSecurityGroupRule has no controller, its a database record of state.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type OpenstackSecurityGroupRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OpenstackSecurityGroupRuleSpec   `json:"spec"`
	Status            OpenstackSecurityGroupRuleStatus `json:"status,omitempty"`
}

type OpenstackSecurityGroupRuleSpec struct {
	// SecurityGroupRuleID is the security group rule ID.
	SecurityGroupRuleID *string `json:"securityGroupRuleID,omitempty"`
}

type OpenstackSecurityGroupRuleStatus struct {
}

// ServerList is a typed list of servers.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Server `json:"items"`
}

// Server defines a server beloning to an identity.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="status",type="string",JSONPath=".status.conditions[?(@.type==\"Available\")].reason"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="privateIP",type="string",JSONPath=".status.privateIP"
// +kubebuilder:printcolumn:name="publicIP",type="string",JSONPath=".status.publicIP"
type Server struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ServerSpec   `json:"spec"`
	Status            ServerStatus `json:"status,omitempty"`
}

type ServerSpec struct {
	// Pause, if true, will inhibit reconciliation.
	Pause bool `json:"pause,omitempty"`
	// Tags are an abitrary list of key/value pairs that a client
	// may populate to store metadata for the resource.
	Tags unikornv1core.TagList `json:"tags,omitempty"`
	// Provider defines the provider type.
	Provider Provider `json:"provider"`
	// FlavorID is the flavor ID.
	FlavorID string `json:"flavorID"`
	// Image defines a set of rules to lookup for the server image.
	Image *ServerImage `json:"image"`
	// SecurityGroups is the server security groups.
	SecurityGroups []ServerSecurityGroupSpec `json:"securityGroups,omitempty"`
	// PublicIPAllocation is the server public IP allocation configuration.
	PublicIPAllocation *ServerPublicIPAllocationSpec `json:"publicIPAllocation,omitempty"`
	// Networks is the server network configuration.
	Networks []ServerNetworkSpec `json:"networks,omitempty"`
	// UserData contains configuration information or scripts to use upon launch.
	UserData []byte `json:"userData,omitempty"`
}

type ServerSecurityGroupSpec struct {
	// ID is the security group ID.
	ID string `json:"id"`
}

type ServerNetworkSpec struct {
	// ID is the physical network ID.
	ID string `json:"id"`
	// AllowedAddressPairs is a list of allowed address pairs for the network interface. This will allow multiple MAC/IP address (range) pairs to pass through this port.
	AllowedAddressPairs []ServerNetworkAddressPair `json:"allowedAddressPairs,omitempty"`
}

type ServerNetworkAddressPair struct {
	// CIDR is the CIDR block to allow traffic from.
	CIDR unikornv1core.IPv4Prefix `json:"cidr"`
	// Optional MAC address to allow traffic to/from.
	MACAddress string `json:"macAddress,omitempty"`
}

type ServerImage struct {
	// ID is the image ID. If specified, it has priority over the selector.
	ID string `json:"id"`
}

type ServerPublicIPAllocationSpec struct {
	// Enabled is a flag to enable public IP allocation.
	Enabled bool `json:"enabled,omitempty"`
}

type ServerStatus struct {
	// Current service state of a cluster manager.
	Conditions []unikornv1core.Condition `json:"conditions,omitempty"`
	// PrivateIP is the private IP address of the server.
	PrivateIP *string `json:"privateIP,omitempty"`
	// PublicIP is the public IP address of the server.
	PublicIP *string `json:"publicIP,omitempty"`
}

// OpenstackServerList is a typed list of servers.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OpenstackServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenstackServer `json:"items"`
}

// OpenstackServer has no controller, its a database record of state.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type OpenstackServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OpenstackServerSpec   `json:"spec"`
	Status            OpenstackServerStatus `json:"status,omitempty"`
}

type OpenstackServerSpec struct {
	// ServerID is the server ID.
	ServerID *string `json:"serverID,omitempty"`
	// PublicIPAllocationId is the public ip allocation id.
	PublicIPAllocationId *string `json:"publicIPAllocationId,omitempty"`
	// PortIDs is a list of port IDs.
	PortIDs []string `json:"portIDs,omitempty"`
}

type OpenstackServerStatus struct {
}
