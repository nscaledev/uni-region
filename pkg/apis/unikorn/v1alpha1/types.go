/*
Copyright 2022-2024 EscherCloud.
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

//nolint:tagliatelle
package v1alpha1

import (
	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Provider is used to communicate the cloud type.
// NOTE: the maximum length is limited to 63 characters, as it's used to generate
// region specific resource names by appending the region ID to the provider type
// e.g. openstack.e1354668-5617-44ea-9073-372aa8e5c5ca.
// +kubebuilder:validation:Enum=openstack;kubernetes
// +kubebuilder:validation:MaxLength=63
type Provider string

const (
	ProviderKubernetes Provider = "kubernetes"
	ProviderOpenstack  Provider = "openstack"
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
// +kubebuilder:validation:XValidation:rule="self.provider == \"openstack\" ? has(self.openstack) : true",message="openstack definition required for region of openstack type"
// +kubebuilder:validation:XValidation:rule="self.provider == \"kubernetes\" ? has(self.kubernetes) : true",message="kubernetes definition required for region of kubernetes type"
type RegionSpec struct {
	// Tags are aribrary user data.
	Tags unikornv1core.TagList `json:"tags,omitempty"`
	// Security controls region visibility.
	Security *RegionSecuritySpec `json:"security,omitempty"`
	// Type defines the provider type.
	Provider Provider `json:"provider"`
	// Kubernetes is provider specific configuration for the region.
	Kubernetes *RegionKubernetesSpec `json:"kubernetes,omitempty"`
	// Openstack is provider specific configuration for the region.
	Openstack *RegionOpenstackSpec `json:"openstack,omitempty"`
}

// NOTE: Organizations deliberately doesn't define just a slice of IDs, even though
// slices.Contains is easy, so we can potentially extend this in future to allow
// projects to have private regions.
type RegionSecuritySpec struct {
	// Organizations if not empty limits access to the region based on the
	// rules defined within.
	Organizations []RegionSecurityOrganizationSpec `json:"organizations,omitempty"`
}

type RegionSecurityOrganizationSpec struct {
	// ID identifies the organization ID that may access the region.
	ID string `json:"id"`
}

type RegionKubernetesSpec struct {
	// Kubeconfig for the remote region.
	KubeconfigSecret *NamespacedObject `json:"kubeConfigSecret"`
	// Nodes describes the cluster nodes.
	// +listType=map
	// +listMapKey=id
	Nodes []RegionKubernetesNodeSpec `json:"nodes,omitempty"`
	// DomainName is the domain services in this region should
	// be provisioned under.
	DomainName string `json:"domainName,omitempty"`
}

type RegionKubernetesNodeSpec struct {
	// ID maps to a node label kubernetes.region.unikorn-cloud.org/node-class.
	// Only nodes with this label will be exported as "flavors", thus providing
	// a way to hide nodes from end users e.g. control planes and the like.
	ID string `json:"id"`
	// Name is the name of the flavor.
	Name string `json:"name"`
	// CPU defines additional CPU metadata.
	CPU *CPUSpec `json:"cpu"`
	// Memory allows the memory amount to be specified.
	Memory *resource.Quantity `json:"memory"`
	// Disk allows the disk size to be specified.
	Disk *resource.Quantity `json:"disk"`
	// GPU defines additional GPU metadata.  When provided it will enable selection
	// of images based on GPU vendor and model.
	GPU *GPUSpec `json:"gpu,omitempty"`
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

// +kubebuilder:validation:Enum=x86_64;aarch64
type Architecture string

const (
	//nolint:revive
	X86_64  Architecture = "x86_64"
	Aarch64 Architecture = "aarch64"
)

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
	// Architecture is the CPU architecture.
	Architecture *Architecture `json:"architecture,omitempty"`
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
	// TODO: V1 hackery only, delete me.
	Provider Provider `json:"provider,omitempty"`
	// Prefix is the IPv4 address prefix.
	Prefix *unikornv1core.IPv4Prefix `json:"prefix"`
	// DNSNameservers are a set of DNS nameservrs for the network.
	DNSNameservers []unikornv1core.IPv4Address `json:"dnsNameservers"`
	// Routes to be distributed via DHCP.
	Routes []Route `json:"routes,omitempty"`
}

type Route struct {
	// Prefix to match when forwarding.
	Prefix unikornv1core.IPv4Prefix `json:"prefix"`
	// NextHop address to forward the traffic to.
	NextHop unikornv1core.IPv4Address `json:"nextHop"`
}

// TODO: delete me.
type NetworkStatusOpenstack struct {
	// NetworkID is the network ID.
	NetworkID *string `json:"networkID,omitempty"`
	// SubnetID is the subnet ID.
	SubnetID *string `json:"subnetID,omitempty"`
	// VlanID is the VLAN ID for this network
	VlanID *int `json:"vlanID,omitempty"`
	// StorageRange gives the start and end IP addresses for attaching to storage (e.g., FileStorage)
	StorageRange *AttachmentIPRange `json:"storageRange,omitempty"`
}

type NetworkStatus struct {
	// Current service state of a cluster manager.
	Conditions []unikornv1core.Condition `json:"conditions,omitempty"`
	// TODO: delete me.
	Openstack *NetworkStatusOpenstack `json:"openstack,omitempty"`
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
	// Rules is a list of security group rules.
	// +kubebuilder:validation:MinimumLength=1
	Rules []SecurityGroupRule `json:"rules,omitempty"`
}

type SecurityGroupStatus struct {
	// Current service state of a security group.
	Conditions []unikornv1core.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:validation:Enum=any;icmp;tcp;udp;vrrp
type SecurityGroupRuleProtocol string

const (
	Any  SecurityGroupRuleProtocol = "any"
	ICMP SecurityGroupRuleProtocol = "icmp"
	TCP  SecurityGroupRuleProtocol = "tcp"
	UDP  SecurityGroupRuleProtocol = "udp"
	VRRP SecurityGroupRuleProtocol = "vrrp"
)

// +kubebuilder:validation:Enum=ingress;egress
type SecurityGroupRuleDirection string

const (
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

type SecurityGroupRule struct {
	// Direction is the direction of the rule.
	Direction SecurityGroupRuleDirection `json:"direction"`
	// Protocol is the protocol of the rule.
	Protocol SecurityGroupRuleProtocol `json:"protocol"`
	// Port is the port or range of ports.
	Port *SecurityGroupRulePort `json:"port,omitempty"`
	// CIDR is the CIDR block to allow traffic from.
	CIDR *unikornv1core.IPv4Prefix `json:"cidr,omitempty"`
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
	Provider Provider `json:"provider,omitempty"`
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

// +kubebuilder:validation:Enum=Pending;Running;Stopping;Stopped
type InstanceLifecyclePhase string

const (
	InstanceLifecyclePhasePending  InstanceLifecyclePhase = "Pending"
	InstanceLifecyclePhaseRunning  InstanceLifecyclePhase = "Running"
	InstanceLifecyclePhaseStopping InstanceLifecyclePhase = "Stopping"
	InstanceLifecyclePhaseStopped  InstanceLifecyclePhase = "Stopped"
)

type ServerStatus struct {
	// Current service state of a cluster manager.
	Conditions []unikornv1core.Condition `json:"conditions,omitempty"`
	// Phase is the current lifecycle phase of the server.
	Phase InstanceLifecyclePhase `json:"phase,omitempty"`
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
	// PublicIPAllocationID is the public ip allocation id.
	PublicIPAllocationID *string `json:"publicIPAllocationId,omitempty"`
	// PortIDs is a list of port IDs.
	PortIDs []string `json:"portIDs,omitempty"`
}

type OpenstackServerStatus struct {
}

// FileStorageList is a list of FileStorage types.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type FileStorageList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FileStorage `json:"items"`
}

// FileStorage defines a FileStorageSpec.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="status",type="string",JSONPath=".status.conditions[?(@.type==\"Available\")].reason"
// +kubebuilder:printcolumn:name="size",type="string",JSONPath=".spec.size"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type FileStorage struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FileStorageSpec   `json:"spec"`
	Status            FileStorageStatus `json:"status,omitempty"`
}

// FileStorageSpec defines the storage request.
type FileStorageSpec struct {
	// StorageClassID is the storage class ID.
	StorageClassID string `json:"storageClassID"`

	// Size is the total size of the file storage.
	Size resource.Quantity `json:"size"`

	// Attachments are the network attachments for the storage.
	Attachments []Attachment `json:"attachments,omitempty"`

	// Tags are an abitrary list of key/value pairs that a client
	// may populate to store metadata for the resource.
	// Tags are aribrary user data.
	Tags unikornv1core.TagList `json:"tags,omitempty"`

	// Pause, if true, will inhibit reconciliation.
	Pause bool `json:"pause,omitempty"`

	// NFS is fulfilled when leveraging the NFS storage class.
	NFS *NFS `json:"nfs,omitempty"`
}

// Protocol defines which storage protocol to leverage.
// +kubebuilder:validation:Enum=nfsv3;nfsv4
type Protocol string

const (
	NFSv3 Protocol = "nfsv3"
	NFSv4 Protocol = "nfsv4"
)

type FileStorageStatus struct {
	// ObservedGeneration is the most recent generation observed by the controller.
	ObservedGeneration *int64 `json:"observedGeneration,omitempty"`
	// Current service state of a file storage.
	Conditions []unikornv1core.Condition `json:"conditions,omitempty"`
	// Size is the currently provisioned/observed size of the file storage.
	// (May differ from spec.size while provisioning/resizing.)
	Size *resource.Quantity `json:"size,omitempty"`
	// MountPath is the path where the file storage is mounted.
	MountPath *string `json:"mountPath,omitempty"`
	// Attachments reflects the observed attachment state per network.
	// +listType=map
	// +listMapKey=networkID
	// +patchStrategy=merge
	// +patchMergeKey=networkID
	// +optional
	Attachments []FileStorageAttachmentStatus `json:"attachments,omitempty"`
}

// AttachmentProvisioningStatus describes the state of a single attachment.
// +kubebuilder:validation:Enum=Provisioning;Provisioned;Errored;Deprovisioning
type AttachmentProvisioningStatus string

const (
	AttachmentProvisioning   AttachmentProvisioningStatus = "Provisioning"
	AttachmentProvisioned    AttachmentProvisioningStatus = "Provisioned"
	AttachmentErrored        AttachmentProvisioningStatus = "Errored"
	AttachmentDeprovisioning AttachmentProvisioningStatus = "Deprovisioning"
)

type FileStorageAttachmentStatus struct {
	// NetworkID is the network ID for the attachment.
	NetworkID string `json:"networkID"`
	// ProvisioningStatus indicates if this attachment is ready/failed/etc.
	ProvisioningStatus AttachmentProvisioningStatus `json:"provisioningStatus"`
	// SegmentationID is the VLAN ID for the attachment.
	SegmentationID *int `json:"segmentationID,omitempty"`
	// Human-readable message indicating details about the attachment.
	Message string `json:"message"`
}

// Attachment has the network identifier for the storage.
type Attachment struct {
	// NetworkID is the network ID for the attachment.
	NetworkID string `json:"networkID"`
	// SegmentationID is the VLAN ID for the attachment.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4094
	SegmentationID *int `json:"segmentationID,omitempty"`
	// IPRange is the IP range for the attachment.
	IPRange *AttachmentIPRange `json:"ipRange,omitempty"`
}

type AttachmentIPRange struct {
	// Start is the start IP address for the attachment.
	Start unikornv1core.IPv4Address `json:"startIP"`
	// End is the end IP address for the attachment.
	End unikornv1core.IPv4Address `json:"endIP"`
}

// NFS has the configuration for NFS type.
type NFS struct {
	RootSquash bool `json:"rootSquash,omitempty"`
}

// FileStorageClassList is a list of the FileStorageClass type.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type FileStorageClassList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FileStorageClass `json:"items"`
}

// FileStorageClass defines the storage protocols, optional QoS guarantees and the service provider.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="protocols",type="string",JSONPath=".spec.protocols"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type FileStorageClass struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Status            FileStorageClassStatus `json:"status,omitempty"`
	Spec              FileStorageClassSpec   `json:"spec"`
}

// FileStorageClassSpec defines the FileStorageClass.
type FileStorageClassSpec struct {
	// Provisioner is the name of the provisioner to use for the file storage class.
	Provisioner string `json:"provisioner"`
	// Protocols specifies the storage protocols (e.g., NFSv3, NFSv4) supported by this class.
	Protocols []Protocol `json:"protocols,omitempty"`
}

type FileStorageClassStatus struct{}

// FileStorageProvisionerList is a list of the FileStorageProvisioner type.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type FileStorageProvisionerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FileStorageProvisioner `json:"items"`
}

// FileStorageProvisioner defines the file storage provisioner.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type FileStorageProvisioner struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Status            FileStorageProvisionerStatus `json:"status,omitempty"`
	Spec              FileStorageProvisionerSpec   `json:"spec"`
}

type FileStorageProvisionerSpec struct {
	// ConfigRef is the reference to the config map for the file storage provisioner.
	ConfigRef *NamespacedObject `json:"configRef,omitempty"`
}

type FileStorageProvisionerStatus struct{}
