/*
Copyright 2022-2024 EscherCloud.
Copyright 2024 the Unikorn Authors.

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
	// Memory is the amount of memory each logical GPU has access to.
	Memory *resource.Quantity `json:"memory"`
	// Count is the number of logical GPUs in the flavor.
	Count int `json:"count"`
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
	// PhysicalNetwork is the neutron provider specific network name used
	// to provision provider networks e.g. VLANs for bare metal clusters.
	PhysicalNetwork *string `json:"physicalNetwork,omitempty"`
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

// Tag is an arbirary key/value.
type Tag struct {
	// Name of the tag.
	Name string `json:"name"`
	// Value of the tag.
	Value string `json:"value"`
}

// TagList is an ordered list of tags.
type TagList []Tag

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
// +kubebuilder:printcolumn:name="provider",type="string",JSONPath=".spec.provider"
// +kubebuilder:printcolumn:name="status",type="string",JSONPath=".status.conditions[?(@.type==\"Available\")].reason"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type Identity struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              IdentitySpec   `json:"spec"`
	Status            IdentityStatus `json:"status"`
}

// IdentitySpec stores any state necessary to manage identity.
type IdentitySpec struct {
	// Tags are an abitrary list of key/value pairs that a client
	// may populate to store metadata for the resource.
	Tags TagList `json:"tags,omitempty"`
	// Provider defines the provider type.
	Provider Provider `json:"provider"`
	// OpenStack is populated when the provider type is set to "openstack".
	OpenStack *IdentitySpecOpenStack `json:"openstack,omitempty"`
}

type IdentitySpecOpenStack struct {
	// CloudConfig is a client compatible cloud configuration.
	CloudConfig []byte `json:"cloudConfig"`
	// Cloud is the cloud name in the cloud config to use.
	Cloud string `json:"cloud"`
	// UserID is the ID of the user created for the identity.
	UserID string `json:"userID"`
	// ProjectID is the ID of the project created for the identity.
	ProjectID string `json:"projectID"`
	// ServerGroupID is the ID of the server group created for the identity.
	ServerGroupID *string `json:"serverGroupID,omitempty"`
}

type IdentityStatus struct {
}

// PhysicalNetworkList s a typed list of physical networks.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type PhysicalNetworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PhysicalNetwork `json:"items"`
}

// PhysicalNetwork defines a physical network beloning to an identity.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:printcolumn:name="status",type="string",JSONPath=".status.conditions[?(@.type==\"Available\")].reason"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type PhysicalNetwork struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              PhysicalNetworkSpec   `json:"spec"`
	Status            PhysicalNetworkStatus `json:"status"`
}

type PhysicalNetworkSpec struct {
	// Tags are an abitrary list of key/value pairs that a client
	// may populate to store metadata for the resource.
	Tags TagList `json:"tags,omitempty"`
	// ProviderNetwork is the provider network for port allocation of
	// virtual machines.
	ProviderNetwork *OpenstackProviderNetworkSpec `json:"providerNetwork,omitempty"`
}

type OpenstackProviderNetworkSpec struct {
	// ID is the network ID.
	ID string `json:"id"`
	// VlanID is the ID if the VLAN for IPAM.
	VlanID int `json:"vlanID"`
}

type PhysicalNetworkStatus struct {
}
