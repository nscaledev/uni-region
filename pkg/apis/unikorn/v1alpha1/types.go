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
	// FlavorExtraSpecsExclude discards any flavors with the listed
	// extra specs keys.
	FlavorExtraSpecsExclude []string `json:"flavorExtraSpecsExclude,omitempty"`
	// GPUDescriptors defines a set of keys that can be probed to
	// list GPU topology information.
	GPUDescriptors []OpenstackGPUDescriptor `json:"gpuDescriptors,omitempty"`
}

type OpenstackGPUDescriptor struct {
	// Property is the property name to examine e.g. "resources.VGPU".
	Property string `json:"property"`
	// Expression describes how to extract the number of GPUs from the property
	// if it exists.  This must contain exactly one submatch that is a number
	// e.g. "^(\d+)$".
	Expression string `json:"expression"`
}

type RegionOpenstackImageSpec struct {
	// PropertiesInclude defines the set of properties that must all exist
	// for an image to be advertised by the provider.
	PropertiesInclude []string `json:"propertiesInclude,omitempty"`
	// SigningKey defines a PEM encoded public ECDSA signing key used to verify
	// the image is trusted.  If specified, an image must contain the "digest"
	// property, the value of which must be a base64 encoded ECDSA signature of
	// the SHA256 hash of the image ID.
	SigningKey []byte `json:"signingKey,omitempty"`
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
	// Provider defines the provider type.
	Provider Provider `json:"provider"`
	// OpenStack is populated when the provider type is set to "openstack".
	OpenStack *IdentitySpecOpenStack `json:"openstack,omitempty"`
}

type IdentitySpecOpenStack struct {
	// UserID is the ID of the user created for the identity.
	UserID string
	// ProjectIS is the ID of the project created for the identity.
	ProjectID string
}

type IdentityStatus struct {
}
