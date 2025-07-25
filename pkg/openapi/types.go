// Package openapi provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.4.1 DO NOT EDIT.
package openapi

import (
	externalRef0 "github.com/unikorn-cloud/core/pkg/openapi"
)

const (
	Oauth2AuthenticationScopes = "oauth2Authentication.Scopes"
)

// Defines values for GpuVendor.
const (
	AMD    GpuVendor = "AMD"
	NVIDIA GpuVendor = "NVIDIA"
)

// Defines values for ImageVirtualization.
const (
	Any         ImageVirtualization = "any"
	Baremetal   ImageVirtualization = "baremetal"
	Virtualized ImageVirtualization = "virtualized"
)

// Defines values for NetworkDirection.
const (
	Egress  NetworkDirection = "egress"
	Ingress NetworkDirection = "ingress"
)

// Defines values for NetworkProtocol.
const (
	Tcp NetworkProtocol = "tcp"
	Udp NetworkProtocol = "udp"
)

// Defines values for OsDistro.
const (
	Rocky  OsDistro = "rocky"
	Ubuntu OsDistro = "ubuntu"
)

// Defines values for OsFamily.
const (
	Debian OsFamily = "debian"
	Redhat OsFamily = "redhat"
)

// Defines values for OsKernel.
const (
	Linux OsKernel = "linux"
)

// Defines values for RegionType.
const (
	Kubernetes RegionType = "kubernetes"
	Openstack  RegionType = "openstack"
)

// ExternalNetwork An Openstack external network.
type ExternalNetwork struct {
	// Id The resource ID.
	Id string `json:"id"`

	// Name The resource name.
	Name string `json:"name"`
}

// ExternalNetworks A list of openstack external networks.
type ExternalNetworks = []ExternalNetwork

// Flavor A flavor.
type Flavor struct {
	// Metadata This metadata is for resources that just exist, and don't require
	// any provisioning and health status, but benefit from a standardized
	// metadata format.
	Metadata externalRef0.StaticResourceMetadata `json:"metadata"`

	// Spec A flavor.
	Spec FlavorSpec `json:"spec"`
}

// FlavorSpec A flavor.
type FlavorSpec struct {
	// Baremetal Whether the flavor is for a dedicated machine.
	Baremetal *bool `json:"baremetal,omitempty"`

	// CpuFamily A free form CPU family description e.g. model number, architecture.
	CpuFamily *string `json:"cpuFamily,omitempty"`

	// Cpus The number of CPUs.
	Cpus int `json:"cpus"`

	// Disk The amount of ephemeral disk in GB.
	Disk int `json:"disk"`

	// Gpu GPU specification.
	Gpu *GpuSpec `json:"gpu,omitempty"`

	// Memory The amount of memory in GiB.
	Memory int `json:"memory"`
}

// Flavors A list of flavors.
type Flavors = []Flavor

// GpuModel A GPU model number.
type GpuModel = string

// GpuModelList A list of GPU model numbers.
type GpuModelList = []GpuModel

// GpuSpec GPU specification.
type GpuSpec struct {
	// LogicalCount The logical number of GPUs available as seen in the OS.
	LogicalCount int `json:"logicalCount"`

	// Memory GPU memory in GiB.
	Memory int `json:"memory"`

	// Model A GPU model.
	Model string `json:"model"`

	// PhysicalCount The physical number of GPUs (cards) available.
	PhysicalCount int `json:"physicalCount"`

	// Vendor The GPU vendor.
	Vendor GpuVendor `json:"vendor"`
}

// GpuVendor The GPU vendor.
type GpuVendor string

// IdentitiesRead A list of provider specific identities.
type IdentitiesRead = []IdentityRead

// IdentityRead A provider specific identity.
type IdentityRead struct {
	// Metadata Metadata required by project scoped resource reads.
	Metadata externalRef0.ProjectScopedResourceReadMetadata `json:"metadata"`

	// Spec A provider specific identity.
	Spec IdentitySpec `json:"spec"`
}

// IdentitySpec A provider specific identity.
type IdentitySpec struct {
	// Openstack Everything an OpenStack client needs to function.
	Openstack *IdentitySpecOpenStack `json:"openstack,omitempty"`

	// RegionId The region an identity is provisioned in.
	RegionId string `json:"regionId"`

	// Type The region's provider type.
	Type RegionType `json:"type"`
}

// IdentitySpecOpenStack Everything an OpenStack client needs to function.
type IdentitySpecOpenStack struct {
	// Cloud The name of the cloud in the cloud config.
	Cloud *string `json:"cloud,omitempty"`

	// CloudConfig A base64 encoded cloud config file.
	CloudConfig *string `json:"cloudConfig,omitempty"`

	// ProjectId Project identifier allocated for the infrastructure.
	ProjectId *string `json:"projectId,omitempty"`

	// ServerGroupId Server group identifier allocated for the intrastructure.
	ServerGroupId *string `json:"serverGroupId,omitempty"`

	// SshKeyName Ephemeral SSH key generated for the identity.
	SshKeyName *string `json:"sshKeyName,omitempty"`

	// SshPrivateKey Ephemeral SSH private key to be used by higher order services.
	SshPrivateKey *string `json:"sshPrivateKey,omitempty"`

	// UserId User identitifer allocated for the infrastructure.
	UserId *string `json:"userId,omitempty"`
}

// IdentityWrite An identity request.
type IdentityWrite struct {
	// Metadata Metadata required for all API resource reads and writes.
	Metadata externalRef0.ResourceWriteMetadata `json:"metadata"`

	// Spec Request parameters for creating an identity.
	Spec IdentityWriteSpec `json:"spec"`
}

// IdentityWriteSpec Request parameters for creating an identity.
type IdentityWriteSpec struct {
	// RegionId The region an identity is provisioned in.
	RegionId string `json:"regionId"`
}

// Image An image.
type Image struct {
	// Metadata This metadata is for resources that just exist, and don't require
	// any provisioning and health status, but benefit from a standardized
	// metadata format.
	Metadata externalRef0.StaticResourceMetadata `json:"metadata"`

	// Spec An image.
	Spec ImageSpec `json:"spec"`
}

// ImageGpu The GPU driver if installed.
type ImageGpu struct {
	// Driver The GPU driver version, this is vendor specific.
	Driver string `json:"driver"`

	// Models A list of GPU model numbers.
	Models *GpuModelList `json:"models,omitempty"`

	// Vendor The GPU vendor.
	Vendor GpuVendor `json:"vendor"`
}

// ImageOS An operating system description.
type ImageOS struct {
	// Codename A free form code name e.g. warty/bionic.
	Codename *string `json:"codename,omitempty"`

	// Distro A distribution name.
	Distro OsDistro `json:"distro"`

	// Family A family of operating systems.  This typically defines the package format.
	Family OsFamily `json:"family"`

	// Kernel A kernel type.
	Kernel OsKernel `json:"kernel"`

	// Variant A free form variant e.g. desktop/server.
	Variant *string `json:"variant,omitempty"`

	// Version Version of the operating system e.g. "24.04".
	Version string `json:"version"`
}

// ImageSpec An image.
type ImageSpec struct {
	// Gpu The GPU driver if installed.
	Gpu *ImageGpu `json:"gpu,omitempty"`

	// Os An operating system description.
	Os ImageOS `json:"os"`

	// SizeGiB Minimum disk size required to use the image in GiB.
	SizeGiB int `json:"sizeGiB"`

	// SoftwareVersions Image preinstalled version version metadata.
	SoftwareVersions *SoftwareVersions `json:"softwareVersions,omitempty"`

	// Virtualization What type of machine the image is for.
	Virtualization ImageVirtualization `json:"virtualization"`
}

// ImageVirtualization What type of machine the image is for.
type ImageVirtualization string

// Images A list of images that are compatible with this platform.
type Images = []Image

// Ipv4Address An IPv4 address.
type Ipv4Address = string

// Ipv4AddressList A list of IPv4 addresses.
type Ipv4AddressList = []Ipv4Address

// KubernetesNameParameter A Kubernetes name. Must be a valid DNS containing only lower case characters, numbers or hyphens, start and end with a character or number, and be at most 63 characters in length.
type KubernetesNameParameter = string

// NetworkDirection The direction of the rule.
type NetworkDirection string

// NetworkProtocol The protocol to allow.
type NetworkProtocol string

// NetworkRead A network.
type NetworkRead struct {
	// Metadata Metadata required by project scoped resource reads.
	Metadata externalRef0.ProjectScopedResourceReadMetadata `json:"metadata"`

	// Spec A physical network's specification.
	Spec NetworkReadSpec `json:"spec"`
}

// NetworkReadSpec A physical network's specification.
type NetworkReadSpec struct {
	// DnsNameservers A list of IPv4 addresses.
	DnsNameservers Ipv4AddressList `json:"dnsNameservers"`

	// Openstack An openstack network.
	Openstack *NetworkSpecOpenstack `json:"openstack,omitempty"`

	// Prefix An IPv4 prefix for the network.
	Prefix string `json:"prefix"`

	// RegionId The region an identity is provisioned in.
	RegionId string `json:"regionId"`

	// Type The region's provider type.
	Type RegionType `json:"type"`
}

// NetworkSpecOpenstack An openstack network.
type NetworkSpecOpenstack struct {
	// NetworkId The openstack network ID.
	NetworkId *string `json:"networkId,omitempty"`

	// RouterId The openstack router ID.
	RouterId *string `json:"routerId,omitempty"`

	// SubnetId The openstack subnet ID.
	SubnetId *string `json:"subnetId,omitempty"`

	// VlanId The allocated VLAN ID.
	VlanId *int `json:"vlanId,omitempty"`
}

// NetworkWrite A network request.
type NetworkWrite struct {
	// Metadata Metadata required for all API resource reads and writes.
	Metadata externalRef0.ResourceWriteMetadata `json:"metadata"`

	// Spec A physical network's specification.
	Spec *NetworkWriteSpec `json:"spec,omitempty"`
}

// NetworkWriteSpec A physical network's specification.
type NetworkWriteSpec struct {
	// DnsNameservers A list of IPv4 addresses.
	DnsNameservers Ipv4AddressList `json:"dnsNameservers"`

	// Prefix An IPv4 prefix for the network.
	Prefix string `json:"prefix"`
}

// NetworksRead A list of networks.
type NetworksRead = []NetworkRead

// OsDistro A distribution name.
type OsDistro string

// OsFamily A family of operating systems.  This typically defines the package format.
type OsFamily string

// OsKernel A kernel type.
type OsKernel string

// RegionDetailKubernetes Region specific information when the type is "kubernetes".
type RegionDetailKubernetes struct {
	// DomainName The region's requested domain name for consuming services.
	DomainName *string `json:"domainName,omitempty"`

	// Kubeconfig The region's base64 encoded Kubernetes configuration file.
	Kubeconfig string `json:"kubeconfig"`
}

// RegionDetailRead A region.
type RegionDetailRead struct {
	// Metadata Metadata required by all resource reads.
	Metadata externalRef0.ResourceReadMetadata `json:"metadata"`

	// Spec Information about the region.
	Spec RegionDetailSpec `json:"spec"`
}

// RegionDetailSpec Information about the region.
type RegionDetailSpec struct {
	// Features A set of features the region may provide to clients.
	Features RegionFeatures `json:"features"`

	// Kubernetes Region specific information when the type is "kubernetes".
	Kubernetes *RegionDetailKubernetes `json:"kubernetes,omitempty"`

	// Type The region's provider type.
	Type RegionType `json:"type"`
}

// RegionFeatures A set of features the region may provide to clients.
type RegionFeatures struct {
	// PhysicalNetworks If set, this indicates that the region supports physical networks and
	// one should be provisioned for clusters to use.  The implication here is
	// the region supports base-metal machines, and these must be provisioned
	// on a physical VLAN etc.
	PhysicalNetworks bool `json:"physicalNetworks"`
}

// RegionRead A region.
type RegionRead struct {
	// Metadata Metadata required by all resource reads.
	Metadata externalRef0.ResourceReadMetadata `json:"metadata"`

	// Spec Information about the region.
	Spec RegionSpec `json:"spec"`
}

// RegionSpec Information about the region.
type RegionSpec struct {
	// Features A set of features the region may provide to clients.
	Features RegionFeatures `json:"features"`

	// Type The region's provider type.
	Type RegionType `json:"type"`
}

// RegionType The region's provider type.
type RegionType string

// Regions A list of regions.
type Regions = []RegionRead

// SecurityGroupRead A security group.
type SecurityGroupRead struct {
	// Metadata Metadata required by project scoped resource reads.
	Metadata externalRef0.ProjectScopedResourceReadMetadata `json:"metadata"`

	// Spec A security group's specification.
	Spec SecurityGroupReadSpec `json:"spec"`
}

// SecurityGroupReadSpec A security group's specification.
type SecurityGroupReadSpec struct {
	// RegionId The region an identity is provisioned in.
	RegionId string `json:"regionId"`
}

// SecurityGroupRulePort The port definition to allow traffic.
type SecurityGroupRulePort struct {
	// Number The port to allow.
	Number *int `json:"number,omitempty"`

	// Range The port range to allow traffic.
	Range *SecurityGroupRulePortRange `json:"range,omitempty"`
}

// SecurityGroupRulePortRange The port range to allow traffic.
type SecurityGroupRulePortRange struct {
	// End The end of the port range.
	End int `json:"end"`

	// Start The start of the port range.
	Start int `json:"start"`
}

// SecurityGroupRuleRead A security group rule.
type SecurityGroupRuleRead struct {
	// Metadata Metadata required by project scoped resource reads.
	Metadata externalRef0.ProjectScopedResourceReadMetadata `json:"metadata"`

	// Spec A security group rule's specification.
	Spec SecurityGroupRuleSpec `json:"spec"`
}

// SecurityGroupRuleSpec A security group rule's specification.
type SecurityGroupRuleSpec struct {
	// Cidr An IPv4 address.
	Cidr Ipv4Address `json:"cidr"`

	// Direction The direction of the rule.
	Direction NetworkDirection `json:"direction"`

	// Port The port definition to allow traffic.
	Port SecurityGroupRulePort `json:"port"`

	// Protocol The protocol to allow.
	Protocol NetworkProtocol `json:"protocol"`
}

// SecurityGroupRuleWrite A security group rule request.
type SecurityGroupRuleWrite struct {
	// Metadata Metadata required for all API resource reads and writes.
	Metadata externalRef0.ResourceWriteMetadata `json:"metadata"`

	// Spec A security group rule's specification.
	Spec SecurityGroupRuleSpec `json:"spec"`
}

// SecurityGroupRulesRead A list of security group rules.
type SecurityGroupRulesRead = []SecurityGroupRuleRead

// SecurityGroupWrite A security group request.
type SecurityGroupWrite struct {
	// Metadata Metadata required for all API resource reads and writes.
	Metadata externalRef0.ResourceWriteMetadata `json:"metadata"`

	// Spec A security group's specification.
	Spec *SecurityGroupWriteSpec `json:"spec,omitempty"`
}

// SecurityGroupWriteSpec A security group's specification.
type SecurityGroupWriteSpec = map[string]interface{}

// SecurityGroupsRead A list of security groups.
type SecurityGroupsRead = []SecurityGroupRead

// ServerNetwork The server's network.
type ServerNetwork struct {
	// AllowedAddressPairs A list of allowed address pairs.
	AllowedAddressPairs *ServerNetworkAllowedAddressPairList `json:"allowedAddressPairs,omitempty"`

	// Id Network to attach the server to
	Id string `json:"id"`
}

// ServerNetworkAllowedAddressPair Allow multiple MAC/IP address (range) pairs to pass through this network port.
type ServerNetworkAllowedAddressPair struct {
	// Cidr The CIDR to allow.
	Cidr string `json:"cidr"`

	// MacAddress The MAC address to allow.
	MacAddress *string `json:"macAddress,omitempty"`
}

// ServerNetworkAllowedAddressPairList A list of allowed address pairs.
type ServerNetworkAllowedAddressPairList = []ServerNetworkAllowedAddressPair

// ServerNetworkList A list of networks.
type ServerNetworkList = []ServerNetwork

// ServerPublicIPAllocation The server's public IP allocation.
type ServerPublicIPAllocation struct {
	// Enabled Whether to allocate a public IP.
	Enabled bool `json:"enabled"`
}

// ServerRead A server.
type ServerRead struct {
	// Metadata Metadata required by project scoped resource reads.
	Metadata externalRef0.ProjectScopedResourceReadMetadata `json:"metadata"`

	// Spec A server's specification.
	Spec ServerSpec `json:"spec"`

	// Status A server's status.
	Status ServerStatus `json:"status"`
}

// ServerSecurityGroup A security group.
type ServerSecurityGroup struct {
	// Id The security group ID.
	Id string `json:"id"`
}

// ServerSecurityGroupList A list of security groups.
type ServerSecurityGroupList = []ServerSecurityGroup

// ServerSpec A server's specification.
type ServerSpec struct {
	// FlavorId The flavor of the server.
	FlavorId string `json:"flavorId"`

	// ImageId The image of the server.
	ImageId string `json:"imageId"`

	// Networks A list of networks.
	Networks ServerNetworkList `json:"networks"`

	// PublicIPAllocation The server's public IP allocation.
	PublicIPAllocation *ServerPublicIPAllocation `json:"publicIPAllocation,omitempty"`

	// SecurityGroups A list of security groups.
	SecurityGroups *ServerSecurityGroupList `json:"securityGroups,omitempty"`

	// UserData UserData contains base64-encoded configuration information or scripts to use upon launch.
	UserData *[]byte `json:"userData,omitempty"`
}

// ServerStatus A server's status.
type ServerStatus struct {
	// PrivateIP The private IP address of the server.
	PrivateIP *string `json:"privateIP,omitempty"`

	// PublicIP The public IP address of the server.
	PublicIP *string `json:"publicIP,omitempty"`
}

// ServerWrite A server request.
type ServerWrite struct {
	// Metadata Metadata required for all API resource reads and writes.
	Metadata externalRef0.ResourceWriteMetadata `json:"metadata"`

	// Spec A server's specification.
	Spec ServerSpec `json:"spec"`
}

// ServersRead A list of servers.
type ServersRead = []ServerRead

// SoftwareVersions Image preinstalled version version metadata.
type SoftwareVersions map[string]externalRef0.Semver

// IdentityIDParameter A Kubernetes name. Must be a valid DNS containing only lower case characters, numbers or hyphens, start and end with a character or number, and be at most 63 characters in length.
type IdentityIDParameter = KubernetesNameParameter

// NetworkIDParameter A Kubernetes name. Must be a valid DNS containing only lower case characters, numbers or hyphens, start and end with a character or number, and be at most 63 characters in length.
type NetworkIDParameter = KubernetesNameParameter

// OrganizationIDParameter defines model for organizationIDParameter.
type OrganizationIDParameter = string

// ProjectIDParameter A Kubernetes name. Must be a valid DNS containing only lower case characters, numbers or hyphens, start and end with a character or number, and be at most 63 characters in length.
type ProjectIDParameter = KubernetesNameParameter

// RegionIDParameter A Kubernetes name. Must be a valid DNS containing only lower case characters, numbers or hyphens, start and end with a character or number, and be at most 63 characters in length.
type RegionIDParameter = KubernetesNameParameter

// RuleIDParameter A Kubernetes name. Must be a valid DNS containing only lower case characters, numbers or hyphens, start and end with a character or number, and be at most 63 characters in length.
type RuleIDParameter = KubernetesNameParameter

// SecurityGroupIDParameter A Kubernetes name. Must be a valid DNS containing only lower case characters, numbers or hyphens, start and end with a character or number, and be at most 63 characters in length.
type SecurityGroupIDParameter = KubernetesNameParameter

// ServerIDParameter A Kubernetes name. Must be a valid DNS containing only lower case characters, numbers or hyphens, start and end with a character or number, and be at most 63 characters in length.
type ServerIDParameter = KubernetesNameParameter

// ExternalNetworksResponse A list of openstack external networks.
type ExternalNetworksResponse = ExternalNetworks

// FlavorsResponse A list of flavors.
type FlavorsResponse = Flavors

// IdentitiesResponse A list of provider specific identities.
type IdentitiesResponse = IdentitiesRead

// IdentityResponse A provider specific identity.
type IdentityResponse = IdentityRead

// ImagesResponse A list of images that are compatible with this platform.
type ImagesResponse = Images

// NetworkResponse A network.
type NetworkResponse = NetworkRead

// NetworksResponse A list of networks.
type NetworksResponse = NetworksRead

// RegionDetailResponse A region.
type RegionDetailResponse = RegionDetailRead

// RegionsResponse A list of regions.
type RegionsResponse = Regions

// SecurityGroupResponse A security group.
type SecurityGroupResponse = SecurityGroupRead

// SecurityGroupRuleResponse A security group rule.
type SecurityGroupRuleResponse = SecurityGroupRuleRead

// SecurityGroupRulesResponse A list of security group rules.
type SecurityGroupRulesResponse = SecurityGroupRulesRead

// SecurityGroupsResponse A list of security groups.
type SecurityGroupsResponse = SecurityGroupsRead

// ServerResponse A server.
type ServerResponse = ServerRead

// ServersResponse A list of servers.
type ServersResponse = ServersRead

// IdentityRequest An identity request.
type IdentityRequest = IdentityWrite

// NetworkRequest A network request.
type NetworkRequest = NetworkWrite

// SecurityGroupRequest A security group request.
type SecurityGroupRequest = SecurityGroupWrite

// SecurityGroupRuleRequest A security group rule request.
type SecurityGroupRuleRequest = SecurityGroupRuleWrite

// ServerRequest A server request.
type ServerRequest = ServerWrite

// GetApiV1OrganizationsOrganizationIDSecuritygroupsParams defines parameters for GetApiV1OrganizationsOrganizationIDSecuritygroups.
type GetApiV1OrganizationsOrganizationIDSecuritygroupsParams struct {
	// Tag A set of tags to match against resources in the form "name=value",
	// thus when encoded you get "?tag=foo%3Dcat&bar%3Ddog".
	Tag *externalRef0.TagSelectorParameter `form:"tag,omitempty" json:"tag,omitempty"`
}

// GetApiV1OrganizationsOrganizationIDServersParams defines parameters for GetApiV1OrganizationsOrganizationIDServers.
type GetApiV1OrganizationsOrganizationIDServersParams struct {
	// Tag A set of tags to match against resources in the form "name=value",
	// thus when encoded you get "?tag=foo%3Dcat&bar%3Ddog".
	Tag *externalRef0.TagSelectorParameter `form:"tag,omitempty" json:"tag,omitempty"`
}

// PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesJSONRequestBody defines body for PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentities for application/json ContentType.
type PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesJSONRequestBody = IdentityWrite

// PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDNetworksJSONRequestBody defines body for PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDNetworks for application/json ContentType.
type PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDNetworksJSONRequestBody = NetworkWrite

// PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsJSONRequestBody defines body for PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroups for application/json ContentType.
type PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsJSONRequestBody = SecurityGroupWrite

// PutApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDJSONRequestBody defines body for PutApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupID for application/json ContentType.
type PutApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDJSONRequestBody = SecurityGroupWrite

// PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDRulesJSONRequestBody defines body for PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDRules for application/json ContentType.
type PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDSecuritygroupsSecurityGroupIDRulesJSONRequestBody = SecurityGroupRuleWrite

// PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersJSONRequestBody defines body for PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServers for application/json ContentType.
type PostApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersJSONRequestBody = ServerWrite

// PutApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDJSONRequestBody defines body for PutApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerID for application/json ContentType.
type PutApiV1OrganizationsOrganizationIDProjectsProjectIDIdentitiesIdentityIDServersServerIDJSONRequestBody = ServerWrite
