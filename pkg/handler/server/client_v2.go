/*
Copyright 2025 the Unikorn Authors.
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

package server

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	goerrors "errors"
	"fmt"
	"net"
	"reflect"
	"slices"

	"github.com/google/uuid"

	corev1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
	identitycommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	principal "github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/identity"
	"github.com/unikorn-cloud/region/pkg/handler/network"
	"github.com/unikorn-cloud/region/pkg/handler/securitygroup"
	"github.com/unikorn-cloud/region/pkg/handler/sshcertificateauthority"
	"github.com/unikorn-cloud/region/pkg/handler/util"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	"github.com/unikorn-cloud/region/pkg/userdata"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type ClientV2 struct {
	*Client
}

func NewClientV2(clientArgs common.ClientArgs) *ClientV2 {
	return &ClientV2{
		Client: NewClient(clientArgs),
	}
}

func (c *ClientV2) getProvider(regionID string) (types.Provider, error) {
	provider, err := c.Providers.LookupCloud(regionID)
	if err != nil {
		return nil, providers.ProviderToServerError(err)
	}

	return provider, nil
}

func (c *ClientV2) validateUpdatedImage(ctx context.Context, network *regionv1.Network, current *regionv1.Server, request *openapi.ServerV2Update) error {
	if current.Spec.Image != nil && current.Spec.Image.ID == request.Spec.ImageId {
		return nil
	}

	provider, err := c.getProvider(network.Labels[constants.RegionLabel])
	if err != nil {
		return err
	}

	organizationID, _, err := current.OrganizationAndProjectID()
	if err != nil {
		return err
	}

	// The flavor is immutable (enforced by validateServerUpdate before this
	// runs), so the request's flavor is the server's flavor and the update-path
	// flavor-miss policy applies.
	return validateServerImageForUpdate(ctx, provider, organizationID, request.Spec.ImageId, request.Spec.FlavorId)
}

// validateCreateImage enforces the image contract on the create path: the
// image must exist and be visible to the organization, be Ready, and be
// architecture/disk/virtualization compatible with the requested flavor. It
// mirrors validateUpdatedImage so create and update enforce a single contract
// for imageId.
func (c *ClientV2) validateCreateImage(ctx context.Context, network *regionv1.Network, request *openapi.ServerV2Create) error {
	provider, err := c.getProvider(network.Labels[constants.RegionLabel])
	if err != nil {
		return err
	}

	organizationID, _, err := network.OrganizationAndProjectID()
	if err != nil {
		return err
	}

	return validateServerImageForCreate(ctx, provider, organizationID, request.Spec.ImageId, request.Spec.FlavorId)
}

// userDataChanged reports whether an update request would change the persisted
// user-data. An omitted field (nil) matches only an absent stored value;
// byte-identical payloads are unchanged.
func userDataChanged(current []byte, request *[]byte) bool {
	if request == nil {
		return len(current) != 0
	}

	return !bytes.Equal(current, *request)
}

// validateUpdatedUserData applies the same boundary validation as create, but
// only when the update would change the persisted user-data — unchanged
// payloads are never re-validated, so legacy servers whose stored payloads
// predate validation keep working when a client PUTs the same bytes back. The
// CA-awareness flag derives from the server's current SSH certificate
// authority because updates preserve the CA chosen at create time.
func validateUpdatedUserData(current *regionv1.Server, request *openapi.ServerV2Update) error {
	if !userDataChanged(current.Spec.UserData, request.Spec.UserData) {
		return nil
	}

	return userdata.Validate(request.Spec.UserData, current.Spec.SSHCertificateAuthorityID != nil)
}

// validateUpdateV2Request runs the update-path validations that need the
// parent network or the current resource: the image contract shared with
// create, and re-validation of changed user-data.
func (c *ClientV2) validateUpdateV2Request(ctx context.Context, network *regionv1.Network, current *regionv1.Server, request *openapi.ServerV2Update) error {
	if err := c.validateUpdatedImage(ctx, network, current, request); err != nil {
		return err
	}

	return validateUpdatedUserData(current, request)
}

func convertSecurityGroupsV2(in []regionv1.ServerSecurityGroupSpec) *openapi.ServerV2SecurityGroupIDList {
	if len(in) == 0 {
		return nil
	}

	out := make(openapi.ServerV2SecurityGroupIDList, len(in))

	for i := range in {
		out[i] = in[i].ID
	}

	return &out
}

func convertPublicIPV2(in *regionv1.ServerPublicIPAllocationSpec) *bool {
	if in == nil {
		return nil
	}

	return &in.Enabled
}

func convertAllowedSourceAddressesV2(in []regionv1.ServerNetworkAddressPair) *openapi.AllowedSourceAddresses {
	if len(in) == 0 {
		return nil
	}

	out := make(openapi.AllowedSourceAddresses, len(in))

	for i := range in {
		out[i] = in[i].CIDR.String()
	}

	return &out
}

func convertNetworkingV2(in *regionv1.Server) *openapi.ServerV2Networking {
	out := openapi.ServerV2Networking{
		SecurityGroups:         convertSecurityGroupsV2(in.Spec.SecurityGroups),
		PublicIP:               convertPublicIPV2(in.Spec.PublicIPAllocation),
		AllowedSourceAddresses: convertAllowedSourceAddressesV2(in.Spec.Networks[0].AllowedAddressPairs),
	}

	if reflect.ValueOf(out).IsZero() {
		return nil
	}

	return &out
}

func convertPowerStateV2(in regionv1.InstanceLifecyclePhase) *openapi.InstanceLifecyclePhase {
	if in == "" {
		return nil
	}

	switch in {
	case regionv1.InstanceLifecyclePhasePending:
		return ptr.To(openapi.InstanceLifecyclePhasePending)
	case regionv1.InstanceLifecyclePhaseQueued:
		return ptr.To(openapi.InstanceLifecyclePhaseQueued)
	case regionv1.InstanceLifecyclePhaseBuilding:
		return ptr.To(openapi.InstanceLifecyclePhaseBuilding)
	case regionv1.InstanceLifecyclePhaseRunning:
		return ptr.To(openapi.InstanceLifecyclePhaseRunning)
	case regionv1.InstanceLifecyclePhaseStopping:
		return ptr.To(openapi.InstanceLifecyclePhaseStopping)
	case regionv1.InstanceLifecyclePhaseStopped:
		return ptr.To(openapi.InstanceLifecyclePhaseStopped)
	case regionv1.InstanceLifecyclePhaseError:
		return ptr.To(openapi.InstanceLifecyclePhaseError)
	}

	return nil
}

func resolveSSHInjection(in *openapi.SshInjection, sshCertificateAuthorityID *string) regionv1.ServerSSHInjection {
	if in != nil {
		return regionv1.ServerSSHInjection(*in)
	}

	if sshCertificateAuthorityID != nil {
		return regionv1.ServerSSHInjectionCA
	}

	return regionv1.ServerSSHInjectionIdentityKeypair
}

func sshInjectionStatus(in *regionv1.Server) *openapi.SshInjection {
	out := openapi.SshInjection(in.ResolvedSSHInjection())

	return &out
}

// deriveProvisioningStatus reports a server with a pending rebuild as
// provisioning: consumers gate on provisioned meaning the spec is fully
// realized, and a Nova-accepted rebuild still in flight is not. Only the
// Provisioned case is rewritten — a parked rebuild's error, and every other
// status, pass through so failures stay visible.
func deriveProvisioningStatus(in *regionv1.Server, status coreapi.ResourceProvisioningStatus) coreapi.ResourceProvisioningStatus {
	if in.RebuildPending() && status == coreapi.ResourceProvisioningStatusProvisioned {
		return coreapi.ResourceProvisioningStatusProvisioning
	}

	return status
}

func convertV2(in *regionv1.Server) (*openapi.ServerV2Read, error) {
	imageID, err := in.ImageID()
	if err != nil {
		return nil, err
	}

	regionID, err := in.RegionID()
	if err != nil {
		return nil, err
	}

	metadata := conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags)
	metadata.ProvisioningStatus = deriveProvisioningStatus(in, metadata.ProvisioningStatus)

	out := &openapi.ServerV2Read{
		Metadata: metadata,
		Spec: openapi.ServerV2Spec{
			FlavorId:   in.Spec.FlavorID,
			ImageId:    imageID,
			Networking: convertNetworkingV2(in),
			UserData:   convertUserData(in.Spec.UserData),
		},
		Status: openapi.ServerV2Status{
			RegionId:                  regionID,
			NetworkId:                 in.Spec.Networks[0].ID,
			SshCertificateAuthorityId: in.Spec.SSHCertificateAuthorityID,
			SshInjection:              sshInjectionStatus(in),
			InfrastructureRef:         in.Spec.InfrastructureRef,
			PowerState:                convertPowerStateV2(in.Status.Phase),
			PrivateIP:                 in.Status.PrivateIP,
			PublicIP:                  in.Status.PublicIP,
			MacAddress:                in.Status.MACAddress,
		},
	}

	return out, nil
}

func convertV2List(in *regionv1.ServerList) (openapi.ServersV2Read, error) {
	out := make(openapi.ServersV2Read, len(in.Items))

	for i := range in.Items {
		server, err := convertV2(&in.Items[i])
		if err != nil {
			return nil, err
		}

		out[i] = *server
	}

	return out, nil
}

// convertCreateToUpdateRequest marshals a create request into an update request
// that can be used with generate().  Updates are a subset of creates (without the
// immutable bits).
func convertCreateToUpdateRequest(in *openapi.ServerV2Create) (*openapi.ServerV2Update, error) {
	t, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal request", err)
	}

	out := &openapi.ServerV2Update{}

	if err := json.Unmarshal(t, out); err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal request", err)
	}

	return out, nil
}

func generatePublicIPAllocation(in *openapi.ServerV2Networking) *regionv1.ServerPublicIPAllocationSpec {
	if in == nil || in.PublicIP == nil || !*in.PublicIP {
		return nil
	}

	return &regionv1.ServerPublicIPAllocationSpec{
		Enabled: true,
	}
}

func generateSecurityGroups(in *openapi.ServerV2Networking) []regionv1.ServerSecurityGroupSpec {
	if in == nil || in.SecurityGroups == nil || len(*in.SecurityGroups) == 0 {
		return nil
	}

	out := make([]regionv1.ServerSecurityGroupSpec, len(*in.SecurityGroups))

	for i, id := range *in.SecurityGroups {
		out[i] = regionv1.ServerSecurityGroupSpec{
			ID: id,
		}
	}

	return out
}

func generateAllowedAddressPairs(in *openapi.ServerV2Networking) ([]regionv1.ServerNetworkAddressPair, error) {
	if in == nil || in.AllowedSourceAddresses == nil || len(*in.AllowedSourceAddresses) == 0 {
		return nil, nil
	}

	prefixes := *in.AllowedSourceAddresses

	out := make([]regionv1.ServerNetworkAddressPair, len(prefixes))

	for i := range prefixes {
		_, prefix, err := net.ParseCIDR(prefixes[i])
		if err != nil {
			return nil, errors.HTTPUnprocessableContent("allowedSourceAddresses must contain valid CIDR prefixes")
		}

		out[i] = regionv1.ServerNetworkAddressPair{
			CIDR: corev1.IPv4Prefix{
				IPNet: *prefix,
			},
		}
	}

	return out, nil
}

func generateNetworks(networkID regionids.NetworkID, in *openapi.ServerV2Networking) ([]regionv1.ServerNetworkSpec, error) {
	allowedAddressPairs, err := generateAllowedAddressPairs(in)
	if err != nil {
		return nil, err
	}

	out := regionv1.ServerNetworkSpec{
		ID:                  networkID,
		AllowedAddressPairs: allowedAddressPairs,
	}

	return []regionv1.ServerNetworkSpec{out}, nil
}

func generateUserData(in *[]byte) []byte {
	if in == nil {
		return nil
	}

	return *in
}

func (c *ClientV2) validateSSHCertificateAuthorityReference(ctx context.Context, scope identityids.ProjectScopeReader, sshCertificateAuthorityID *string) error {
	if sshCertificateAuthorityID == nil {
		return nil
	}

	ca, err := sshcertificateauthority.New(c.Client.ClientArgs).GetV2Raw(ctx, *sshCertificateAuthorityID)
	if err != nil {
		return err
	}

	sameProject, err := identityids.SameProject(scope, ca)
	if err != nil {
		return err
	}

	if !sameProject {
		return errors.HTTPUnprocessableContent("sshCertificateAuthorityId must reference an SSH certificate authority in the same organization and project as the server")
	}

	return nil
}

func validateSSHInjection(request *openapi.ServerV2Create, sshInjection regionv1.ServerSSHInjection) error {
	switch sshInjection {
	case regionv1.ServerSSHInjectionCA:
		if request.Spec.SshCertificateAuthorityId == nil {
			return errors.HTTPUnprocessableContent("sshInjection ca requires sshCertificateAuthorityId")
		}
	case regionv1.ServerSSHInjectionIdentityKeypair:
		if request.Spec.SshCertificateAuthorityId != nil {
			return errors.HTTPUnprocessableContent("sshInjection identityKeypair cannot be used with sshCertificateAuthorityId")
		}
	case regionv1.ServerSSHInjectionNone:
		if request.Spec.SshCertificateAuthorityId != nil {
			return errors.HTTPUnprocessableContent("sshInjection none cannot be used with sshCertificateAuthorityId")
		}
	default:
		return errors.HTTPUnprocessableContent("sshInjection must be one of ca, identityKeypair, none")
	}

	if request.Spec.InfrastructureRef != nil && sshInjection == regionv1.ServerSSHInjectionIdentityKeypair {
		return errors.HTTPUnprocessableContent("infrastructureRef cannot be used with sshInjection identityKeypair")
	}

	return nil
}

// assertSameNetwork denies a security group reference that belongs to a different
// network. A network belongs to exactly one identity (one underlying OpenStack
// project), which in turn belongs to one organization and project, so requiring the
// security group to share the server's network closes the cross-tenancy hole at its
// natural granularity — and is what OpenStack itself permits. The security group's
// owning network is exposed identically in region (the NetworkLabel) and in the read
// model the compute service consumes (status.networkId), so the same rule is enforced
// uniformly across both services.
func assertSameNetwork(networkID string, securityGroup *regionv1.SecurityGroup) error {
	if securityGroup.Labels[constants.NetworkLabel] != networkID {
		return errors.HTTPUnprocessableContent("a referenced security group must belong to the same network as the server")
	}

	return nil
}

func (c *ClientV2) validateSecurityGroupReferences(ctx context.Context, networkID string, networking *openapi.ServerV2Networking) error {
	if networking == nil || networking.SecurityGroups == nil {
		return nil
	}

	for _, id := range *networking.SecurityGroups {
		securityGroup, err := securitygroup.New(c.Client.ClientArgs).GetV2Raw(ctx, id.String())
		if err != nil {
			return err
		}

		if err := assertSameNetwork(networkID, securityGroup); err != nil {
			return err
		}
	}

	return nil
}

// validateInfrastructureRefForFlavor rejects a request that omits an
// infrastructureRef when the flavor demands one. It only runs on the create
// path, so a flavor the region no longer offers gets the create-path miss
// policy: the same 422 as validateServerImageForCreate, rather than silently
// passing the pinned-only gate.
func (c *ClientV2) validateInfrastructureRefForFlavor(ctx context.Context, regionID string, flavorID regionids.FlavorID, infrastructureRef *string) error {
	if infrastructureRef != nil {
		return nil
	}

	provider, err := c.getProvider(regionID)
	if err != nil {
		return err
	}

	flavor, err := flavorByID(ctx, provider, flavorID)
	if err != nil {
		if goerrors.Is(err, coreerrors.ErrResourceNotFound) {
			return errors.HTTPUnprocessableContent("flavor is no longer offered by the region").WithError(err)
		}

		return err
	}

	if flavor.PinnedOnly {
		return errors.HTTPUnprocessableContent("flavor requires infrastructureRef to be set")
	}

	return nil
}

func (c *ClientV2) generateV2(ctx context.Context, organizationID identityids.OrganizationID, projectID identityids.ProjectID, in *openapi.ServerV2Update, network *regionv1.Network, sshCertificateAuthorityID *string, infrastructureRef *string, sshInjection regionv1.ServerSSHInjection) (*regionv1.Server, error) {
	networkID, err := network.NetworkID()
	if err != nil {
		return nil, err
	}

	networks, err := generateNetworks(networkID, in.Spec.Networking)
	if err != nil {
		return nil, err
	}

	out := &regionv1.Server{
		ObjectMeta: conversion.NewDeterministicObjectMetadata(&in.Metadata, c.Namespace,
			uuid.UUID(networkID), in.Metadata.Name).
			WithLabel(constants.RegionLabel, network.Labels[constants.RegionLabel]).
			WithLabel(constants.IdentityLabel, network.Labels[constants.IdentityLabel]).
			WithLabel(constants.NetworkLabel, network.Name).
			WithLabel(constants.ResourceAPIVersionLabel, constants.MarshalAPIVersion(2)).
			Get(),
		Spec: regionv1.ServerSpec{
			Tags:     conversion.GenerateTagList(in.Metadata.Tags),
			FlavorID: in.Spec.FlavorId,
			Image: &regionv1.ServerImage{
				ID: in.Spec.ImageId,
			},
			PublicIPAllocation:        generatePublicIPAllocation(in.Spec.Networking),
			SecurityGroups:            generateSecurityGroups(in.Spec.Networking),
			Networks:                  networks,
			SSHCertificateAuthorityID: sshCertificateAuthorityID,
			SSHInjection:              ptr.To(sshInjection),
			InfrastructureRef:         infrastructureRef,
			UserData:                  generateUserData(in.Spec.UserData),
		},
	}

	// Enrich from the parent network's scope before stamping placement and
	// attribution: the principal must be populated for the audit metadata, and
	// the new resource inherits the network's tenancy.
	if err := principal.EnrichUserPrincipalProjectScopeReader(ctx, network); err != nil {
		return nil, fmt.Errorf("%w: unable to set principal information", err)
	}

	if err := identitycommon.SetIdentityMetadataProjectScope(ctx, &out.ObjectMeta, organizationID, projectID); err != nil {
		return nil, fmt.Errorf("%w: failed to set identity metadata", err)
	}

	// Ensure the server is owned by the network so it is automatically cleaned
	// up on cascading deletion.
	if err := controllerutil.SetOwnerReference(network, out, c.Client.Client.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
		return nil, err
	}

	return out, nil
}

func (c *ClientV2) ListV2(ctx context.Context, params openapi.GetApiV2ServersParams) (openapi.ServersV2Read, error) {
	selector := labels.SelectorFromSet(map[string]string{
		constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
	})

	var err error

	selector, err = rbac.AddOrganizationAndProjectIDQuery(ctx, selector, util.OrganizationIDQuery(params.OrganizationID), util.ProjectIDQuery(params.ProjectID))
	if err != nil {
		if rbac.HasNoMatches(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("%w: failed to add identity label selector", err)
	}

	selector, err = util.AddRegionIDQuery(selector, params.RegionID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to add region label selector", err)
	}

	selector, err = util.AddNetworkIDQuery(selector, params.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to add network label selector", err)
	}

	options := &client.ListOptions{
		Namespace:     c.Namespace,
		LabelSelector: selector,
	}

	result := &regionv1.ServerList{}

	if err := c.Client.Client.List(ctx, result, options); err != nil {
		return nil, fmt.Errorf("%w: unable to list servers", err)
	}

	tagSelector, err := coreutil.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(resource regionv1.Server) bool {
		if !resource.Spec.Tags.ContainsAll(tagSelector) {
			return true
		}

		return rbac.AllowProjectScopeReader(ctx, "region:servers", identityapi.Read, &resource) != nil
	})

	slices.SortStableFunc(result.Items, func(a, b regionv1.Server) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertV2List(result)
}

// validateCreateV2Request runs the request-level validations for a v2 server
// create: SSH injection mode compatibility, that any user-data is well-formed
// cloud-init, that any referenced SSH certificate authority shares the server's
// organization and project, that any referenced security group belongs to the
// server's network, that the requested image is Ready and compatible with the
// requested flavor, and the infrastructure reference requirements of the
// requested flavor.
func (c *ClientV2) validateCreateV2Request(ctx context.Context, request *openapi.ServerV2Create, network *regionv1.Network) error {
	sshInjection := resolveSSHInjection(request.Spec.SshInjection, request.Spec.SshCertificateAuthorityId)

	if err := validateSSHInjection(request, sshInjection); err != nil {
		return err
	}

	// Reject user-data that is not recognizable cloud-init, so a malformed
	// payload surfaces as a 422 at create time rather than failing mid-provision
	// (when managed augmentation parses it) or silently inside the guest at boot.
	if err := userdata.Validate(request.Spec.UserData, request.Spec.SshCertificateAuthorityId != nil); err != nil {
		return err
	}

	if err := c.validateSSHCertificateAuthorityReference(ctx, network, request.Spec.SshCertificateAuthorityId); err != nil {
		return err
	}

	if err := c.validateSecurityGroupReferences(ctx, network.Name, request.Spec.Networking); err != nil {
		return err
	}

	if err := c.validateCreateImage(ctx, network, request); err != nil {
		return err
	}

	return c.validateInfrastructureRefForFlavor(ctx, network.Labels[constants.RegionLabel], request.Spec.FlavorId, request.Spec.InfrastructureRef)
}

func (c *ClientV2) CreateV2(ctx context.Context, request *openapi.ServerV2Create) (*openapi.ServerV2Read, error) {
	network, err := network.New(c.Client.ClientArgs).GetV2Raw(ctx, request.Spec.NetworkId.String())
	if err != nil {
		return nil, err
	}

	organizationID, projectID, err := network.OrganizationAndProjectID()
	if err != nil {
		return nil, err
	}

	if err := rbac.AllowProjectScopeCreateID(ctx, c.Identity, "region:servers", identityapi.Create, organizationID, projectID); err != nil {
		return nil, err
	}

	if err := c.validateCreateV2Request(ctx, request, network); err != nil {
		return nil, err
	}

	commonRequest, err := convertCreateToUpdateRequest(request)
	if err != nil {
		return nil, err
	}

	sshInjection := resolveSSHInjection(request.Spec.SshInjection, request.Spec.SshCertificateAuthorityId)

	resource, err := c.generateV2(ctx, organizationID, projectID, commonRequest, network, request.Spec.SshCertificateAuthorityId, request.Spec.InfrastructureRef, sshInjection)
	if err != nil {
		return nil, err
	}

	if err := c.Client.Client.Create(ctx, resource); err != nil {
		if kerrors.IsAlreadyExists(err) {
			return nil, errors.HTTPConflict()
		}

		return nil, fmt.Errorf("%w: unable to create server", err)
	}

	return convertV2(resource)
}

func (c *ClientV2) GetV2Raw(ctx context.Context, serverID string) (*regionv1.Server, error) {
	result := &regionv1.Server{}

	if err := c.Client.Client.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: serverID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: unable to lookup server", err)
	}

	if err := rbac.AllowProjectScopeReader(ctx, "region:servers", identityapi.Read, result); err != nil {
		return nil, err
	}

	// Only allow access to resources created by this API (temporarily).
	v, ok := result.Labels[constants.ResourceAPIVersionLabel]
	if !ok {
		return nil, errors.HTTPNotFound().WithValues("serverID", serverID)
	}

	version, err := constants.UnmarshalAPIVersion(v)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to parse API version", coreerrors.ErrConsistency)
	}

	if version != 2 {
		return nil, errors.HTTPNotFound()
	}

	return result, nil
}

func (c *ClientV2) GetV2(ctx context.Context, serverID regionids.ServerID) (*openapi.ServerV2Read, error) {
	result, err := c.GetV2Raw(ctx, serverID.String())
	if err != nil {
		return nil, err
	}

	return convertV2(result)
}

func validateServerUpdate(current *regionv1.Server, request *openapi.ServerV2Update) error {
	if current.DeletionTimestamp != nil {
		return errors.OAuth2InvalidRequest("server is being deleted")
	}

	if request.Metadata.Name != current.Labels[coreconstants.NameLabel] {
		return errors.HTTPUnprocessableContent("server names are immutable")
	}

	if request.Spec.FlavorId != current.Spec.FlavorID {
		return errors.HTTPUnprocessableContent("server flavor is immutable")
	}

	return nil
}

func (c *ClientV2) UpdateV2(ctx context.Context, serverID regionids.ServerID, request *openapi.ServerV2Update) (*openapi.ServerV2Read, error) {
	current, err := c.GetV2Raw(ctx, serverID.String())
	if err != nil {
		return nil, err
	}

	organizationID, projectID, err := current.OrganizationAndProjectID()
	if err != nil {
		return nil, err
	}

	if err := rbac.AllowProjectScopeID(ctx, "region:servers", identityapi.Update, organizationID, projectID); err != nil {
		return nil, err
	}

	if err := validateServerUpdate(current, request); err != nil {
		return nil, err
	}

	// Security groups are mutable, so re-validate that every referenced group still
	// belongs to the server's network. The SSH certificate authority and
	// infrastructure reference are immutable, so they keep the scope validated at
	// create time.
	if err := c.validateSecurityGroupReferences(ctx, current.Labels[constants.NetworkLabel], request.Spec.Networking); err != nil {
		return nil, err
	}

	// Get the network, required for generation.
	network, err := network.New(c.Client.ClientArgs).GetV2Raw(ctx, current.Spec.Networks[0].ID.String())
	if err != nil {
		return nil, err
	}

	// Updates replace the persisted user-data wholesale: an omitted field clears
	// the stored value. The value is not applied to the running guest — it is
	// consumed by the next rebuild (image change) or recreate. Changed user-data
	// is re-validated at the boundary; identical payloads are not.
	if err := c.validateUpdateV2Request(ctx, network, current, request); err != nil {
		return nil, err
	}

	required, err := c.generateV2(ctx, organizationID, projectID, request, network, current.Spec.SSHCertificateAuthorityID, current.Spec.InfrastructureRef, current.ResolvedSSHInjection())
	if err != nil {
		return nil, err
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := c.Client.Client.Patch(ctx, updated, client.MergeFromWithOptions(current, &client.MergeFromWithOptimisticLock{})); err != nil {
		return nil, fmt.Errorf("%w: unable to update server", err)
	}

	return convertV2(updated)
}

func (c *ClientV2) DeleteV2(ctx context.Context, serverID regionids.ServerID) error {
	resource, err := c.GetV2Raw(ctx, serverID.String())
	if err != nil {
		return err
	}

	if err := rbac.AllowProjectScopeReader(ctx, "region:servers", identityapi.Delete, resource); err != nil {
		return err
	}

	if err := c.Client.Client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return fmt.Errorf("%w: unable to delete server", err)
	}

	return nil
}

func (c *ClientV2) getServerIdentityAndProviderV2(ctx context.Context, serverID regionids.ServerID) (*regionv1.Server, *regionv1.Identity, types.Provider, error) {
	server, err := c.GetV2Raw(ctx, serverID.String())
	if err != nil {
		return nil, nil, nil, err
	}

	identity, err := c.getIdentityForServerV2(ctx, server)
	if err != nil {
		return nil, nil, nil, err
	}

	provider, err := c.getProvider(server.Labels[constants.RegionLabel])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: failed to create region provider", err)
	}

	return server, identity, provider, nil
}

func (c *ClientV2) getIdentityForServerV2(ctx context.Context, server *regionv1.Server) (*regionv1.Identity, error) {
	organizationID, projectID, err := server.OrganizationAndProjectID()
	if err != nil {
		return nil, err
	}

	identity, err := identity.New(c.Client.ClientArgs).GetRaw(ctx, organizationID, projectID, server.Labels[constants.IdentityLabel])
	if err != nil {
		return nil, err
	}

	return identity, nil
}

func (c *ClientV2) SSHKey(ctx context.Context, serverID regionids.ServerID) (*openapi.SshKey, error) {
	server, err := c.GetV2Raw(ctx, serverID.String())
	if err != nil {
		return nil, err
	}

	if !server.UsesIdentitySSHKey() {
		return nil, errors.HTTPNotFound().WithValues("serverID", serverID)
	}

	identity, err := c.getIdentityForServerV2(ctx, server)
	if err != nil {
		return nil, err
	}

	var openstackIdentity regionv1.OpenstackIdentity

	if err := c.Client.Client.Get(ctx, client.ObjectKey{Namespace: identity.Namespace, Name: identity.Name}, &openstackIdentity); err != nil {
		return nil, fmt.Errorf("%w: failed to load server identity information", err)
	}

	if len(openstackIdentity.Spec.SSHPrivateKey) == 0 {
		return nil, errors.HTTPNotFound().WithValues("serverID", serverID)
	}

	out := &openapi.SshKey{
		PrivateKey: string(openstackIdentity.Spec.SSHPrivateKey),
	}

	return out, nil
}

func (c *ClientV2) StartV2(ctx context.Context, serverID regionids.ServerID) error {
	server, identity, provider, err := c.getServerIdentityAndProviderV2(ctx, serverID)
	if err != nil {
		return err
	}

	return c.start(ctx, identity, server, provider)
}

func (c *ClientV2) StopV2(ctx context.Context, serverID regionids.ServerID) error {
	server, identity, provider, err := c.getServerIdentityAndProviderV2(ctx, serverID)
	if err != nil {
		return err
	}

	return c.stop(ctx, identity, server, provider)
}

func (c *ClientV2) RebootV2(ctx context.Context, serverID regionids.ServerID, hard bool) error {
	server, identity, provider, err := c.getServerIdentityAndProviderV2(ctx, serverID)
	if err != nil {
		return err
	}

	return c.reboot(ctx, identity, server, hard, provider)
}

func (c *ClientV2) ConsoleOutputV2(ctx context.Context, serverID regionids.ServerID, params openapi.GetApiV2ServersServerIDConsoleoutputParams) (*openapi.ConsoleOutputResponse, error) {
	server, identity, provider, err := c.getServerIdentityAndProviderV2(ctx, serverID)
	if err != nil {
		return nil, err
	}

	return c.getConsoleOutput(ctx, identity, server, params.Length, provider)
}

func (c *ClientV2) ConsoleSessionV2(ctx context.Context, serverID regionids.ServerID) (*openapi.ConsoleSessionResponse, error) {
	server, identity, provider, err := c.getServerIdentityAndProviderV2(ctx, serverID)
	if err != nil {
		return nil, err
	}

	return c.createConsoleSession(ctx, identity, server, provider)
}
