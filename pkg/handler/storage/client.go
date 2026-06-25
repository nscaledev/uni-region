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

package storage

import (
	"cmp"
	"context"
	"fmt"
	"math/big"
	"net"
	"slices"

	unikorncorev1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/saga"
	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
	identitycommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	principal "github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/network"
	"github.com/unikorn-cloud/region/pkg/handler/util"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// DefaultParallelism is the default number of IP addresses assigned to storage.
	// This maintains legacy default behaviour for storage classes that do not specify a value.
	DefaultParallelism = 4
)

// Client provides a restful API for storage.
type Client struct {
	common.ClientArgs
}

type storageV2GenerateRequest struct {
	Metadata coreopenapi.ResourceWriteMetadata
	Spec     storageV2GenerateSpec
}

type storageV2GenerateSpec struct {
	Attachments                      *openapi.StorageAttachmentV2Spec
	DefaultSnapshotProtectionEnabled bool
	SizeGiB                          int64
	SnapshotPolicies                 *openapi.StorageSnapshotPolicyListV2Spec
	StorageType                      openapi.StorageTypeV2Spec
}

// New creates a new client.
func New(clientArgs common.ClientArgs) *Client {
	return &Client{
		ClientArgs: clientArgs,
	}
}

func convertV2(in *regionv1.FileStorage) *openapi.StorageV2Read {
	snapshotPolicies := userManagedSnapshotPolicies(in.Spec.SnapshotPolicies)

	return &openapi.StorageV2Read{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.StorageV2Spec{
			Attachments: &openapi.StorageAttachmentV2Spec{
				NetworkIds: convertAttachmentsList(in.Spec.Attachments),
			},
			DefaultSnapshotProtectionEnabled: ptr.To(in.Spec.DefaultSnapshotProtectionEnabled),
			SnapshotPolicies:                 convertSnapshotPoliciesPointer(snapshotPolicies),
			StorageType: openapi.StorageTypeV2Spec{
				NFS: checkRegionNFS(in.Spec.NFS),
			},
			SizeGiB: quantityToSizeGiB(in.Spec.Size),
		},
		Status: openapi.StorageV2Status{
			RegionId:       in.Labels[constants.RegionLabel],
			StorageClassId: in.Spec.StorageClassID,
			Attachments:    convertStatusAttachmentList(in),
			SnapshotPolicies: convertSnapshotPolicyStatuses(
				snapshotPolicies,
				in.Status.SnapshotPolicies,
			),
			Usage: convertUsageStatus(in),
		},
	}
}

func convertUsageStatus(in *regionv1.FileStorage) *openapi.StorageUsageV2Status {
	if in.Status.Size == nil {
		return nil
	}

	out := &openapi.StorageUsageV2Status{
		CapacityBytes: in.Status.Size.Value(),
	}

	if in.Status.Usage != nil {
		out.UsedBytes = ptr.To(in.Status.Usage.Value())
	}

	if in.Status.UsageTimestamp != nil {
		out.UpdatedAt = &in.Status.UsageTimestamp.Time
	}

	return out
}

// Status attachment rows follow desired attachments, then use observed status
// to enrich matching rows with controller-projected state.
func convertStatusAttachmentList(in *regionv1.FileStorage) *openapi.StorageAttachmentListV2Status {
	if len(in.Spec.Attachments) == 0 {
		return nil
	}

	observedAttachments := make(map[string]regionv1.FileStorageAttachmentStatus, len(in.Status.Attachments))
	for _, status := range in.Status.Attachments {
		observedAttachments[status.NetworkID] = status
	}

	out := make(openapi.StorageAttachmentListV2Status, len(in.Spec.Attachments))

	for i, att := range in.Spec.Attachments {
		var mountSource *string

		// Only build MountSource if all required fields are non-nil.
		if att.IPRange != nil && in.Status.MountPath != nil {
			mountSource = ptr.To(fmt.Sprintf("%s:%s", att.IPRange.Start, *in.Status.MountPath))
		}

		attachmentStatus := openapi.StorageAttachmentV2Status{
			NetworkId:          att.NetworkID,
			MountSource:        mountSource,
			ProvisioningStatus: coreopenapi.ResourceProvisioningStatusPending,
		}

		if observed, ok := observedAttachments[att.NetworkID]; ok {
			attachmentStatus.ProvisioningStatus = convertAttachmentProvisioningStatus(observed.ProvisioningStatus)
			attachmentStatus.MountOptions = mountOptionsFromAttachmentStatus(observed)
		}

		out[i] = attachmentStatus
	}

	return &out
}

func convertAttachmentProvisioningStatus(in regionv1.AttachmentProvisioningStatus) coreopenapi.ResourceProvisioningStatus {
	switch in {
	case regionv1.AttachmentProvisioning:
		return coreopenapi.ResourceProvisioningStatusProvisioning
	case regionv1.AttachmentProvisioned:
		return coreopenapi.ResourceProvisioningStatusProvisioned
	case regionv1.AttachmentErrored:
		return coreopenapi.ResourceProvisioningStatusError
	case regionv1.AttachmentDeprovisioning:
		return coreopenapi.ResourceProvisioningStatusDeprovisioning
	default:
		return coreopenapi.ResourceProvisioningStatusUnknown
	}
}

func mountOptionsFromAttachmentStatus(in regionv1.FileStorageAttachmentStatus) *map[string]string {
	if in.IPRange == nil {
		return nil
	}

	options := map[string]string{
		"remoteports": remotePortsFromIPRange(in.IPRange),
	}

	return &options
}

func remotePortsFromIPRange(in *regionv1.AttachmentIPRange) string {
	start := in.Start.String()
	end := in.End.String()

	if start == end {
		return start
	}

	return fmt.Sprintf("%s-%s", start, end)
}

func checkRegionNFS(in *regionv1.NFS) *openapi.NFSV2Spec {
	if in == nil {
		return &openapi.NFSV2Spec{
			RootSquash: true,
		}
	}

	return &openapi.NFSV2Spec{
		RootSquash: in.RootSquash,
	}
}

func convertAttachmentsList(in []regionv1.Attachment) openapi.NetworkIDList {
	out := make(openapi.NetworkIDList, len(in))

	for i := range in {
		out[i] = in[i].NetworkID
	}

	return out
}

// ListV2 satisfies an http get to return all storage items within a project.
func (c *Client) ListV2(ctx context.Context, params openapi.GetApiV2FilestorageParams) (openapi.StorageV2List, error) {
	selector := labels.Everything()

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

	options := &client.ListOptions{
		Namespace:     c.Namespace,
		LabelSelector: selector,
	}

	result := &regionv1.FileStorageList{}

	err = c.Client.List(ctx, result, options)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to list storage", err)
	}

	tagSelector, err := coreutil.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(resource regionv1.FileStorage) bool {
		if !resource.Spec.Tags.ContainsAll(tagSelector) {
			return true
		}

		return rbac.AllowProjectScopeReader(ctx, "region:filestorage:v2", identityapi.Read, &resource) != nil
	})

	slices.SortStableFunc(result.Items, func(a, b regionv1.FileStorage) int {
		return cmp.Compare(a.Name, b.Name)
	})

	storageList := convertV2List(result)

	return storageList, nil
}

func convertV2List(in *regionv1.FileStorageList) openapi.StorageV2List {
	out := make(openapi.StorageV2List, len(in.Items))

	for i, v := range in.Items {
		out[i] = *convertV2(&v)
	}

	return out
}

func (c *Client) GetRaw(ctx context.Context, storageID string) (*regionv1.FileStorage, error) {
	result := &regionv1.FileStorage{}

	err := c.Client.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: storageID}, result)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: unable to lookup storage", err)
	}

	if err := rbac.AllowProjectScopeReader(ctx, "region:filestorage:v2", identityapi.Read, result); err != nil {
		return nil, err
	}

	return result, nil
}

// Get returns a storage object for a specific storageID.
func (c *Client) Get(ctx context.Context, storageID regionids.FileStorageID) (*openapi.StorageV2Read, error) {
	result, err := c.GetRaw(ctx, storageID.String())
	if err != nil {
		return nil, err
	}

	storage := convertV2(result)

	return storage, nil
}

func (c *Client) generateV2(ctx context.Context, organizationID identityids.OrganizationID, projectID identityids.ProjectID, regionID string, request *storageV2GenerateRequest, storageClass *openapi.StorageClassV2Read) (*regionv1.FileStorage, error) {
	networkClient := network.New(c.ClientArgs)

	attachments, err := generateAttachmentList(ctx, networkClient, request, storageClass.Spec.Parallelism)
	if err != nil {
		return nil, err
	}

	defaultSnapshotProtectionEnabled := request.Spec.DefaultSnapshotProtectionEnabled
	policies := generateSnapshotPolicies(request.Spec.SnapshotPolicies)

	out := &regionv1.FileStorage{
		ObjectMeta: conversion.NewObjectMetadata(&request.Metadata, c.Namespace).
			WithLabel(constants.RegionLabel, regionID).
			Get(),
		Spec: regionv1.FileStorageSpec{
			Tags:                             conversion.GenerateTagList(request.Metadata.Tags),
			Size:                             *gibToQuantity(request.Spec.SizeGiB),
			Attachments:                      attachments,
			DefaultSnapshotProtectionEnabled: defaultSnapshotProtectionEnabled,
			SnapshotPolicies:                 materializeDefaultSnapshotProtection(policies, defaultSnapshotProtectionEnabled),
			NFS: &regionv1.NFS{
				RootSquash: checkRootSquash(request.Spec.StorageType.NFS),
			},
			StorageClassID: storageClass.Metadata.Id,
		},
	}

	// Root create: no parent resource to read scope from, so enrich the principal
	// from the typed request IDs before stamping. Attribution still sees the
	// populated principal, and out needs no early placement labels.
	if err := principal.EnrichUserPrincipalProjectScopeID(ctx, organizationID, projectID); err != nil {
		return nil, fmt.Errorf("%w: unable to set principal information", err)
	}

	if err := identitycommon.SetIdentityMetadataProjectScope(ctx, &out.ObjectMeta, organizationID, projectID); err != nil {
		return nil, fmt.Errorf("%w: failed to set identity metadata", err)
	}

	return out, nil
}

// checkRootSquash sets the Rootsquash bool, defaults to true
// this is only called on 'generates'.
func checkRootSquash(nfs *openapi.NFSV2Spec) bool {
	if nfs != nil {
		return nfs.RootSquash
	}

	return true
}

func generateAttachmentList(ctx context.Context, networkClient *network.Client, in *storageV2GenerateRequest, parallelism int) ([]regionv1.Attachment, error) {
	if in == nil || in.Spec.Attachments == nil {
		return []regionv1.Attachment{}, nil
	}

	networkIDs := in.Spec.Attachments.NetworkIds
	out := make([]regionv1.Attachment, len(networkIDs))

	for i, networkID := range networkIDs {
		network, err := networkClient.GetV2Raw(ctx, networkID)
		if err != nil {
			return nil, fmt.Errorf("%w: unable to get network", err)
		}

		attachment, err := generateAttachment(network, parallelism)
		if err != nil {
			return nil, err
		}

		out[i] = *attachment
	}

	return out, nil
}

func generateAttachment(network *regionv1.Network, parallelism int) (*regionv1.Attachment, error) {
	storageRange, err := validateStorageRange(network, parallelism)
	if err != nil {
		return nil, err
	}

	return &regionv1.Attachment{
		NetworkID:      network.Name,
		IPRange:        narrowStorageRange(storageRange, parallelism),
		SegmentationID: network.Status.Openstack.VlanID,
	}, nil
}

// validateStorageRange checks that the network has a non-empty IPv4 storage
// range. The range is inclusive on both ends: [Start, End], so Start=10.0.0.1,
// End=10.0.0.4 yields 4 addresses.
func validateStorageRange(network *regionv1.Network, parallelism int) (*regionv1.AttachmentIPRange, error) {
	if parallelism < 1 {
		return nil, errors.HTTPUnprocessableContent("requested parallelism must be at least 1")
	}

	// FIXME: this part of the network status is destined for deprecation, since it is not generic.
	// Because FileStorage needs details that are only available through the status at present,
	// I have used it (conditionally) here until there is a reliable, generic way to get that info.
	if network.Status.Openstack == nil {
		return nil, errors.HTTPUnprocessableContent("network requested is not a suitable network")
	}

	sr := network.Status.Openstack.StorageRange
	if sr == nil {
		return nil, errors.HTTPUnprocessableContent("network requested does not have a storage range configured")
	}

	startIP := sr.Start.To4()
	endIP := sr.End.To4()

	if startIP == nil || endIP == nil {
		return nil, errors.HTTPUnprocessableContent("network storage range is not a valid IPv4 range")
	}

	// Storage ranges are inclusive, so Start == End means one usable address.
	// A zero or negative inclusive count means End is before Start.
	available := big.NewInt(0).Sub(
		big.NewInt(0).SetBytes(endIP),
		big.NewInt(0).SetBytes(startIP),
	)
	available.Add(available, big.NewInt(1))

	if available.Sign() <= 0 {
		return nil, errors.HTTPUnprocessableContent("network storage range does not contain any usable addresses")
	}

	return sr, nil
}

func narrowStorageRange(in *regionv1.AttachmentIPRange, parallelism int) *regionv1.AttachmentIPRange {
	if in == nil {
		return nil
	}

	startIP := in.Start.To4() // NB assumes IPv4 address
	maxEndIP := in.End.To4()

	bs := big.NewInt(0).SetBytes(startIP)
	me := big.NewInt(0).SetBytes(maxEndIP)

	// Calculate the address range the user asked for, capping it at the maximum
	// possible value.
	be := big.NewInt(0).Add(bs, big.NewInt(int64(parallelism)-1))

	if be.Cmp(me) > 0 {
		be = me
	}

	endIP := net.IP(be.Bytes())

	return &regionv1.AttachmentIPRange{
		Start: unikorncorev1.IPv4Address{IP: startIP},
		End:   unikorncorev1.IPv4Address{IP: endIP},
	}
}

func generateRequestFromCreate(in *openapi.StorageV2Create) *storageV2GenerateRequest {
	return &storageV2GenerateRequest{
		Metadata: in.Metadata,
		Spec: storageV2GenerateSpec{
			Attachments: in.Spec.Attachments,
			// Default snapshot protection is enabled on create unless the caller opts out.
			DefaultSnapshotProtectionEnabled: ptr.Deref(in.Spec.DefaultSnapshotProtectionEnabled, true),
			SizeGiB:                          in.Spec.SizeGiB,
			SnapshotPolicies:                 in.Spec.SnapshotPolicies,
			StorageType:                      in.Spec.StorageType,
		},
	}
}

func generateRequestFromUpdate(in *openapi.StorageV2Update, currentDefaultProtection bool) *storageV2GenerateRequest {
	return &storageV2GenerateRequest{
		Metadata: in.Metadata,
		Spec: storageV2GenerateSpec{
			Attachments: in.Spec.Attachments,
			// An omitted field preserves the current default-protection state.
			DefaultSnapshotProtectionEnabled: ptr.Deref(in.Spec.DefaultSnapshotProtectionEnabled, currentDefaultProtection),
			SizeGiB:                          in.Spec.SizeGiB,
			SnapshotPolicies:                 in.Spec.SnapshotPolicies,
			StorageType:                      in.Spec.StorageType,
		},
	}
}

// CreateV2 satisifies an http PUT action by creating a unique storage object.
// It does this leveraging the saga system which acts as a tape to enable rollbacks
// in case of errors.
func (c *Client) CreateV2(ctx context.Context, request *openapi.StorageV2Create) (*openapi.StorageV2Read, error) {
	s, err := newCreateSaga(c, request)
	if err != nil {
		return nil, err
	}

	if err := rbac.AllowProjectScopeCreateID(ctx, c.Identity, "region:filestorage:v2", identityapi.Create, s.organizationID, s.projectID); err != nil {
		return nil, err
	}

	if err := saga.Run(ctx, s); err != nil {
		return nil, err
	}

	return convertV2(s.filestorage), nil
}

// Update satisifies an http POST action by updating the storage object attached
// to the storage ID.
// it leverages the update saga system, which acts as a tape to enable rollbacks
// in case of errors.
func (c *Client) Update(ctx context.Context, storageID regionids.FileStorageID, request *openapi.StorageV2Update) (*openapi.StorageV2Read, error) {
	current, err := c.GetRaw(ctx, storageID.String())
	if err != nil {
		return nil, err
	}

	if err := rbac.AllowProjectScopeReader(ctx, "region:filestorage:v2", identityapi.Update, current); err != nil {
		return nil, err
	}

	if current.DeletionTimestamp != nil {
		return nil, errors.OAuth2InvalidRequest("filestorage is being deleted")
	}

	sc, err := c.GetStorageClass(ctx, current.Spec.StorageClassID)
	if err != nil {
		return nil, err
	}

	s := newUpdateSaga(c, current, request, sc)
	if err := saga.Run(ctx, s); err != nil {
		return nil, err
	}

	storage := convertV2(s.updated)

	return storage, nil
}

// Delete satisfies the http DELETE action by removing the client.
// It does not leverage the saga system because we can rely on finalizers
// to handle this for us.
func (c *Client) Delete(ctx context.Context, storageID regionids.FileStorageID) error {
	resource, err := c.GetRaw(ctx, storageID.String())
	if err != nil {
		return err
	}

	if err := rbac.AllowProjectScopeReader(ctx, "region:filestorage:v2", identityapi.Delete, resource); err != nil {
		return err
	}

	if resource.DeletionTimestamp != nil {
		return nil
	}

	if err := c.Client.Delete(ctx, resource); err != nil {
		return fmt.Errorf("%w: delete failed", err)
	}

	return nil
}

func (c *Client) ListClasses(ctx context.Context, params openapi.GetApiV2FilestorageclassesParams) (openapi.StorageClassListV2Read, error) {
	selector, err := util.AddRegionIDQuery(labels.Everything(), params.RegionID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to add region label selector", err)
	}

	result := &regionv1.FileStorageClassList{}
	options := &client.ListOptions{
		Namespace:     c.Namespace,
		LabelSelector: selector,
	}

	if err := c.Client.List(ctx, result, options); err != nil {
		return nil, fmt.Errorf("%w: unable to list storage classes", err)
	}

	result.Items = slices.DeleteFunc(result.Items, func(resource regionv1.FileStorageClass) bool {
		return authorizeFileStorageClassRead(ctx, &resource) != nil
	})

	slices.SortStableFunc(result.Items, func(a, b regionv1.FileStorageClass) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertClassList(result), nil
}

func (c *Client) GetStorageClass(ctx context.Context, storageClassID string) (*openapi.StorageClassV2Read, error) {
	result := &regionv1.FileStorageClass{}

	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: storageClassID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPUnprocessableContent("storage class not found").WithError(err)
		}

		return nil, fmt.Errorf("%w: unable to lookup storage class", err)
	}

	if err := authorizeFileStorageClassRead(ctx, result); err != nil {
		return nil, err
	}

	return convertClass(result), nil
}

func convertClassList(in *regionv1.FileStorageClassList) openapi.StorageClassListV2Read {
	out := make(openapi.StorageClassListV2Read, len(in.Items))

	for i := range in.Items {
		out[i] = *convertClass(&in.Items[i])
	}

	return out
}

func convertClass(in *regionv1.FileStorageClass) *openapi.StorageClassV2Read {
	return &openapi.StorageClassV2Read{
		Metadata: conversion.ResourceReadMetadata(in, nil),
		Spec: openapi.StorageClassV2Spec{
			RegionId:    in.Labels[constants.RegionLabel],
			Protocols:   convertProtocols(in.Spec.Protocols),
			Parallelism: ensureParallelism(in.Spec.Parallelism),
		},
	}
}

func convertProtocols(in []regionv1.Protocol) []openapi.StorageClassProtocolType {
	out := make([]openapi.StorageClassProtocolType, len(in))

	for i := range in {
		out[i] = openapi.StorageClassProtocolType(in[i])
	}

	return out
}

// ensureParallelism returns the given parallelism value if it is valid (non-nil and >= 1),
// otherwise falls back to DefaultParallelism. This guarantees callers always receive a
// usable, non-nil parallelism value.
func ensureParallelism(in *int) int {
	if in == nil || *in < 1 {
		return DefaultParallelism
	}

	return *in
}

func quantityToSizeGiB(quantity resource.Quantity) int64 {
	return (quantity.Value() / (1 << 30))
}

func gibToQuantity(size int64) *resource.Quantity {
	return resource.NewQuantity((size * (1 << 30)), resource.BinarySI)
}

// authorizeFileStorageClassRead enforces read permissions for a FileStorageClass.
// If the storage class has an associated organization, access is allowed only if the caller has read permissions for that organization.
// Otherwise, the class is accessible to all organizations.
func authorizeFileStorageClassRead(ctx context.Context, resource *regionv1.FileStorageClass) error {
	orgID := resource.Labels[coreconstants.OrganizationLabel]
	if orgID == "" {
		return nil
	}

	organizationID, err := identityids.ParseOrganizationID(orgID)
	if err != nil {
		return fmt.Errorf("%w: invalid organization ID in file storage class labels", err)
	}

	return rbac.AllowOrganizationScopeID(ctx, "region:filestorageclass:v2", identityapi.Read, organizationID)
}
