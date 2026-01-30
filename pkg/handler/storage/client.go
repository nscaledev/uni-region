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
	"encoding/json"
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
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/file-storage/provisioners/types"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/network"
	"github.com/unikorn-cloud/region/pkg/handler/util"
	"github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Driver interface {
	GetDetails(ctx context.Context, projectID string, fileStorageID string) (*types.FileStorageDetails, error)
}

// Client provides a restful API for storage.
type Client struct {
	common.ClientArgs
}

// New creates a new client.
func New(clientArgs common.ClientArgs) *Client {
	return &Client{
		ClientArgs: clientArgs,
	}
}

func convertV2(in *regionv1.FileStorage) *openapi.StorageV2Read {
	return &openapi.StorageV2Read{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.StorageV2Spec{
			Attachments: &openapi.StorageAttachmentV2Spec{
				NetworkIds: convertAttachmentsList(in.Spec.Attachments),
			},
			StorageType: openapi.StorageTypeV2Spec{
				NFS: checkRegionNFS(in.Spec.NFS),
			},
			SizeGiB: quantityToSizeGiB(in.Spec.Size),
		},
		Status: openapi.StorageV2Status{
			RegionId:       in.Labels[constants.RegionLabel],
			StorageClassId: in.Spec.StorageClassID,
			Attachments:    convertStatusAttachmentList(in),
		},
	}
}

// NOTE: This returns attachment status based solely on FileStorage.Spec.Attachments (the desired state).
// Because attachments may be reconciled asynchronously by the controller, this does not accurately reflect the actual state.
// As a result, provisioning status is omitted (nil). This will be addressed in a future update.
func convertStatusAttachmentList(in *regionv1.FileStorage) *openapi.StorageAttachmentListV2Status {
	if len(in.Spec.Attachments) == 0 {
		return nil
	}

	out := make(openapi.StorageAttachmentListV2Status, len(in.Spec.Attachments))

	for i, att := range in.Spec.Attachments {
		var mountSource *string

		// Only build MountSource if all required fields are non-nil.
		if att.IPRange != nil && in.Status.MountPath != nil {
			mountSource = ptr.To(fmt.Sprintf("%s:%s", att.IPRange.Start, *in.Status.MountPath))
		}

		out[i] = openapi.StorageAttachmentV2Status{
			NetworkId:          att.NetworkID,
			MountSource:        mountSource,
			ProvisioningStatus: coreopenapi.ResourceProvisioningStatusUnknown,
		}
	}

	return &out
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

		return nil, errors.OAuth2ServerError("failed to add identity label selector").WithError(err)
	}

	selector, err = util.AddRegionIDQuery(selector, params.RegionID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to add region label selector").WithError(err)
	}

	options := &client.ListOptions{
		Namespace:     c.Namespace,
		LabelSelector: selector,
	}

	result := &regionv1.FileStorageList{}

	err = c.Client.List(ctx, result, options)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to list storage").WithError(err)
	}

	tagSelector, err := coreutil.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(resource regionv1.FileStorage) bool {
		return !resource.Spec.Tags.ContainsAll(tagSelector) ||
			rbac.AllowProjectScope(ctx, "region:filestorage:v2", identityapi.Read, resource.Labels[coreconstants.OrganizationLabel], resource.Labels[coreconstants.ProjectLabel]) != nil
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

		return nil, errors.OAuth2ServerError("unable to lookup storage").WithError(err)
	}

	err = rbac.AllowProjectScope(ctx, "region:filestorage:v2", identityapi.Read,
		result.Labels[coreconstants.OrganizationLabel], result.Labels[coreconstants.ProjectLabel])

	if err != nil {
		return nil, err
	}

	return result, nil
}

// Get returns a storage object for a specific storageID.
func (c *Client) Get(ctx context.Context, storageID string) (*openapi.StorageV2Read, error) {
	result, err := c.GetRaw(ctx, storageID)
	if err != nil {
		return nil, err
	}

	storage := convertV2(result)

	return storage, nil
}

func (c *Client) generateV2(ctx context.Context, organizationID, projectID, regionID string, request *openapi.StorageV2Update, storageClassID string) (*regionv1.FileStorage, error) {
	networkClient := network.New(c.ClientArgs)

	err := util.InjectUserPrincipal(ctx, organizationID, projectID)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to set principal information").WithError(err)
	}

	attachments, err := generateAttachmentList(ctx, networkClient, request.Spec.Attachments)
	if err != nil {
		return nil, err
	}

	out := &regionv1.FileStorage{
		ObjectMeta: conversion.NewObjectMetadata(&request.Metadata, c.Namespace).
			WithOrganization(organizationID).
			WithProject(projectID).
			WithLabel(constants.RegionLabel, regionID).
			Get(),
		Spec: regionv1.FileStorageSpec{
			Tags:        conversion.GenerateTagList(request.Metadata.Tags),
			Size:        *gibToQuantity(request.Spec.SizeGiB),
			Attachments: attachments,
			NFS: &regionv1.NFS{
				RootSquash: checkRootSquash(request.Spec.StorageType.NFS),
			},
			StorageClassID: storageClassID,
		},
	}

	err = identitycommon.SetIdentityMetadata(ctx, &out.ObjectMeta)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
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

func generateAttachmentList(ctx context.Context, networkClient *network.Client, in *openapi.StorageAttachmentV2Spec) ([]regionv1.Attachment, error) {
	if in == nil {
		return []regionv1.Attachment{}, nil
	}

	networkIDs := in.NetworkIds
	out := make([]regionv1.Attachment, len(networkIDs))

	for i, networkID := range networkIDs {
		network, err := networkClient.GetV2Raw(ctx, networkID)
		if err != nil {
			return nil, errors.OAuth2ServerError("unable to get network").WithError(err)
		}

		attachment, err := generateAttachment(network)
		if err != nil {
			return nil, err
		}

		out[i] = *attachment
	}

	return out, nil
}

func generateAttachment(network *regionv1.Network) (*regionv1.Attachment, error) {
	networkID := network.Name

	// FIXME: this part of the network status is destined for deprecation, since it is not generic.
	// Because FileStorage needs details that are only available through the status at present,
	// I have used it (conditionally) here until there is a reliable, generic way to get that info.
	if network.Status.Openstack == nil {
		return nil, errors.OAuth2ServerError("network requested is not a suitable network") // TODO: use 422, or supply better information here.
	}

	ipRange := narrowStorageRange(network.Status.Openstack.StorageRange)

	return &regionv1.Attachment{
		NetworkID:      networkID,
		IPRange:        ipRange,
		SegmentationID: network.Status.Openstack.VlanID,
	}, nil
}

func narrowStorageRange(in *regionv1.AttachmentIPRange) *regionv1.AttachmentIPRange {
	if in == nil {
		return nil
	}

	startIP := in.Start.To4() // NB assumes IPv4 address

	bs := big.NewInt(0).SetBytes(startIP)
	be := big.NewInt(0).Add(bs, big.NewInt(3))
	endIP := net.IP(be.Bytes())

	return &regionv1.AttachmentIPRange{
		Start: unikorncorev1.IPv4Address{IP: startIP},
		End:   unikorncorev1.IPv4Address{IP: endIP},
	}
}

func convertCreateToUpdateRequest(in *openapi.StorageV2Create) (*openapi.StorageV2Update, error) {
	t, err := json.Marshal(in)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to marshal request").WithError(err)
	}

	out := &openapi.StorageV2Update{}

	if err := json.Unmarshal(t, out); err != nil {
		return nil, errors.OAuth2ServerError("failed to unmarshal request").WithError(err)
	}

	return out, nil
}

// CreateV2 satisifies an http PUT action by creating a unique storage object.
// It does this leveraging the saga system which acts as a tape to enable rollbacks
// in case of errors.
func (c *Client) CreateV2(ctx context.Context, request *openapi.StorageV2Create) (*openapi.StorageV2Read, error) {
	if err := rbac.AllowProjectScope(ctx, "region:filestorage:v2", identityapi.Create,
		request.Spec.OrganizationId, request.Spec.ProjectId); err != nil {
		return nil, err
	}

	s := newCreateSaga(c, request)

	if err := saga.Run(ctx, s); err != nil {
		return nil, err
	}

	return convertV2(s.filestorage), nil
}

// Update satisifies an http POST action by updating the storage object attached
// to the storage ID.
// it leverages the update saga system, which acts as a tape to enable rollbacks
// in case of errors.
func (c *Client) Update(ctx context.Context, storageID string, request *openapi.StorageV2Update) (*openapi.StorageV2Read, error) {
	current, err := c.GetRaw(ctx, storageID)
	if err != nil {
		return nil, err
	}

	if err := rbac.AllowProjectScope(ctx, "region:filestorage:v2", identityapi.Delete, current.Labels[coreconstants.OrganizationLabel], current.Labels[coreconstants.ProjectLabel]); err != nil {
		return nil, err
	}

	if current.DeletionTimestamp != nil {
		return nil, errors.OAuth2InvalidRequest("filestorage is being deleted")
	}

	s := newUpdateSaga(c, current, request)
	if err := saga.Run(ctx, s); err != nil {
		return nil, err
	}

	storage := convertV2(s.updated)

	return storage, nil
}

// Delete satisfies the http DELETE action by removing the client.
// It does not leverage the saga system because we can rely on finalizers
// to handle this for us.
func (c *Client) Delete(ctx context.Context, storageID string) error {
	resource, err := c.GetRaw(ctx, storageID)
	if err != nil {
		return err
	}

	organizationID := resource.Labels[coreconstants.OrganizationLabel]
	projectID := resource.Labels[coreconstants.ProjectLabel]

	if err := rbac.AllowProjectScope(ctx, "region:filestorage:v2", identityapi.Delete, organizationID, projectID); err != nil {
		return err
	}

	if resource.DeletionTimestamp != nil {
		return nil
	}

	if err := c.Client.Delete(ctx, resource); err != nil {
		return errors.OAuth2ServerError("delete failed").WithError(err)
	}

	return nil
}

func (c *Client) ListClasses(ctx context.Context, params openapi.GetApiV2FilestorageclassesParams) (openapi.StorageClassListV2Read, error) {
	selector, err := util.AddRegionIDQuery(labels.Everything(), params.RegionID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to add region label selector").WithError(err)
	}

	result := &regionv1.FileStorageClassList{}
	options := &client.ListOptions{
		Namespace:     c.Namespace,
		LabelSelector: selector,
	}

	if err := c.Client.List(ctx, result, options); err != nil {
		return nil, errors.OAuth2ServerError("unable to list storage classes").WithError(err)
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

		return nil, errors.OAuth2ServerError("unable to lookup storage class").WithError(err)
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
			RegionId:  in.Labels[constants.RegionLabel],
			Protocols: convertProtocols(in.Spec.Protocols),
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

	return rbac.AllowOrganizationScope(ctx, "region:filestorageclass:v2", identityapi.Read, orgID)
}
