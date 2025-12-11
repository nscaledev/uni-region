/*
Copyright 2025 the Unikorn Authors.

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
	"slices"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/saga"
	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/util"
	"github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Client provides a restful API for storage.
type Client struct {
	// client ia a Kubernetes client.
	client client.Client
	// namespace we are running in.
	namespace string
	// identity allows quota allocation.
	identity identityapi.ClientWithResponsesInterface
}

// New creates a new client.
func New(client client.Client, namespace string, identity identityapi.ClientWithResponsesInterface) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
		identity:  identity,
	}
}

func convertV2(in *regionv1.FileStorage) *openapi.StorageV2Read {
	return &openapi.StorageV2Read{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.StorageV2Spec{
			Attachments: &openapi.StorageAttachmentV2Spec{
				NetworkIDs: convertAttachmentsList(in.Spec.Attachments),
			},
			StorageType: openapi.StorageTypeV2Spec{
				NFS: checkRegionNFS(in.Spec.NFS),
			},
			Size: in.Spec.Size.String(),
		},
		Status: openapi.StorageV2Status{
			RegionId:       in.Labels[constants.RegionLabel],
			StorageClassId: in.Spec.StorageClassID,
		},
	}
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
		Namespace:     c.namespace,
		LabelSelector: selector,
	}

	result := &regionv1.FileStorageList{}

	err = c.client.List(ctx, result, options)
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

	return convertV2List(result), nil
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

	err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: storageID}, result)
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

	return convertV2(result), nil
}

func (c *Client) generateV2(ctx context.Context, organizationID, projectID, regionID string, request *openapi.StorageV2Update, storageClassID string) (*regionv1.FileStorage, error) {
	size, err := convertSize(request.Spec.Size)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to convert size to resource.Quantity").WithError(err)
	}

	out := &regionv1.FileStorage{
		ObjectMeta: conversion.NewObjectMetadata(&request.Metadata, c.namespace).
			WithOrganization(organizationID).
			WithProject(projectID).
			WithLabel(constants.RegionLabel, regionID).
			Get(),
		Spec: regionv1.FileStorageSpec{
			Tags:        conversion.GenerateTagList(request.Metadata.Tags),
			Size:        *size,
			Attachments: generateAttachmentList(request.Spec.Attachments),
			NFS: &regionv1.NFS{
				RootSquash: checkRootSquash(request.Spec.StorageType.NFS),
			},
			StorageClassID: storageClassID,
		},
	}

	err = util.InjectUserPrincipal(ctx, organizationID, projectID)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to set principal information").WithError(err)
	}

	err = common.SetIdentityMetadata(ctx, &out.ObjectMeta)
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

func generateAttachmentList(in *openapi.StorageAttachmentV2Spec) []regionv1.Attachment {
	out := make([]regionv1.Attachment, len(in.NetworkIDs))
	for i := range in.NetworkIDs {
		out[i] = regionv1.Attachment{
			NetworkID: in.NetworkIDs[i],
		}
	}

	return out
}

func convertSize(size string) (*resource.Quantity, error) {
	quantity, err := resource.ParseQuantity(size)
	if err != nil {
		return nil, err
	}

	return &quantity, nil
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

	organizationID := current.Labels[coreconstants.OrganizationLabel]
	projectID := current.Labels[coreconstants.ProjectLabel]
	regionID := current.Labels[constants.RegionLabel]

	required, err := c.generateV2(ctx, organizationID, projectID, regionID, request, current.Spec.StorageClassID)
	if err != nil {
		return nil, err
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	s := newUpdateSaga(c, organizationID, regionID, current, updated)
	if err := saga.Run(ctx, s); err != nil {
		return nil, err
	}

	return convertV2(updated), nil
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

	if err := c.client.Delete(ctx, resource); err != nil {
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
		Namespace:     c.namespace,
		LabelSelector: selector,
	}

	if err := c.client.List(ctx, result, options); err != nil {
		return nil, errors.OAuth2ServerError("unable to list storage classes").WithError(err)
	}

	result.Items = slices.DeleteFunc(result.Items, func(resource regionv1.FileStorageClass) bool {
		return rbac.AllowOrganizationScope(ctx, "region:filestorageclass:v2", identityapi.Read, resource.Labels[coreconstants.OrganizationLabel]) != nil
	})

	slices.SortStableFunc(result.Items, func(a, b regionv1.FileStorageClass) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertClassList(result), nil
}

func (c *Client) GetStorageClass(ctx context.Context, storageClassID string) (*openapi.StorageClassV2Read, error) {
	result := &regionv1.FileStorageClass{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: storageClassID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to lookup storage class").WithError(err)
	}

	if err := rbac.AllowOrganizationScope(ctx, "region:filestorageclass:v2", identityapi.Read, result.Labels[coreconstants.OrganizationLabel]); err != nil {
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
