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
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/identity"
	"github.com/unikorn-cloud/region/pkg/handler/util"
	"github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Client provides a restful API for networks.
type Client struct {
	// client ia a Kubernetes client.
	client client.Client
	// namespace we are running in.
	namespace string
	// identity allows quota allocation.
	identity identityclient.APIClientGetter
}

// New creates a new client.
func New(client client.Client, namespace string, identity identityclient.APIClientGetter) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
		identity:  identity,
	}
}

func convertRoute(in *regionv1.Route) *openapi.Route {
	return &openapi.Route{
		Prefix:  in.Prefix.String(),
		Nexthop: in.NextHop.String(),
	}
}

func convertRoutes(in []regionv1.Route) *openapi.Routes {
	if len(in) == 0 {
		return nil
	}

	out := make(openapi.Routes, len(in))

	for i := range in {
		out[i] = *convertRoute(&in[i])
	}

	return &out
}

func convertV2(in *regionv1.FileStorage) *openapi.StorageV2Read {
	return &openapi.StorageV2Read{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.StorageV2Spec{
			Attachments: &openapi.StorageAttachmentV2Spec{},
			StorageType: openapi.StorageTypeV2Spec{},
		},
		Status: openapi.StorageV2Status{
			RegionId: in.Labels[constants.RegionLabel],
		},
	}
}

func (c *Client) ListV2(ctx context.Context, params openapi.GetApiV2FilestorageParams) (openapi.StoragesV2List, error) {
	selector := labels.SelectorFromSet(map[string]string{
		constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
	})

	var err error

	selector, err = rbac.AddOrganizationAndProjectIDQuery(ctx, selector, util.OrganizationIDQuery(params.OrganizationID), util.ProjectIDQuery(params.ProjectID))
	if err != nil {
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

	if err := c.client.List(ctx, result, options); err != nil {
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

func convertV2List(in *regionv1.FileStorageList) openapi.StoragesV2List {
	out := make(openapi.StoragesV2List, len(in.Items))

	for i := range in.Items {
		out[i] = *convertV2(&in.Items[i])
	}

	return out
}

func (c *Client) GetRaw(ctx context.Context, storageID string) (*regionv1.FileStorage, error) {
	result := &regionv1.FileStorage{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: storageID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to lookup storage").WithError(err)
	}

	if err := rbac.AllowProjectScope(ctx, "region:filestorage:v2", identityapi.Read, result.Labels[coreconstants.OrganizationLabel], result.Labels[coreconstants.ProjectLabel]); err != nil {
		return nil, err
	}

	// Only allow access to resources created by this API (temporarily).
	v, ok := result.Labels[constants.ResourceAPIVersionLabel]
	if !ok {
		return nil, errors.HTTPNotFound()
	}

	version, err := constants.UnmarshalAPIVersion(v)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to parse API version")
	}

	if version != 2 {
		return nil, errors.HTTPNotFound()
	}

	return result, nil
}

func (c *Client) Get(ctx context.Context, storageID string) (*openapi.StorageV2Read, error) {
	result, err := c.GetRaw(ctx, storageID)
	if err != nil {
		return nil, err
	}

	return convertV2(result), nil
}

// convertCreateToUpdateRequest marshals a create request into an update request
// that can be used with generate().  Updates are a subset of creates (without the
// immutable bits).
func convertCreateToUpdateRequest(in *openapi.NetworkV2Create) (*openapi.NetworkV2Update, error) {
	t, err := json.Marshal(in)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to marshal request").WithError(err)
	}

	out := &openapi.NetworkV2Update{}

	if err := json.Unmarshal(t, out); err != nil {
		return nil, errors.OAuth2ServerError("failed to unmarshal request").WithError(err)
	}

	return out, nil
}

func (c *Client) generateV2(ctx context.Context, organizationID, projectID, regionID string, request *openapi.StorageV2Update) (*regionv1.FileStorage, error) {

	out := &regionv1.FileStorage{
		ObjectMeta: conversion.NewObjectMetadata(&request.Metadata, c.namespace).
			WithOrganization(organizationID).
			WithProject(projectID).
			WithLabel(constants.RegionLabel, regionID).
			WithLabel(constants.ResourceAPIVersionLabel, constants.MarshalAPIVersion(2)).
			Get(),
		Spec: regionv1.FileStorageSpec{
			Tags: conversion.GenerateTagList(request.Metadata.Tags),
		},
	}

	if err := util.InjectUserPrincipal(ctx, organizationID, projectID); err != nil {
		return nil, errors.OAuth2ServerError("unable to set principal information").WithError(err)
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	return out, nil
}

type createSaga struct {
	client  *Client
	request *openapi.StorageV2Create

	identity    *regionv1.Identity
	filestorage *regionv1.FileStorage
}

func newCreateSaga(client *Client, request *openapi.StorageV2Create) *createSaga {
	return &createSaga{
		client:  client,
		request: request,
	}
}

// createAllocation creates an allocation for the network ID and then attaches
// the allocation ID to the network for persistence.
func (s *createSaga) createAllocation(ctx context.Context) error {
	required := identityapi.ResourceAllocationList{
		{
			Kind:      "filestorage",
			Committed: 1,
		},
	}

	if err := identityclient.NewAllocations(s.client.client, s.client.identity).Create(ctx, s.filestorage, required); err != nil {
		return err
	}

	return nil
}

func (s *createSaga) deleteAllocation(ctx context.Context) error {
	if err := identityclient.NewAllocations(s.client.client, s.client.identity).Delete(ctx, s.filestorage); err != nil {
		return err
	}

	return nil
}

func (s *createSaga) Actions() []saga.Action {
	return []saga.Action{
		saga.NewAction("validate request", s.validateRequest, nil),
		saga.NewAction("create quota allocation", s.createAllocation, s.deleteAllocation),
		saga.NewAction("create filestorage", s.createFileStorage, nil),
	}
}

func (c *Client) CreateV2(ctx context.Context, request *openapi.StorageV2Create) (*openapi.StorageV2Read, error) {
	if err := rbac.AllowProjectScope(ctx, "region:filestorage:v2", identityapi.Create, request.Spec.OrganizationId, request.Spec.ProjectId); err != nil {
		return nil, err
	}

	s := newCreateSaga(c, request)

	if err := saga.Run(ctx, s); err != nil {
		return nil, err
	}

	return convertV2(s.filestorage), nil
}

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

	required, err := c.generateV2(ctx, organizationID, projectID, regionID, request)
	if err != nil {
		return nil, err
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return nil, errors.OAuth2ServerError("unable to update filestorage").WithError(err)
	}

	return convertV2(updated), nil
}

func (c *Client) Delete(ctx context.Context, storageID string) error {
	resource, err := c.GetV2Raw(ctx, storageID)
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

	// The V2 API doesn't expose service principals, but they are mapped 1:1 to networks, so as the
	// real root of the tree we actually delete that and allow cascading deletion to do the
	// rest.
	return identity.New(c.client, c.namespace).Delete(ctx, organizationID, projectID, resource.Labels[constants.IdentityLabel])
}

func (c *Client) GetV2Raw(ctx context.Context, storageID string) (*regionv1.FileStorage, error) {
	result := &regionv1.FileStorage{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: storageID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to lookup file storage").WithError(err)
	}

	if err := rbac.AllowProjectScope(ctx, "region:filestorage:v2", identityapi.Read, result.Labels[coreconstants.OrganizationLabel], result.Labels[coreconstants.ProjectLabel]); err != nil {
		return nil, err
	}

	// Only allow access to resources created by this API (temporarily).
	v, ok := result.Labels[constants.ResourceAPIVersionLabel]
	if !ok {
		return nil, errors.HTTPNotFound()
	}

	version, err := constants.UnmarshalAPIVersion(v)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to parse API version")
	}

	if version != 2 {
		return nil, errors.HTTPNotFound()
	}

	return result, nil
}

func (s *createSaga) createFileStorage(ctx context.Context) error {
	if err := s.client.client.Create(ctx, s.filestorage); err != nil {
		return errors.OAuth2ServerError("unable to create filestorage").WithError(err)
	}

	return nil
}

func (s *createSaga) validateRequest(ctx context.Context) error {

	filestorage, err := s.client.generateV2(ctx, s.request.Spec.OrganizationId, s.request.Spec.ProjectId, s.request.Spec.RegionId)
	if err != nil {
		return err
	}

	s.filestorage = filestorage

	return nil
}
