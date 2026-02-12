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

//go:generate mockgen -source=saga.go -destination=mock/saga.go -package=mock

import (
	"context"
	"fmt"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/saga"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/network"
	"github.com/unikorn-cloud/region/pkg/handler/region"
	"github.com/unikorn-cloud/region/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type NetworkGetter interface {
	GetV2(ctx context.Context, id string) (*openapi.NetworkV2Read, error)
}

var ErrAllocation = fmt.Errorf("allocation error")

// wrapAllocationError returns access/permission errors as-is so they
// surface the correct HTTP status to callers, and wraps everything else
// with ErrAllocation so callers can distinguish allocation failures.
func wrapAllocationError(err error) error {
	if err == nil {
		return nil
	}

	if errors.IsAccessDenied(err) || errors.IsForbidden(err) {
		return err
	}

	return fmt.Errorf("%w: %s", ErrAllocation, err.Error())
}

type createSaga struct {
	client  *Client
	request *openapi.StorageV2Create

	filestorage  *regionv1.FileStorage
	storageClass *openapi.StorageClassV2Read
}

func (s *createSaga) Actions() []saga.Action {
	return []saga.Action{
		saga.NewAction("validate request", s.validateRequest, nil),
		saga.NewAction("create quota allocation", s.createAllocation, s.deleteAllocation),
		saga.NewAction("create filestorage", s.createFileStorage, nil),
	}
}

func newCreateSaga(client *Client, request *openapi.StorageV2Create) *createSaga {
	return &createSaga{
		client:  client,
		request: request,
	}
}

func (c *Client) generateAllocation(size int64) identityapi.ResourceAllocationList {
	return identityapi.ResourceAllocationList{
		{
			Kind:      "filestorage",
			Committed: int(size),
		},
	}
}

func (s *createSaga) createAllocation(ctx context.Context) error {
	// We want to preserve that all sizes stored in k8s is in bytes
	quantity := gibToQuantity(s.request.Spec.SizeGiB)
	required := s.client.generateAllocation(quantity.Value())

	if err := identityclient.NewAllocations(s.client.Client, s.client.Identity).Create(ctx, s.filestorage, required); err != nil {
		return wrapAllocationError(err)
	}

	return nil
}

func (s *createSaga) deleteAllocation(ctx context.Context) error {
	if err := identityclient.NewAllocations(s.client.Client, s.client.Identity).Delete(ctx, s.filestorage); err != nil {
		return wrapAllocationError(err)
	}

	return nil
}

func (s *createSaga) createFileStorage(ctx context.Context) error {
	if err := s.client.Client.Create(ctx, s.filestorage); err != nil {
		return fmt.Errorf("%w: unable to create filestorage", err)
	}

	return nil
}

func (s *createSaga) validateRequest(ctx context.Context) error {
	if s.request.Spec.SizeGiB <= 0 {
		return errors.HTTPUnprocessableContent("size must be greater or equal to 1GiB")
	}

	if err := s.validateRegion(ctx, s.request.Spec.RegionId); err != nil {
		return err
	}

	if err := s.validateStorageClass(ctx, s.request.Spec.StorageClassId); err != nil {
		return err
	}

	networkClient := network.New(s.client.ClientArgs)
	if err := validateAttachments(ctx, networkClient, s.request.Spec.Attachments, s.request.Spec.ProjectId); err != nil {
		return err
	}

	updateRequest, err := convertCreateToUpdateRequest(s.request)
	if err != nil {
		return err
	}

	filestorage, err := s.client.generateV2(ctx, s.request.Spec.OrganizationId, s.request.Spec.ProjectId, s.request.Spec.RegionId, updateRequest, s.storageClass)
	if err != nil {
		return err
	}

	s.filestorage = filestorage

	return nil
}

func (s *createSaga) validateRegion(ctx context.Context, regionID string) error {
	regionClient := region.NewClient(s.client.ClientArgs)

	if _, err := regionClient.GetDetail(ctx, regionID); err != nil {
		if !errors.IsHTTPNotFound(err) {
			return err
		}

		return errors.HTTPUnprocessableContent("region does not exist").WithError(err)
	}

	return nil
}

func (s *createSaga) validateStorageClass(ctx context.Context, storageClassID string) error {
	sc, err := s.client.GetStorageClass(ctx, storageClassID)
	if err != nil {
		return err
	}

	if sc.Spec.RegionId != s.request.Spec.RegionId {
		return errors.HTTPUnprocessableContent("storage class not available in region").
			WithValues("storageClassID", sc.Metadata.Name, "storageClassRegionID", sc.Spec.RegionId, "requestedRegionID", s.request.Spec.RegionId)
	}

	s.storageClass = sc

	return nil
}

type updateSaga struct {
	client *Client

	request      *openapi.StorageV2Update
	current      *regionv1.FileStorage
	updated      *regionv1.FileStorage
	storageClass *openapi.StorageClassV2Read
}

func newUpdateSaga(client *Client, current *regionv1.FileStorage, request *openapi.StorageV2Update, storageClass *openapi.StorageClassV2Read) *updateSaga {
	return &updateSaga{
		client:       client,
		request:      request,
		current:      current,
		storageClass: storageClass,
	}
}

func (s *updateSaga) validateRequest(ctx context.Context) error {
	networkClient := network.New(s.client.ClientArgs)
	projectID := s.current.Labels[coreconstants.ProjectLabel]

	if err := validateAttachments(ctx, networkClient, s.request.Spec.Attachments, projectID); err != nil {
		return err
	}

	return nil
}

func (s *updateSaga) generate(ctx context.Context) error {
	organizationID := s.current.Labels[coreconstants.OrganizationLabel]
	projectID := s.current.Labels[coreconstants.ProjectLabel]
	regionID := s.current.Labels[constants.RegionLabel]

	required, err := s.client.generateV2(ctx, organizationID, projectID, regionID, s.request, s.storageClass)
	if err != nil {
		return err
	}

	if err := conversion.UpdateObjectMetadata(required, s.current, common.IdentityMetadataMutator); err != nil {
		return fmt.Errorf("%w: failed to merge metadata", err)
	}

	// Preserve the allocation.
	if v, ok := s.current.Annotations[coreconstants.AllocationAnnotation]; ok {
		required.Annotations[coreconstants.AllocationAnnotation] = v
	}

	s.updated = s.current.DeepCopy()
	s.updated.Labels = required.Labels
	s.updated.Annotations = required.Annotations
	s.updated.Spec = required.Spec

	return nil
}

func (s *updateSaga) updateAllocation(ctx context.Context) error {
	required := s.client.generateAllocation(s.updated.Spec.Size.Value())

	if err := identityclient.NewAllocations(s.client.Client, s.client.Identity).Update(ctx, s.current, required); err != nil {
		return wrapAllocationError(err)
	}

	return nil
}

func (s *updateSaga) revertAllocation(ctx context.Context) error {
	required := s.client.generateAllocation(s.current.Spec.Size.Value())

	if err := identityclient.NewAllocations(s.client.Client, s.client.Identity).Update(ctx, s.current, required); err != nil {
		return wrapAllocationError(err)
	}

	return nil
}

func (s *updateSaga) updateStorage(ctx context.Context) error {
	if err := s.client.Client.Patch(ctx, s.updated, client.MergeFrom(s.current)); err != nil {
		return fmt.Errorf("%w: unable to update filestorage", err)
	}

	return nil
}

func (s *updateSaga) Actions() []saga.Action {
	return []saga.Action{
		saga.NewAction("validate request", s.validateRequest, nil),
		saga.NewAction("generate", s.generate, nil),
		saga.NewAction("update quota allocation", s.updateAllocation, s.revertAllocation),
		saga.NewAction("update storage", s.updateStorage, nil),
	}
}

func validateAttachments(ctx context.Context, networkClient NetworkGetter, attachments *openapi.StorageAttachmentV2Spec, projectID string) error {
	if attachments == nil {
		return nil
	}

	for _, id := range attachments.NetworkIds {
		net, err := networkClient.GetV2(ctx, id)
		if err != nil {
			if !errors.IsHTTPNotFound(err) {
				return err
			}

			return errors.HTTPUnprocessableContent("network not found").WithError(err)
		}

		if net.Metadata.ProjectId != projectID {
			return errors.HTTPUnprocessableContent("network not available in project").
				WithValues("networkID", id, "expectedProjectID", projectID, "actualProjectID", net.Metadata.ProjectId)
		}

		if net.Metadata.ProvisioningStatus != coreopenapi.ResourceProvisioningStatusProvisioned {
			return errors.HTTPUnprocessableContent("network not provisioned").
				WithValues("networkID", id, "provisioningStatus", net.Metadata.ProvisioningStatus)
		}
	}

	return nil
}
