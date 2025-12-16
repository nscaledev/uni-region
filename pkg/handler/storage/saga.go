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
	"context"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/saga"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/network"
	"github.com/unikorn-cloud/region/pkg/handler/region"
	"github.com/unikorn-cloud/region/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type createSaga struct {
	client  *Client
	request *openapi.StorageV2Create

	filestorage *regionv1.FileStorage
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
	required := s.client.generateAllocation(s.request.Spec.SizeGiB)

	return identityclient.NewAllocations(s.client.client, s.client.identity).Create(ctx, s.filestorage, required)
}

func (s *createSaga) deleteAllocation(ctx context.Context) error {
	if err := identityclient.NewAllocations(s.client.client, s.client.identity).Delete(ctx, s.filestorage); err != nil {
		return err
	}

	return nil
}

func (s *createSaga) createFileStorage(ctx context.Context) error {
	if err := s.client.client.Create(ctx, s.filestorage); err != nil {
		return errors.OAuth2ServerError("unable to create filestorage").WithError(err)
	}

	return nil
}

func (s *createSaga) validateRequest(ctx context.Context) error {
	if err := s.validateRegion(ctx, s.request.Spec.RegionId); err != nil {
		return err
	}

	if err := s.validateStorageClass(ctx, s.request.Spec.StorageClassId); err != nil {
		return err
	}

	if err := s.validateNetworks(ctx, s.request.Spec.Attachments.NetworkIDs); err != nil {
		return err
	}

	updateRequest, err := convertCreateToUpdateRequest(s.request)
	if err != nil {
		return err
	}

	filestorage, err := s.client.generateV2(ctx, s.request.Spec.OrganizationId, s.request.Spec.ProjectId, s.request.Spec.RegionId, updateRequest, s.request.Spec.StorageClassId)
	if err != nil {
		return err
	}

	s.filestorage = filestorage

	return nil
}

func (s *createSaga) validateRegion(ctx context.Context, regionID string) error {
	regionClient := region.NewClient(s.client.client, s.client.namespace)

	if _, err := regionClient.GetDetail(ctx, regionID); err != nil {
		return errors.OAuth2ServerError("region does not exist").WithError(err)
	}

	return nil
}

func (s *createSaga) validateStorageClass(ctx context.Context, storageClassID string) error {
	sc, err := s.client.GetStorageClass(ctx, storageClassID)
	if err != nil {
		return err
	}

	if sc.Spec.RegionId != s.request.Spec.RegionId {
		return errors.OAuth2InvalidRequest("storage class not available in region").WithError(err)
	}

	return nil
}

func (s *createSaga) validateNetworks(ctx context.Context, networkIDs []string) error {
	networkClient := network.New(s.client.client, s.client.namespace, s.client.identity)

	for _, id := range networkIDs {
		network, err := networkClient.GetV2(ctx, id)
		if err != nil {
			return errors.
				OAuth2ServerError("network attachment not found").
				WithError(err).
				WithValues("networkID", id)
		}

		if network.Metadata.ProjectId != s.request.Spec.ProjectId {
			return errors.OAuth2InvalidRequest("network not available in project").WithError(err)
		}
	}

	return nil
}

type updateSaga struct {
	client         *Client
	organizationID string
	regionID       string
	current        *regionv1.FileStorage
	updated        *regionv1.FileStorage
}

func newUpdateSaga(client *Client, organizationID, regionID string, current, updated *regionv1.FileStorage) *updateSaga {
	return &updateSaga{
		client:         client,
		organizationID: organizationID,
		regionID:       regionID,
		current:        current,
		updated:        updated,
	}
}

func (s *updateSaga) validateRequest(ctx context.Context) error {
	networkClient := network.New(s.client.client, s.client.namespace, s.client.identity)

	for _, attachment := range s.updated.Spec.Attachments {
		network, err := networkClient.GetV2(ctx, attachment.NetworkID)
		if err != nil {
			return errors.
				OAuth2InvalidRequest("network attachment not found").
				WithError(err).
				WithValues("networkID", attachment.NetworkID)
		}

		projectID := s.current.Labels[coreconstants.ProjectLabel]
		if network.Metadata.ProjectId != projectID {
			return errors.OAuth2InvalidRequest("network not available in project").WithError(err)
		}
	}

	return nil
}

func (s *updateSaga) updateAllocation(ctx context.Context) error {
	required := s.client.generateAllocation(s.updated.Spec.Size.Value())

	return identityclient.NewAllocations(s.client.client, s.client.identity).Update(ctx, s.current, required)
}

func (s *updateSaga) revertAllocation(ctx context.Context) error {
	required := s.client.generateAllocation(s.current.Spec.Size.Value())

	return identityclient.NewAllocations(s.client.client, s.client.identity).Update(ctx, s.current, required)
}

func (s *updateSaga) updateStorage(ctx context.Context) error {
	if err := s.client.client.Patch(ctx, s.updated, client.MergeFrom(s.current)); err != nil {
		return errors.OAuth2ServerError("unable to update filestorage").WithError(err)
	}

	return nil
}

func (s *updateSaga) Actions() []saga.Action {
	return []saga.Action{
		saga.NewAction("validate request", s.validateRequest, nil),
		saga.NewAction("update quota allocation", s.updateAllocation, s.revertAllocation),
		saga.NewAction("update storage", s.updateStorage, nil),
	}
}
