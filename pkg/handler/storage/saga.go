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
	"strconv"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/saga"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/network"
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

func (c *Client) generateAllocation(size int) identityapi.ResourceAllocationList {
	return identityapi.ResourceAllocationList{
		{
			Kind:      "filestorage",
			Committed: size,
		},
	}
}

func (s *createSaga) createAllocation(ctx context.Context) error {
	convertedSize, err := strconv.Atoi(s.request.Spec.Size)
	if err != nil {
		return err
	}

	required := s.client.generateAllocation(convertedSize)

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
	storageClassKey := client.ObjectKey{
		Name:      s.request.Spec.StorageClassId,
		Namespace: s.client.namespace,
	}
	storageType := regionv1.FileStorageClass{}
	networkClient := network.New(s.client.client, s.client.namespace, s.client.identity)

	err := s.client.client.Get(ctx, storageClassKey, &storageType)

	if err != nil {
		return errors.OAuth2ServerError("filestorage class does not exist").WithError(err)
	}

	for _, v := range s.request.Spec.Attachments.NetworkIDs {
		_, err = networkClient.GetV2(ctx, v)
		if err != nil {
			return errors.OAuth2ServerError("network attachment not found").WithError(err).WithValues("networkID", v)
		}
	}

	updateRequest, err := convertCreateToUpdateRequest(s.request)
	if err != nil {
		return err
	}

	filestorage, err := s.client.generateV2(ctx, s.request.Spec.OrganizationId, s.request.Spec.ProjectId, s.request.Spec.ProjectId, updateRequest)
	if err != nil {
		return err
	}

	s.filestorage = filestorage

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

func (s *updateSaga) updateAllocation(ctx context.Context) error {
	required := s.client.generateAllocation(s.updated.Spec.Size.Size())

	return identityclient.NewAllocations(s.client.client, s.client.identity).Update(ctx, s.current, required)
}

func (s *updateSaga) revertAllocation(ctx context.Context) error {
	required := s.client.generateAllocation(s.current.Spec.Size.Size())

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
		saga.NewAction("update quota allocation", s.updateAllocation, s.revertAllocation),
		saga.NewAction("update storage", s.updateStorage, nil),
	}
}
