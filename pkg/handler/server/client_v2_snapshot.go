/*
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
	"context"
	"encoding/json"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/server/saga"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/image"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"
)

func (c *ClientV2) CreateV2Snapshot(ctx context.Context, serverID string, request *openapi.SnapshotCreate) (*openapi.ImageResponse, error) {
	server, id, provider, err := c.getServerIdentityAndProviderV2(ctx, serverID)
	if err != nil {
		return nil, err
	}

	snapshot := snapshotState{
		request:        request,
		organizationID: server.Labels[constants.OrganizationLabel],
		client:         c,
		server:         server,
		identity:       id,
		provider:       provider,
	}

	if err := saga.Run(ctx, &snapshot); err != nil {
		return nil, err
	}

	return snapshot.result, nil
}

type snapshotState struct {
	// input: the request
	request *openapi.SnapshotCreate
	// input: organization where this is created (used to scope the image)
	organizationID string
	// input: the server
	server *regionv1.Server
	// input: the client to use to get things
	client *ClientV2

	// state: the provider for the region in which the server lives
	provider serverProvider
	// state: identity for provider operations
	identity *regionv1.Identity
	// state: the image used by the server
	originalImage *types.Image
	// state: the ID of the snapshot image
	snapshotID string
	// state: the image result
	result *openapi.Image
}

func (s *snapshotState) Actions() []saga.Action {
	return []saga.Action{
		saga.NewAction("get server image", s.fetchServerImage, nil),
		saga.NewAction("request snapshot", s.requestSnapshot, s.deleteSnapshot),
		saga.NewAction("get snapshot image", s.fetchSnapshotImage, nil),
	}
}

func (s *snapshotState) fetchServerImage(ctx context.Context) error {
	serverImage := s.server.Spec.Image
	if serverImage == nil {
		// TODO decide what to do here. Is this normal?
		return errors.ErrConsistency
	}

	imageID := serverImage.ID

	image, err := s.provider.GetImage(ctx, s.organizationID, imageID)
	if err != nil {
		return err
	}

	s.originalImage = image
	return nil
}

func (s *snapshotState) generateSnapshotImage() (*types.Image, error) {
	// I don't want to mutate a record that's cached and used elsewhere.
	// TODO this is pretty quick and dirty; the provider only really cares about the name and metadata anyway.
	bytes, err := json.Marshal(s.originalImage)
	if err != nil {
		return nil, err
	}

	var generated types.Image
	if err := json.Unmarshal(bytes, &generated); err != nil {
		return nil, err
	}

	generated.Name = s.request.Metadata.Name
	generated.OrganizationID = &s.organizationID

	return &generated, nil
}

func (s *snapshotState) requestSnapshot(ctx context.Context) error {
	snapshotImage, err := s.generateSnapshotImage()
	if err != nil {
		return err
	}

	snapshotID, err := s.provider.CreateImageFromServer(ctx, s.identity, s.server, snapshotImage)
	if err != nil {
		return err
	}

	s.snapshotID = snapshotID

	return nil
}

func (s *snapshotState) deleteSnapshot(ctx context.Context) error {
	if s.snapshotID != "" {
		return s.provider.DeleteImage(ctx, s.snapshotID)
	}
	return nil
}

func (s *snapshotState) fetchSnapshotImage(ctx context.Context) error {
	result, err := s.provider.GetImage(ctx, s.organizationID, s.snapshotID)
	if err != nil {
		return err
	}

	s.result = image.ConvertImage(result)

	return nil
}
