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

package region

import (
	"context"
	goerrors "errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/cenkalti/backoff/v4"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/saga"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/identity"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	kerrors "k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var ErrFailedImageFetch = goerrors.New("image fetch failed")

type createImageForUploadSaga struct {
	client         *Client
	organizationID string
	regionID       string
	sourceFormat   *openapi.ImageDiskFormat
	sourceURL      *string
	image          *types.Image
	provider       types.Provider

	result *types.Image
}

func (s *createImageForUploadSaga) validateSourceURL(ctx context.Context) error {
	if s.sourceURL == nil {
		return nil
	}

	if _, err := url.Parse(*s.sourceURL); err != nil {
		return errors.OAuth2InvalidRequest("The provided URL is not valid").WithError(err)
	}

	return nil
}

func (s *createImageForUploadSaga) convertImageDiskFormat(ctx context.Context) error {
	s.image.DiskFormat = types.ImageDiskFormatRaw

	if s.sourceFormat == nil {
		return nil
	}

	f, err := generateDiskFormat(*s.sourceFormat)
	if err != nil {
		return errors.OAuth2InvalidRequest("The provided disk format is not valid").WithError(err)
	}

	s.image.DiskFormat = f

	return nil
}

func (s *createImageForUploadSaga) createImage(ctx context.Context) error {
	s.image.DataSource = types.ImageDataSourceFile
	if s.sourceURL != nil {
		s.image.DataSource = types.ImageDataSourceURL
	}

	result, err := s.provider.CreateImageForUpload(ctx, s.image)
	if err != nil {
		return errors.OAuth2ServerError("failed to create image").WithError(err)
	}

	s.result = result

	return nil
}

func (s *createImageForUploadSaga) deleteImage(ctx context.Context) error {
	if s.result == nil {
		return errors.OAuth2ServerError("unexpected nil image")
	}

	if err := s.provider.DeleteImage(ctx, s.result.ID); err != nil {
		return errors.OAuth2ServerError("failed to delete image")
	}

	return nil
}

func (s *createImageForUploadSaga) uploadFromURL(ctx context.Context, source string) error {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return err
	}

	res, err := http.DefaultClient.Do(r)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		// Reading and closing the response body lets us reuse connections; but, defensively, don't just read
		// until the other side decides to stop sending!
		body := io.LimitReader(res.Body, 10*1024)
		_, _ = io.Copy(io.Discard, body)

		return fmt.Errorf("%w: non-OK status code (%s) from fetching source", ErrFailedImageFetch, res.Status)
	}

	if _, err := UploadImageData(ctx, s.image.ID, s.result.DiskFormat, res.Body, s.provider); err != nil {
		return err
	}

	return nil
}

func (s *createImageForUploadSaga) createImageUploadTask(ctx context.Context) error {
	if s.sourceURL == nil {
		return nil
	}

	source := *s.sourceURL

	if s.result == nil {
		return errors.OAuth2ServerError("unexpected nil image")
	}

	go func(ctx context.Context) {
		if err := s.uploadFromURL(ctx, source); err != nil {
			// NB the image will not be published if it's not successfully uploaded, so
			// there's no further action to take here; in particular, no need to update
			// the record at the provider.
			log.FromContext(ctx).Error(err, "fetching from given source", "url", source)
		}
	}(context.WithoutCancel(ctx))

	return nil
}

func (s *createImageForUploadSaga) Actions() []saga.Action {
	// REVIEW_ME: This could be problematic if the error is caused by context cancellation, since we would still reuse the same context for all compensation actions.
	return []saga.Action{
		saga.NewAction("validate source url", s.validateSourceURL, nil),
		saga.NewAction("convert disk format", s.convertImageDiskFormat, nil),
		saga.NewAction("create image", s.createImage, s.deleteImage),
		saga.NewAction("create image upload task", s.createImageUploadTask, nil),
	}
}

func (s *createImageForUploadSaga) Result() (*types.Image, error) {
	if s.result == nil {
		return nil, errors.OAuth2ServerError("unexpected nil image result")
	}

	return s.result, nil
}

type createImageFromServerSaga struct {
	client         *Client
	organizationID string
	regionID       string
	serverID       string
	image          *types.Image
	provider       types.Provider

	server   *unikornv1.Server
	identity *unikornv1.Identity
	imageID  string

	result *types.Image
}

func (s *createImageFromServerSaga) retrieveServer(ctx context.Context) error {
	var server unikornv1.Server

	if err := s.client.client.Get(ctx, client.ObjectKey{Namespace: s.client.namespace, Name: s.serverID}, &server); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.OAuth2InvalidRequest("The provided server does not exist").WithError(err)
		}

		return errors.OAuth2ServerError("failed to get server").WithError(err)
	}

	if server.Labels[coreconstants.OrganizationLabel] != s.organizationID {
		return errors.OAuth2InvalidRequest("The provided server does not exist")
	}

	s.server = &server

	return nil
}

func (s *createImageFromServerSaga) retrieveIdentity(ctx context.Context) error {
	if s.server == nil {
		return errors.OAuth2ServerError("unexpected nil server")
	}

	projectID := s.server.Labels[coreconstants.ProjectLabel]
	identityID := s.server.Labels[constants.IdentityLabel]

	identity, err := identity.New(s.client.client, s.client.namespace).GetRaw(ctx, s.organizationID, projectID, identityID)
	if err != nil {
		return err
	}

	s.identity = identity

	return nil
}

func (s *createImageFromServerSaga) createImage(ctx context.Context) error {
	if s.server == nil {
		return errors.OAuth2ServerError("unexpected nil server")
	}

	if s.identity == nil {
		return errors.OAuth2ServerError("unexpected nil identity")
	}

	imageID, err := s.provider.CreateImageFromServer(ctx, s.identity, s.server, s.image)
	if err != nil {
		// FIXME: We should provide a better error description instead of using the default one defined in HTTPConflict function.
		// This means the server isn't in a valid state to create an image from. It could be because the server isn't in the desired status, or a snapshot is already being created.
		if goerrors.Is(err, types.ErrResourceNotFound) {
			return errors.HTTPNotFound().WithError(err)
		}

		if goerrors.Is(err, types.ErrResourceNotFound) {
			return errors.HTTPConflict().WithError(err)
		}

		return errors.OAuth2ServerError("failed to create image").WithError(err)
	}

	s.imageID = imageID

	return nil
}

func (s *createImageFromServerSaga) deleteImage(ctx context.Context) error {
	if s.imageID == "" {
		return errors.OAuth2ServerError("unexpected empty image ID")
	}

	// This should give enough time for the image to appear in the provider before we attempt deletion.
	backoffStrategy := backoff.NewExponentialBackOff(backoff.WithMaxElapsedTime(5 * time.Minute))

	for {
		if err := s.provider.DeleteImage(ctx, s.imageID); err != nil {
			if goerrors.Is(err, types.ErrResourceNotFound) {
				backoffDuration := backoffStrategy.NextBackOff()
				time.Sleep(backoffDuration)

				continue
			}

			return errors.OAuth2ServerError("failed to delete image").WithError(err)
		}

		return nil
	}
}

func (s *createImageFromServerSaga) publishImage(ctx context.Context) error {
	if s.imageID == "" {
		return errors.OAuth2ServerError("unexpected empty image ID")
	}

	// This should give enough time for the image to appear in the provider before we attempt publishing.
	backoffStrategy := backoff.NewExponentialBackOff(backoff.WithMaxElapsedTime(5 * time.Minute))

	for {
		image, err := s.provider.PublishImage(ctx, s.imageID)
		if err != nil {
			if goerrors.Is(err, types.ErrResourceNotFound) {
				backoffDuration := backoffStrategy.NextBackOff()
				time.Sleep(backoffDuration)

				continue
			}

			return errors.OAuth2ServerError("failed to publish image").WithError(err)
		}

		s.result = image

		return nil
	}
}

// createImageMonitorTask runs a thread to watch the Image record stream at the provider, and
// invalidate the cache if/when it has succeeded.
func (s *createImageFromServerSaga) createImageMonitorTask(ctx context.Context) error {
	if s.imageID == "" {
		return errors.OAuth2ServerError("unexpected empty image ID")
	}

	go func(ctx context.Context) {
		ok, err := s.waitForSnapshot(ctx)
		if err != nil {
			log.FromContext(ctx).Error(err, "error waiting for snapshot image to be completed")
		}

		if ok {
			if err := s.provider.ClearImageCache(ctx); err != nil {
				log.FromContext(ctx).Error(err, "clearing image cache after successful snapshot")
			}
		}
	}(context.WithoutCancel(ctx))

	return nil
}

// waitForSnapshot blocks until it can give a definitive status for an image that has been created as a snapshot.
// The result is true if the image has becomes ready, and false otherwise; and error is returned if there was a problem
// polling the provider.
func (s *createImageFromServerSaga) waitForSnapshot(ctx context.Context) (bool, error) {
	backoffStrategy := backoff.NewExponentialBackOff(backoff.WithMaxElapsedTime(time.Hour))

	for {
		resource, err := s.provider.GetImage(ctx, s.organizationID, s.imageID)
		if err != nil {
			if goerrors.Is(err, types.ErrResourceNotFound) {
				if backoffStrategy.GetElapsedTime() > 30*time.Minute {
					return false, fmt.Errorf("%w: image %s not found after waiting for 30 minutes", ErrResource, s.imageID)
				}

				time.Sleep(backoffStrategy.NextBackOff())

				continue
			}

			return false, err
		}

		switch resource.Status {
		case types.ImageStatusCreating, types.ImageStatusPending:
			time.Sleep(backoffStrategy.NextBackOff())
		case types.ImageStatusReady:
			return true, nil
		case types.ImageStatusFailed:
			return false, nil
		default:
			return false, fmt.Errorf("%w: unexpected image status %s for image %s", ErrResource, resource.Status, s.imageID)
		}
	}
}

func (s *createImageFromServerSaga) Actions() []saga.Action {
	return []saga.Action{
		saga.NewAction("retrieve server", s.retrieveServer, nil),
		saga.NewAction("retrieve identity", s.retrieveIdentity, nil),
		saga.NewAction("create image", s.createImage, s.deleteImage),
		saga.NewAction("publish image", s.publishImage, nil),
		saga.NewAction("create image monitor task", s.createImageMonitorTask, nil),
	}
}

func (s *createImageFromServerSaga) Result() (*types.Image, error) {
	if s.result == nil {
		return nil, errors.OAuth2ServerError("unexpected nil image result")
	}

	return s.result, nil
}
