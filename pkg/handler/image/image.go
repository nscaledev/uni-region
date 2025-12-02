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

package image

import (
	"cmp"
	"context"
	goerrors "errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/saga"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type GetProviderFunc func(context.Context, client.Client, string, string) (Provider, error)

type Client struct {
	client      client.Client
	namespace   string
	getProvider GetProviderFunc
}

func DefaultGetProvider(ctx context.Context, c client.Client, namespace, regionID string) (Provider, error) {
	return providers.New(ctx, c, namespace, regionID)
}

func NewClient(client client.Client, namespace string, getProvider GetProviderFunc) *Client {
	return &Client{
		client:      client,
		namespace:   namespace,
		getProvider: getProvider,
	}
}

var ErrFailedImageFetch = goerrors.New("image fetch failed")
var ErrProviderResource = goerrors.New("conflict with resource at provider")

type Provider interface {
	types.ImageRead
	types.ImageWrite
}

func (c *Client) provider(ctx context.Context, regionID string) (Provider, error) {
	return c.getProvider(ctx, c.client, c.namespace, regionID)
}

func (c *Client) ListImages(ctx context.Context, organizationID, regionID string) (openapi.Images, error) {
	provider, err := c.provider(ctx, regionID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	result, err := provider.ListImages(ctx, organizationID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to list images").WithError(err)
	}

	// Apply ordering guarantees, ordered by name.
	slices.SortStableFunc(result, func(a, b types.Image) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertImages(result), nil
}

func (c *Client) CreateImage(ctx context.Context, organizationID, regionID string, request *openapi.ImageCreateRequest) (*openapi.ImageResponse, error) {
	provider, err := c.provider(ctx, regionID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	var gpu *types.ImageGPU

	if request.Spec.Gpu != nil {
		gpu = generateImageGPU(request.Spec.Gpu)
	}

	var packages *types.ImagePackages

	if request.Spec.SoftwareVersions != nil {
		temp := generatePackages(*request.Spec.SoftwareVersions)
		packages = &temp
	}

	image := &types.Image{
		Name:           request.Metadata.Name,
		OrganizationID: ptr.To(organizationID),
		Virtualization: generateImageVirtualization(request.Spec.Virtualization),
		GPU:            gpu,
		OS:             *generateImageOS(&request.Spec.Os),
		Packages:       packages,
	}

	tx := &createImageForUploadSaga{
		client:         c,
		organizationID: organizationID,
		regionID:       regionID,
		sourceFormat:   request.Spec.SourceFormat,
		sourceURL:      request.Spec.SourceURL,
		image:          image,
		provider:       provider,
	}

	if err = saga.Run(ctx, tx); err != nil {
		return nil, err
	}

	result, err := tx.Result()
	if err != nil {
		return nil, err
	}

	return convertImage(result), nil
}

func (c *Client) UploadImage(ctx context.Context, organizationID, regionID, imageID string, contentType string, data io.Reader) (*openapi.ImageResponse, error) {
	provider, err := c.provider(ctx, regionID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	image, err := provider.GetImage(ctx, organizationID, imageID)
	if err != nil {
		if goerrors.Is(err, types.ErrResourceNotFound) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("failed to get image").WithError(err)
	}

	if image.Status != types.ImageStatusPending {
		return nil, errors.HTTPConflict()
	}

	if image.OrganizationID == nil || *image.OrganizationID != organizationID {
		return nil, errors.HTTPNotFound()
	}

	if err := uploadImageData(ctx, imageID, image.DiskFormat, data, provider); err != nil {
		return nil, err
	}

	return convertImage(image), nil
}

func (c *Client) DeleteImage(ctx context.Context, organizationID, regionID, imageID string) error {
	provider, err := c.provider(ctx, regionID)
	if err != nil {
		return errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	image, err := provider.GetImage(ctx, organizationID, imageID)
	if err != nil {
		if goerrors.Is(err, types.ErrResourceNotFound) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to get image").WithError(err)
	}

	if image.OrganizationID == nil || *image.OrganizationID != organizationID {
		return errors.HTTPNotFound()
	}

	if err = provider.DeleteImage(ctx, imageID); err != nil {
		// Most deletion APIs ignore not found errors, but our other delete APIs return 404. To maintain consistency, we do the same here.
		if goerrors.Is(err, types.ErrResourceNotFound) {
			return errors.HTTPNotFound().WithError(err)
		}

		// This means that the image is still being used by another resource.
		if goerrors.Is(err, types.ErrImageStillInUse) {
			return errors.HTTPConflict().WithError(err)
		}

		return errors.OAuth2ServerError("failed to delete image").WithError(err)
	}

	return nil
}

type createImageForUploadSaga struct {
	client         *Client
	organizationID string
	regionID       string
	sourceFormat   *openapi.ImageDiskFormat
	sourceURL      *string
	image          *types.Image
	provider       Provider

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

	if err := uploadImageData(ctx, s.result.ID, s.result.DiskFormat, res.Body, s.provider); err != nil {
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
