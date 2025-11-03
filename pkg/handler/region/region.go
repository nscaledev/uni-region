/*
Copyright 2024-2025 the Unikorn Authors.

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
	"archive/tar"
	"cmp"
	"compress/gzip"
	"context"
	"encoding/base64"
	goerrors "errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"time"

	"github.com/cenkalti/backoff/v4"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/saga"
	"github.com/unikorn-cloud/core/pkg/util"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/identity"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	// ErrResource is raised when a resource is in a bad state.
	ErrResource = goerrors.New("resource error")

	// ErrRegionNotFound is raised when a region doesn't exist.
	ErrRegionNotFound = goerrors.New("region doesn't exist")
)

type Client struct {
	client    client.Client
	namespace string
}

func NewClient(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

func (c *Client) Provider(ctx context.Context, regionID string) (types.Provider, error) {
	return providers.New(ctx, c.client, c.namespace, regionID)
}

func convertRegionType(in unikornv1.Provider) openapi.RegionType {
	switch in {
	case unikornv1.ProviderKubernetes:
		return openapi.Kubernetes
	case unikornv1.ProviderOpenstack:
		return openapi.Openstack
	}

	return ""
}

func convert(in *unikornv1.Region) *openapi.RegionRead {
	out := &openapi.RegionRead{
		Metadata: conversion.ResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.RegionSpec{
			Type: convertRegionType(in.Spec.Provider),
		},
	}

	// Calculate any region specific configuration.
	if in.Spec.Provider == unikornv1.ProviderOpenstack {
		if in.Spec.Openstack.Network != nil && in.Spec.Openstack.Network.ProviderNetworks != nil {
			out.Spec.Features.PhysicalNetworks = true
		}
	}

	return out
}

func (c *Client) convertDetail(ctx context.Context, in *unikornv1.Region) (*openapi.RegionDetailRead, error) {
	out := &openapi.RegionDetailRead{
		Metadata: conversion.ResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.RegionDetailSpec{
			Type: convertRegionType(in.Spec.Provider),
		},
	}

	// Calculate any region specific configuration.
	switch in.Spec.Provider {
	case unikornv1.ProviderKubernetes:
		secret := &corev1.Secret{}

		if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: in.Spec.Kubernetes.KubeconfigSecret.Name}, secret); err != nil {
			return nil, err
		}

		kubeconfig, ok := secret.Data["kubeconfig"]
		if !ok {
			return nil, fmt.Errorf("%w: kubeconfig kye missing in region secret", ErrResource)
		}

		out.Spec.Kubernetes = &openapi.RegionDetailKubernetes{
			Kubeconfig: base64.RawURLEncoding.EncodeToString(kubeconfig),
		}

		if in.Spec.Kubernetes.DomainName != "" {
			out.Spec.Kubernetes.DomainName = &in.Spec.Kubernetes.DomainName
		}
	case unikornv1.ProviderOpenstack:
		if in.Spec.Openstack.Network != nil && in.Spec.Openstack.Network.ProviderNetworks != nil {
			out.Spec.Features.PhysicalNetworks = true
		}
	}

	return out, nil
}

func convertList(in *unikornv1.RegionList) openapi.Regions {
	out := make(openapi.Regions, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i])
	}

	return out
}

func (c *Client) List(ctx context.Context) (openapi.Regions, error) {
	regions := &unikornv1.RegionList{}

	if err := c.client.List(ctx, regions, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, err
	}

	return convertList(regions), nil
}

func (c *Client) GetDetail(ctx context.Context, regionID string) (*openapi.RegionDetailRead, error) {
	result := &unikornv1.Region{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: regionID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to lookup region").WithError(err)
	}

	return c.convertDetail(ctx, result)
}

func (c *Client) ListFlavors(ctx context.Context, organizationID, regionID string) (openapi.Flavors, error) {
	provider, err := c.Provider(ctx, regionID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	result, err := provider.Flavors(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to list flavors").WithError(err)
	}

	// Apply ordering guarantees, ascending order with GPUs taking precedence over
	// CPUs and memory.
	slices.SortStableFunc(result, func(a, b types.Flavor) int {
		if v := cmp.Compare(a.GPUCount(), b.GPUCount()); v != 0 {
			return v
		}

		if v := cmp.Compare(a.CPUs, b.CPUs); v != 0 {
			return v
		}

		return cmp.Compare(a.Memory.Value(), b.Memory.Value())
	})

	return fromProviderFlavors(result), nil
}

func (c *Client) ClearImageCache(ctx context.Context, regionID string) error {
	provider, err := c.Provider(ctx, regionID)
	if err != nil {
		return errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	if err = provider.ClearImageCache(ctx); err != nil {
		return errors.OAuth2ServerError("failed to clear image cache").WithError(err)
	}

	return nil
}

func (c *Client) ListImages(ctx context.Context, organizationID, regionID string) (openapi.Images, error) {
	provider, err := c.Provider(ctx, regionID)
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

	return fromProviderImages(result), nil
}

func (c *Client) CreateImage(ctx context.Context, organizationID, regionID string, request *openapi.ImageCreateRequest) (*openapi.Image, error) {
	if request.Spec.SourceURL != nil && request.Spec.SourceServerID != nil {
		return nil, errors.OAuth2InvalidRequest("Only one source parameter may be provided. Specify either \"sourceURL\" or \"sourceServerID\", not both")
	}

	provider, err := c.Provider(ctx, regionID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	var gpu *types.ImageGPU

	if request.Spec.Gpu != nil {
		gpu = toProviderImageGPU(request.Spec.Gpu)
	}

	var packages *types.ImagePackages

	if request.Spec.SoftwareVersions != nil {
		temp := toProviderPackages(*request.Spec.SoftwareVersions)
		packages = &temp
	}

	image := &types.Image{
		Name:           request.Metadata.Name,
		OrganizationID: ptr.To(organizationID),
		Virtualization: toProviderImageVirtualization(request.Spec.Virtualization),
		GPU:            gpu,
		OS:             *toProviderImageOS(&request.Spec.Os),
		Packages:       packages,
	}

	type LocalTransaction interface {
		saga.Handler
		Result() (*types.Image, error)
	}

	var tx LocalTransaction

	if request.Spec.SourceServerID == nil {
		tx = &createImageForUploadSaga{
			client:         c,
			organizationID: organizationID,
			regionID:       regionID,
			sourceFormat:   request.Spec.SourceFormat,
			sourceURL:      request.Spec.SourceURL,
			image:          image,
			provider:       provider,
		}
	} else {
		tx = &createImageFromServerSaga{
			client:         c,
			organizationID: organizationID,
			regionID:       regionID,
			serverID:       *request.Spec.SourceServerID,
			image:          image,
			provider:       provider,
		}
	}

	if err = saga.Run(ctx, tx); err != nil {
		return nil, err
	}

	result, err := tx.Result()
	if err != nil {
		return nil, err
	}

	return fromProviderImage(result), nil
}

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

	temp, err := toProviderImageDiskFormat(*s.sourceFormat)
	if err != nil {
		return errors.OAuth2InvalidRequest("The provided disk format is not valid").WithError(err)
	}

	s.image.DiskFormat = temp

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

func (s *createImageForUploadSaga) createImageUploadTask(ctx context.Context) error {
	if s.sourceURL == nil {
		return nil
	}

	if s.result == nil {
		return errors.OAuth2ServerError("unexpected nil image")
	}

	imageUploadTask := &unikornv1.ImageUploadTask{
		ObjectMeta: metav1.ObjectMeta{
			Name:      util.GenerateResourceID(),
			Namespace: s.client.namespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel: s.organizationID,
				constants.RegionLabel:           s.regionID,
				constants.ImageLabel:            s.result.ID,
			},
		},
		Spec: unikornv1.ImageUploadTaskSpec{
			SourceURL: *s.sourceURL,
		},
		Status: unikornv1.ImageUploadTaskStatus{},
	}

	if err := common.SetIdentityMetadata(ctx, &imageUploadTask.ObjectMeta); err != nil {
		return errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	if err := s.client.client.Create(ctx, imageUploadTask); err != nil {
		return errors.OAuth2ServerError("failed to create image upload task").WithError(err)
	}

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

func (s *createImageFromServerSaga) createImageMonitorTask(ctx context.Context) error {
	if s.imageID == "" {
		return errors.OAuth2ServerError("unexpected empty image ID")
	}

	imageMonitorTask := &unikornv1.ImageMonitorTask{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.imageID,
			Namespace: s.client.namespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel: s.organizationID,
				constants.RegionLabel:           s.regionID,
				constants.ImageLabel:            s.imageID,
			},
		},
	}

	if err := common.SetIdentityMetadata(ctx, &imageMonitorTask.ObjectMeta); err != nil {
		return errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	if err := s.client.client.Create(ctx, imageMonitorTask); err != nil {
		return errors.OAuth2ServerError("failed to create image monitor task").WithError(err)
	}

	return nil
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

func (c *Client) UploadImage(ctx context.Context, organizationID, regionID, imageID string, r *http.Request) (*openapi.Image, error) {
	provider, err := c.Provider(ctx, regionID)
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

	return c.uploadImageFromFile(ctx, imageID, image.DiskFormat, r, provider)
}

func (c *Client) uploadImageFromFile(ctx context.Context, imageID string, diskFormat types.ImageDiskFormat, r *http.Request, provider types.Provider) (*openapi.Image, error) {
	multipartFile, _, err := r.FormFile("file")
	if err != nil {
		if goerrors.Is(err, http.ErrMissingFile) {
			return nil, errors.OAuth2InvalidRequest("No file provided for upload")
		}

		return nil, errors.OAuth2ServerError("The server encountered an unexpected error while reading the uploaded file").WithError(err)
	}
	defer multipartFile.Close()

	return UploadImageData(ctx, imageID, diskFormat, multipartFile, provider)
}

//nolint:cyclop,gocognit
func UploadImageData(ctx context.Context, imageID string, diskFormat types.ImageDiskFormat, sourceReader io.Reader, provider types.Provider) (*openapi.Image, error) {
	gzipReader, err := gzip.NewReader(sourceReader)
	if err != nil {
		return nil, errors.OAuth2InvalidRequest("The provided file is not a valid gzip file").WithError(err)
	}
	defer gzipReader.Close()

	tempFile, err := os.CreateTemp(os.TempDir(), "disk_")
	if err != nil {
		return nil, errors.OAuth2ServerError("The server encountered an unexpected error while processing the provided file").WithError(err)
	}
	defer tempFile.Close()

	defer func() {
		if err := os.Remove(tempFile.Name()); err != nil {
			log.FromContext(ctx).Error(err, "failed to remove temporary disk image file", "file", tempFile.Name())
		}
	}()

	var (
		tarReader = tar.NewReader(gzipReader)
		diskCount = 0
	)

	for {
		header, err := tarReader.Next()
		if err != nil {
			if goerrors.Is(err, io.EOF) {
				break
			}

			if goerrors.Is(err, io.ErrUnexpectedEOF) || goerrors.Is(err, tar.ErrHeader) {
				return nil, errors.OAuth2InvalidRequest("The provided file is not a valid tar archive").WithError(err)
			}

			return nil, errors.OAuth2ServerError("The server encountered an unexpected error while reading the tar archive").WithError(err)
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		// REVIEW_ME: We are not cross-checking the disk format against the image that was created.
		// Doing so would require seeking the first few magic bytes, but tar.Reader does not support
		// seeking without additional copies. For simplicity, this check is skipped.
		//nolint:nestif
		if header.Name == "disk.raw" || header.Name == "disk.qcow2" {
			if diskCount++; diskCount > 1 {
				return nil, errors.OAuth2InvalidRequest("The provided file contains multiple disk images, only a single disk image is supported")
			}

			contextReader := NewContextReader(ctx, tarReader)

			var validatingReader io.Reader

			switch diskFormat {
			case types.ImageDiskFormatRaw:
				validatingReader, err = NewMasterBootRecordReader(contextReader)
			case types.ImageDiskFormatQCOW2:
				validatingReader, err = NewQCOW2Reader(contextReader)
			default:
				return nil, errors.OAuth2ServerError("The server encountered an unexpected error due to an unhandled disk format").WithValues("disk_format", diskFormat)
			}

			if err != nil {
				if goerrors.Is(err, ErrInvalidMasterBootRecord) || goerrors.Is(err, ErrInvalidQCOW2) {
					message := fmt.Sprintf("The provided disk image is not a valid %s image", diskFormat)
					return nil, errors.OAuth2InvalidRequest(message)
				}

				return nil, errors.OAuth2ServerError("The server encountered an unexpected error while validating the disk image").WithError(err)
			}

			if _, err = io.Copy(tempFile, validatingReader); err != nil {
				// REVIEW_ME: For simplicity, we will return a status code 500 for all errors here, even if the error is due to context/request cancellation.
				return nil, errors.OAuth2ServerError("The server encountered an unexpected error while extracting the disk image").WithError(err)
			}
		}
	}

	if diskCount == 0 {
		return nil, errors.OAuth2InvalidRequest("The provided file does not contain a valid disk image")
	}

	if _, err = tempFile.Seek(0, io.SeekStart); err != nil {
		return nil, errors.OAuth2ServerError("The server encountered an unexpected error while processing the provided file").WithError(err)
	}

	if err = provider.UploadImage(ctx, imageID, tempFile); err != nil {
		if goerrors.Is(err, types.ErrResourceNotFound) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		if goerrors.Is(err, types.ErrImageNotReadyForUpload) {
			return nil, errors.HTTPConflict().WithError(err)
		}

		return nil, errors.OAuth2ServerError("The server encountered an unexpected error while uploading the image data").WithError(err)
	}

	result, err := provider.PublishImage(ctx, imageID)
	if err != nil {
		return nil, errors.OAuth2ServerError("The server encountered an unexpected error while finalizing the image upload").WithError(err)
	}

	return fromProviderImage(result), nil
}

func (c *Client) DeleteImage(ctx context.Context, organizationID, regionID, imageID string) error {
	provider, err := c.Provider(ctx, regionID)
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
		// REVIEW_ME: Most deletion APIs ignore not found errors, but our other delete APIs return 404. To maintain consistency, we do the same here.
		if goerrors.Is(err, types.ErrResourceNotFound) {
			return errors.HTTPNotFound().WithError(err)
		}

		// FIXME: We should provide a better error description instead of using the default one defined in HTTPConflict function.
		// This means that the image is still being used by another resource.
		if goerrors.Is(err, types.ErrImageStillInUse) {
			return errors.HTTPConflict().WithError(err)
		}

		return errors.OAuth2ServerError("failed to delete image").WithError(err)
	}

	return nil
}

func (c *Client) ListExternalNetworks(ctx context.Context, regionID string) (openapi.ExternalNetworks, error) {
	provider, err := c.Provider(ctx, regionID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	result, err := provider.ListExternalNetworks(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to list external networks").WithError(err)
	}

	return fromProviderExternalNetworks(result), nil
}
