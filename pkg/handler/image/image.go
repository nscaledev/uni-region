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

package image

import (
	"cmp"
	"context"
	goerrors "errors"
	"io"
	"net/http"
	"slices"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type GetProviderFunc func(context.Context, client.Client, string, string) (Provider, error)

type Client struct {
	common.ClientArgs
	getProvider GetProviderFunc
}

func DefaultGetProvider(ctx context.Context, c client.Client, namespace, regionID string) (Provider, error) {
	return providers.New(ctx, c, namespace, regionID)
}

func NewClient(clientArgs common.ClientArgs, getProvider GetProviderFunc) *Client {
	return &Client{
		ClientArgs:  clientArgs,
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
	return c.getProvider(ctx, c.Client, c.Namespace, regionID)
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

// readMBR reads the MBR from the image response.  If we got a 206 then we should
// have exactly 512 bytes, if not then we read exactly 512 bytes.
func readMBR(r *http.Response) ([]byte, error) {
	if r.StatusCode == http.StatusPartialContent {
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}

		if len(buf) != 512 {
			return nil, errors.OAuth2InvalidRequest("Unable to peek image header, incorrect response size for range")
		}

		return buf, nil
	}

	buf := make([]byte, 512)

	if _, err := io.ReadFull(r.Body, buf); err != nil {
		return nil, errors.HTTPUnprocessableContent("Unable to peek image header, response too small")
	}

	return buf, nil
}

// validateImage peeks at the image file header, and ensures it's a master boot record
// as this is all we support currently.  We must be careful here to shut down the client
// connection quickly if the server does not support the HTTP Range header as this can
// consume memory very quickly and OOM kill the service.
func validateImage(ctx context.Context, uri string) error {
	client := &http.Client{}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return err
	}

	// NOTE: this may or may not be listened to by the server...
	request.Header.Set("Range", "bytes=0-511")

	response, err := client.Do(request)
	if err != nil {
		return errors.HTTPUnprocessableContent("Image read failed, please ensure the URL is correct")
	}

	defer response.Body.Close()

	if response.StatusCode/100 != 2 {
		return errors.HTTPUnprocessableContent("Image read failed with an incorrect status code, please ensure the URL is correct")
	}

	mbr, err := readMBR(response)
	if err != nil {
		return err
	}

	if mbr[510] != 0x55 || mbr[511] != 0xaa {
		return errors.HTTPUnprocessableContent("Image does not contain a valid master boot record, ensure the image is in raw format")
	}

	return nil
}

func (c *Client) CreateImage(ctx context.Context, organizationID, regionID string, request *openapi.ImageCreateRequest) (*openapi.ImageResponse, error) {
	provider, err := c.provider(ctx, regionID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	if err := validateImage(ctx, request.Spec.Uri); err != nil {
		return nil, err
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
		Tags:           GenerateTags(request.Metadata.Tags),
		OrganizationID: ptr.To(organizationID),
		Architecture:   generateArchitecture(request.Spec.Architecture),
		Virtualization: generateImageVirtualization(request.Spec.Virtualization),
		GPU:            gpu,
		OS:             *generateImageOS(&request.Spec.Os),
		Packages:       packages,
	}

	result, err := provider.CreateImage(ctx, image, request.Spec.Uri)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create image").WithError(err)
	}

	return convertImage(result), nil
}

func (c *Client) DeleteImage(ctx context.Context, organizationID, regionID, imageID string) error {
	provider, err := c.provider(ctx, regionID)
	if err != nil {
		return errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	image, err := provider.GetImage(ctx, organizationID, imageID)
	if err != nil {
		if goerrors.Is(err, coreerrors.ErrResourceNotFound) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to get image").WithError(err)
	}

	if image.OrganizationID == nil || *image.OrganizationID != organizationID {
		return errors.HTTPNotFound()
	}

	if err = provider.DeleteImage(ctx, imageID); err != nil {
		// Most deletion APIs ignore not found errors, but our other delete APIs return 404. To maintain consistency, we do the same here.
		if goerrors.Is(err, coreerrors.ErrResourceNotFound) {
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
