/*
Copyright 2022-2024 EscherCloud.
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

package openstack

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/imagedata"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"github.com/kaptinlin/jsonschema"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
)

var (
	// ErrPEMDecode is raised when the PEM decode failed for some reason.
	ErrPEMDecode = errors.New("PEM decode error")

	// ErrPEMType is raised when the encounter the wrong PEM type, e.g. PKCS#1.
	ErrPEMType = errors.New("PEM type unsupported")

	// ErrKeyType is raised when we encounter an unsupported key type.
	ErrKeyType = errors.New("key type unsupported")
)

// imagePropertySchemaV2 defines what consitutes a valid image e.g. contains all the
// required information to work correctly.  This is defined in:
// https://github.com/unikorn-cloud/specifications/blob/main/specifications/providers/openstack/flavors_and_images.md.
//
//go:embed v2.image.schema.json
var imagePropertySchemaV2 []byte

// ImageClient wraps the generic client because gophercloud is unsafe.
type ImageClient struct {
	client  *gophercloud.ServiceClient
	options *unikornv1.RegionOpenstackImageSpec
}

// NewImageClient provides a simple one-liner to start computing.
func NewImageClient(ctx context.Context, provider CredentialProvider, options *unikornv1.RegionOpenstackImageSpec) (*ImageClient, error) {
	providerClient, err := provider.Client(ctx)
	if err != nil {
		return nil, err
	}

	client, err := openstack.NewImageV2(providerClient, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}

	c := &ImageClient{
		client:  client,
		options: options,
	}

	return c, nil
}

func decodeSigningKey(signingKey []byte) (*ecdsa.PublicKey, error) {
	pemBlock, _ := pem.Decode(signingKey)
	if pemBlock == nil {
		return nil, ErrPEMDecode
	}

	if pemBlock.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%w: %s", ErrPEMType, pemBlock.Type)
	}

	key, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrKeyType
	}

	return ecKey, nil
}

func ImageSignatureValid(image *images.Image, signingKeyRaw []byte) bool {
	signatureRaw, ok := image.Properties["unikorn:digest"]
	if !ok {
		return false
	}

	signatureB64, ok := signatureRaw.(string)
	if !ok {
		return false
	}

	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false
	}

	hash := sha256.Sum256([]byte(image.ID))

	signingKey, err := decodeSigningKey(signingKeyRaw)
	if err != nil {
		return false
	}

	return ecdsa.VerifyASN1(signingKey, hash[:], signature)
}

// verifyImageSignature asserts the image is trustworthy for use with our goodselves.
func (c *ImageClient) verifyImageSignature(image *images.Image) bool {
	// We only verify images that are not tied to an organization.
	// Images that are tied to an organization are custom images, which will not be signed by us.
	organizationID, _ := image.Properties["unikorn:organization:id"].(string)
	if organizationID != "" {
		return true
	}

	if c.options == nil || c.options.Selector == nil || c.options.Selector.SigningKey == nil {
		return true
	}

	if image.Properties == nil {
		return false
	}

	return ImageSignatureValid(image, c.options.Selector.SigningKey)
}

func ImageSchemaValid(image *images.Image, schema *jsonschema.Schema) bool {
	return schema.Validate(image.Properties).Valid
}

// imageValid returns true when the image is active, matches the schema and optionally
// is signed by a trusted image building pipeline.
func (c *ImageClient) imageValid(image *images.Image, schema *jsonschema.Schema) bool {
	if !ImageSchemaValid(image, schema) {
		return false
	}

	if !c.verifyImageSignature(image) {
		return false
	}

	return true
}

func ImageSchema() (*jsonschema.Schema, error) {
	return jsonschema.NewCompiler().Compile(imagePropertySchemaV2)
}

// CreateImage creates a new image.
func (c *ImageClient) CreateImage(ctx context.Context, opts *images.CreateOpts) (*images.Image, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "POST /image/v2/images", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	return images.Create(ctx, c.client, opts).Extract()
}

func (c *ImageClient) UploadImageData(ctx context.Context, id string, reader io.Reader) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "PUT /image/v2/images/{image_id}/file", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	return imagedata.Upload(ctx, c.client, id, reader).ExtractErr()
}

func (c *ImageClient) UpdateImage(ctx context.Context, id string, opts images.UpdateOpts) (*images.Image, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "PATCH /image/v2/images/{image_id}", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	return images.Update(ctx, c.client, id, opts).Extract()
}

// ListImages returns a list of active images.
func (c *ImageClient) ListImages(ctx context.Context) ([]images.Image, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "GET /image/v2/images", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	schema, err := ImageSchema()
	if err != nil {
		return nil, err
	}

	opts := &images.ListOpts{
		Visibility: images.ImageVisibilityPublic,
		Status:     images.ImageStatusActive,
	}

	page, err := images.List(c.client, opts).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	result, err := images.ExtractImages(page)
	if err != nil {
		return nil, err
	}

	// Filter out images that aren't compatible.
	result = slices.DeleteFunc(result, func(image images.Image) bool {
		return !c.imageValid(&image, schema)
	})

	// Sort by age, the newest should have the fewest CVEs!
	slices.SortStableFunc(result, func(a, b images.Image) int {
		return a.CreatedAt.Compare(b.CreatedAt)
	})

	return result, nil
}

// GetImage retrieves a specific image by its ID and the image is not guaranteed to be active.
func (c *ImageClient) GetImage(ctx context.Context, id string) (*images.Image, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "GET /image/v2/images/{image_id}", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	schema, err := ImageSchema()
	if err != nil {
		return nil, err
	}

	result, err := images.Get(ctx, c.client, id).Extract()
	if err != nil {
		return nil, err
	}

	// REVIEW_ME: Ideally, we should move the image validation to the caller side.
	if !c.imageValid(result, schema) {
		// This mimics the error returned by the OpenStack when an image is not found,
		// allowing us to have consistent error handling over a single error type.
		err = gophercloud.ErrUnexpectedResponseCode{
			Method:   http.MethodGet,
			Expected: []int{http.StatusOK},
			Actual:   http.StatusNotFound,
		}

		return nil, err
	}

	return result, nil
}

func (c *ImageClient) DeleteImage(ctx context.Context, id string) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "DELETE /image/v2/images/{image_id}", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	return images.Delete(ctx, c.client, id).ExtractErr()
}
