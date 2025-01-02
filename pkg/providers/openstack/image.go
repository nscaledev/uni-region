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
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	"github.com/unikorn-cloud/core/pkg/util"
	"github.com/unikorn-cloud/core/pkg/util/cache"
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

// ImageClient wraps the generic client because gophercloud is unsafe.
type ImageClient struct {
	client     *gophercloud.ServiceClient
	options    *unikornv1.RegionOpenstackImageSpec
	imageCache *cache.TimeoutCache[[]images.Image]
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
		client:     client,
		options:    options,
		imageCache: cache.New[[]images.Image](time.Hour),
	}

	return c, nil
}

func (c *ImageClient) validateProperties(image *images.Image) bool {
	if c.options == nil || c.options.Selector == nil {
		return true
	}

	for _, r := range c.options.Selector.Properties {
		if !slices.Contains(util.Keys(image.Properties), r) {
			return false
		}
	}

	return true
}

func (c *ImageClient) decodeSigningKey() (*ecdsa.PublicKey, error) {
	pemBlock, _ := pem.Decode(c.options.Selector.SigningKey)
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

// verifyImage asserts the image is trustworthy for use with our goodselves.
func (c *ImageClient) verifyImage(image *images.Image) bool {
	if c.options == nil || c.options.Selector == nil || c.options.Selector.SigningKey == nil {
		return true
	}

	if image.Properties == nil {
		return false
	}

	// These will be digitally signed by Baski when created, so we only trust
	// those images.
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

	signingKey, err := c.decodeSigningKey()
	if err != nil {
		return false
	}

	return ecdsa.VerifyASN1(signingKey, hash[:], signature)
}

func (c *ImageClient) filterImage(image *images.Image) bool {
	if image.Status != "active" {
		return true
	}

	if !c.validateProperties(image) {
		return true
	}

	if !c.verifyImage(image) {
		return true
	}

	return false
}

// images does a memoized lookup of images.
func (c *ImageClient) images(ctx context.Context) ([]images.Image, error) {
	if result, ok := c.imageCache.Get(); ok {
		return result, nil
	}

	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, "GET /image/v2/images", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	opts := &images.ListOpts{
		Visibility: images.ImageVisibilityPublic,
	}

	page, err := images.List(c.client, opts).AllPages(ctx)
	if err != nil {
		return nil, err
	}

	result, err := images.ExtractImages(page)
	if err != nil {
		return nil, err
	}

	c.imageCache.Set(result)

	return result, nil
}

// Images returns a list of images.
func (c *ImageClient) Images(ctx context.Context) ([]images.Image, error) {
	result, err := c.images(ctx)
	if err != nil {
		return nil, err
	}

	// Filter out images that aren't compatible.
	result = slices.DeleteFunc(result, func(image images.Image) bool {
		return c.filterImage(&image)
	})

	// Sort by age, the newest should have the fewest CVEs!
	slices.SortStableFunc(result, func(a, b images.Image) int {
		return a.CreatedAt.Compare(b.CreatedAt)
	})

	return result, nil
}
