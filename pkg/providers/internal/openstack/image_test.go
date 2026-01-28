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

package openstack_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"

	"k8s.io/apimachinery/pkg/util/uuid"
)

const (
	osKernelProperty          = "unikorn:os:kernel"
	osFamilyProperty          = "unikorn:os:family"
	osDistroProperty          = "unikorn:os:distro"
	osVariantProperty         = "unikorn:os:variant"
	osCodenameProperty        = "unikorn:os:codename"
	osVersionProperty         = "unikorn:os:version"
	packageKubernetesProperty = "unikorn:package:kubernetes"
	packageSlurmdProperty     = "unikorn:package:slurmd"
	gpuVendorProperty         = "unikorn:gpu_vendor"
	gpuModelsProperty         = "unikorn:gpu_models"
	gpuDriverVersionProperty  = "unikorn:gpu_driver_version"
	virtualizationProperty    = "unikorn:virtualization"
	digestProperty            = "unikorn:digest"
	organizationIDProperty    = "unikorn:organization:id"

	osKernelLinux = "linux"

	osFamilyDebian = "debian"
	osFamilyRedhat = "redhat"

	osDistroUbuntu = "ubuntu"
	osDistroRocky  = "rocky"

	gpuVendorAMD    = "AMD"
	gpuVendorNVIDIA = "NVIDIA"

	virtualizationAny = "any"
)

type imageFixtureGenerator func() *images.Image
type imageFixtureMutator func(*images.Image)

func basicImageFixture() *images.Image {
	return &images.Image{
		Properties: map[string]any{
			osKernelProperty:       osKernelLinux,
			osFamilyProperty:       osFamilyDebian,
			osDistroProperty:       osDistroUbuntu,
			osCodenameProperty:     "Oracular Oriole",
			osVersionProperty:      "24.10",
			virtualizationProperty: virtualizationAny,
		},
	}
}

func imageFixtureWithID(id string) *images.Image {
	image := basicImageFixture()
	image.ID = id

	return image
}

func withOrganizationID(image *images.Image, organizationID string) *images.Image {
	image.Properties[organizationIDProperty] = organizationID

	return image
}

func signedBasicImageFixture(id string, signature string) imageFixtureGenerator {
	return func() *images.Image {
		image := imageFixtureWithID(id)
		image.Properties[digestProperty] = signature

		return image
	}
}

func gpuImageFixture() *images.Image {
	image := basicImageFixture()
	image.Properties[gpuVendorProperty] = gpuVendorNVIDIA
	image.Properties[gpuModelsProperty] = "H200"
	image.Properties[gpuDriverVersionProperty] = "Lewis Hamilton (Ferrari Edition)"

	return image
}

func removePropertyMutator(property string) imageFixtureMutator {
	return func(image *images.Image) {
		delete(image.Properties, property)
	}
}

func replacePropertyMutator(property string, value any) imageFixtureMutator {
	return func(image *images.Image) {
		image.Properties[property] = value
	}
}

func TestImageSchema(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		fixture imageFixtureGenerator
		mutator imageFixtureMutator
		valid   bool
	}{
		// Check the test actually works...
		{
			name:    "BasicImage",
			fixture: basicImageFixture,
			valid:   true,
		},
		// Check required things are actually required...
		{
			name:    "BasicImageNoKernel",
			fixture: basicImageFixture,
			mutator: removePropertyMutator(osKernelProperty),
		},
		{
			name:    "BasicImageNoFamily",
			fixture: basicImageFixture,
			mutator: removePropertyMutator(osFamilyProperty),
		},
		{
			name:    "BasicImageNoDistro",
			fixture: basicImageFixture,
			mutator: removePropertyMutator(osDistroProperty),
		},
		{
			name:    "BasicImageNoVersion",
			fixture: basicImageFixture,
			mutator: removePropertyMutator(osVersionProperty),
		},
		{
			name:    "BasicImageNoVirtualization",
			fixture: basicImageFixture,
			mutator: removePropertyMutator(virtualizationProperty),
		},
		// Check enumerations work...
		{
			name:    "BasicImageInvalidKernel",
			fixture: basicImageFixture,
			mutator: replacePropertyMutator(osKernelProperty, "darwin"),
		},
		{
			name:    "BasicImageInvalidFamily",
			fixture: basicImageFixture,
			mutator: replacePropertyMutator(osFamilyProperty, "gentoo"),
		},
		{
			name:    "BasicImageInvalidDistro",
			fixture: basicImageFixture,
			mutator: replacePropertyMutator(osDistroProperty, "mandriver"),
		},
		{
			name:    "BasicImageInvalidVirtualization",
			fixture: basicImageFixture,
			mutator: replacePropertyMutator(virtualizationProperty, "virtualised"),
		},
		// Check the type system works...
		{
			name:    "BasicImageInvalidVersionType",
			fixture: basicImageFixture,
			mutator: replacePropertyMutator(osVersionProperty, 18),
		},
		// Check the test works...
		{
			name:    "GPUImage",
			fixture: gpuImageFixture,
			valid:   true,
		},
		{
			name:    "GPUImageMultipleModels",
			fixture: gpuImageFixture,
			mutator: replacePropertyMutator(gpuModelsProperty, "A100,H100"),
			valid:   true,
		},
		// Check required things are actually required...
		{
			name:    "GPUImageNoModels",
			fixture: gpuImageFixture,
			mutator: removePropertyMutator(gpuModelsProperty),
		},
		{
			name:    "GPUImageNoDriverVersion",
			fixture: gpuImageFixture,
			mutator: removePropertyMutator(gpuDriverVersionProperty),
		},
		// Check enumerations work...
		{
			name:    "GPUImageInvalidVendor",
			fixture: gpuImageFixture,
			mutator: replacePropertyMutator(gpuVendorProperty, "Intel"),
		},
		// Check the type system works...
		{
			name:    "GPUImageInvalidModelsFormat",
			fixture: gpuImageFixture,
			mutator: replacePropertyMutator(gpuModelsProperty, "A100 H100"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			schema, err := openstack.ImageSchema()
			require.NoError(t, err)

			fixture := c.fixture()

			if c.mutator != nil {
				c.mutator(fixture)
			}

			require.Equal(t, c.valid, openstack.ImageSchemaValid(fixture, schema))
		})
	}
}

func TestImageSigning(t *testing.T) {
	t.Parallel()

	// If you know you know, if you don't, learn :D
	signingKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	publicKeyPKIX, err := x509.MarshalPKIXPublicKey(signingKey.Public())
	require.NoError(t, err)

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyPKIX,
	}

	publicKey := &bytes.Buffer{}

	require.NoError(t, pem.Encode(publicKey, pemBlock))

	id := string(uuid.NewUUID())

	digest := sha256.Sum256([]byte(id))

	signatureASN1, err := ecdsa.SignASN1(rand.Reader, signingKey, digest[:])
	require.NoError(t, err)

	signature := base64.StdEncoding.EncodeToString(signatureASN1)

	cases := []struct {
		name    string
		fixture imageFixtureGenerator
		mutator imageFixtureMutator
		valid   bool
	}{
		// Check the test actually works...
		{
			name:    "BasicImage",
			fixture: signedBasicImageFixture(id, signature),
			valid:   true,
		},
		// Check it does what it's meant to...
		{
			name:    "BasicImageInvalidID",
			fixture: signedBasicImageFixture(string(uuid.NewUUID()), signature),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			fixture := c.fixture()

			if c.mutator != nil {
				c.mutator(fixture)
			}

			require.Equal(t, c.valid, openstack.ImageSignatureValid(fixture, publicKey.Bytes()))
		})
	}
}
