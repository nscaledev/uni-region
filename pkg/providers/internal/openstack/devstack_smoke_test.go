//go:build devstack

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
	"os"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
)

func devstackProvider(t *testing.T) *gophercloud.ProviderClient {
	t.Helper()

	if os.Getenv("OS_AUTH_URL") == "" {
		t.Fatal("OS_AUTH_URL must be set; source the DevStack OpenStack environment before running devstack tests")
	}

	opts, err := openstack.AuthOptionsFromEnv()
	if err != nil {
		t.Fatalf("failed to build OpenStack auth options from environment: %v", err)
	}

	provider, err := openstack.AuthenticatedClient(t.Context(), opts)
	if err != nil {
		t.Fatalf("failed to authenticate with OpenStack: %v", err)
	}

	return provider
}

func TestDevstackSmoke_ListImages(t *testing.T) {
	t.Logf("OS_AUTH_URL=%q OS_REGION_NAME=%q", os.Getenv("OS_AUTH_URL"), os.Getenv("OS_REGION_NAME"))

	provider := devstackProvider(t)

	imageClient, err := openstack.NewImageV2(provider, gophercloud.EndpointOpts{Region: os.Getenv("OS_REGION_NAME")})
	if err != nil {
		t.Fatalf("failed to create OpenStack image client: %v", err)
	}

	pages, err := images.List(imageClient, nil).AllPages(t.Context())
	if err != nil {
		t.Fatalf("failed to list OpenStack images: %v", err)
	}

	allImages, err := images.ExtractImages(pages)
	if err != nil {
		t.Fatalf("failed to extract OpenStack images: %v", err)
	}

	if len(allImages) == 0 {
		t.Fatal("expected DevStack to expose at least one image")
	}
}

func TestDevstackSmoke_ListFlavors(t *testing.T) {
	t.Logf("OS_AUTH_URL=%q OS_REGION_NAME=%q", os.Getenv("OS_AUTH_URL"), os.Getenv("OS_REGION_NAME"))

	provider := devstackProvider(t)

	computeClient, err := openstack.NewComputeV2(provider, gophercloud.EndpointOpts{Region: os.Getenv("OS_REGION_NAME")})
	if err != nil {
		t.Fatalf("failed to create OpenStack compute client: %v", err)
	}

	pages, err := flavors.ListDetail(computeClient, nil).AllPages(t.Context())
	if err != nil {
		t.Fatalf("failed to list OpenStack flavors: %v", err)
	}

	allFlavors, err := flavors.ExtractFlavors(pages)
	if err != nil {
		t.Fatalf("failed to extract OpenStack flavors: %v", err)
	}

	if len(allFlavors) == 0 {
		t.Fatal("expected DevStack to expose at least one flavor")
	}
}
