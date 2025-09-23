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

package openstack_test

import (
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/region/pkg/providers/openstack"
)

// TestImageFiltering checks that when filtering images we only get those
// that are public or scoped to the organization.
func TestImageFiltering(t *testing.T) {
	t.Parallel()

	public1 := *imageFixtureWithID("foo")
	public2 := *imageFixtureWithID("foo")
	private1 := *withOrganizationID(imageFixtureWithID("felix"), "cats")
	private2 := *withOrganizationID(imageFixtureWithID("rover"), "dogs")

	images := []images.Image{
		public1,
		public2,
		private1,
		private2,
	}

	images = openstack.GetPublicOrOrganizationOwnedImages(images, "cats")
	require.Len(t, images, 3)
	require.Contains(t, images, public1)
	require.Contains(t, images, public2)
	require.Contains(t, images, private1)
	require.NotContains(t, images, private2)
}
