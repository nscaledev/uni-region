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

//nolint:testpackage
package image

import (
	"testing"
	"time"

	"go.uber.org/mock/gomock"

	"github.com/unikorn-cloud/region/pkg/handler/image/mock"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/utils/ptr"
)

const (
	testImageID        = "b3796b32-57d3-40cf-b43e-d227c0c5a70b"
	testOrganizationID = "3d84f1f2-4a41-44d5-98ab-8b282d00abb9"
	testRegionID       = "test-region"
	testProjectID      = "test-project"
	testIdentityID     = "test-identity"
	testServerID       = "test-server"
	testNamespace      = "test-namespace"
)

// newTestProviderImage creates a test provider image with the given parameters.
// If organizationID is empty, it uses testOrganizationID as the default.
func newTestProviderImage(status types.ImageStatus) *types.Image {
	return &types.Image{
		ID:             testImageID,
		Name:           "test-image",
		OrganizationID: ptr.To(testOrganizationID),
		Created:        time.Date(2025, 10, 31, 12, 0, 0, 0, time.UTC),
		Modified:       time.Date(2025, 10, 31, 12, 0, 0, 0, time.UTC),
		SizeGiB:        25,
		Virtualization: types.Virtualized,
		DiskFormat:     types.ImageDiskFormatRaw,
		Status:         status,
	}
}

// newTestMockProvider creates a new mock provider with a gomock controller.
// The controller is automatically cleaned up when the test finishes.
func newTestMockProvider(t *testing.T) *mock.Mockprovider {
	t.Helper()

	mockController := gomock.NewController(t)
	t.Cleanup(mockController.Finish)

	return mock.NewMockprovider(mockController)
}
