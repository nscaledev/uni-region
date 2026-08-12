/*
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

package openapi_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/region/pkg/openapi"
)

func TestVolumeClassListDoesNotDeclareNotFoundForRegionSelectors(t *testing.T) {
	t.Parallel()

	swagger, err := openapi.GetSwagger()
	require.NoError(t, err)

	path := swagger.Paths.Find("/api/v2/volumeclasses")
	require.NotNil(t, path)
	require.NotNil(t, path.Get)
	require.Nil(t, path.Get.Responses.Value("404"))
}

func TestVolumeClassMetadataUsesStaticResourceMetadata(t *testing.T) {
	t.Parallel()

	swagger, err := openapi.GetSwagger()
	require.NoError(t, err)

	resource := swagger.Components.Schemas["volumeClassV2Read"]
	require.NotNil(t, resource)
	require.NotNil(t, resource.Value)

	flavor := swagger.Components.Schemas["flavor"]
	require.NotNil(t, flavor)
	require.NotNil(t, flavor.Value)
	require.Equal(t, flavor.Value.Properties["metadata"].Ref, resource.Value.Properties["metadata"].Ref)
}

func TestVolumeClassCapacityBoundsAreOptionalPositiveInt64Values(t *testing.T) {
	t.Parallel()

	swagger, err := openapi.GetSwagger()
	require.NoError(t, err)

	spec := swagger.Components.Schemas["volumeClassV2Spec"]
	require.NotNil(t, spec)
	require.NotNil(t, spec.Value)

	for _, name := range []string{"minimumSizeGiB", "maximumSizeGiB"} {
		property := spec.Value.Properties[name]
		require.NotNilf(t, property, "%s is missing", name)
		require.NotNil(t, property.Value)
		require.True(t, property.Value.Type.Is("integer"))
		require.Equal(t, "int64", property.Value.Format)
		require.NotNil(t, property.Value.Min)
		require.InDelta(t, 1, *property.Value.Min, 0)
		require.False(t, slices.Contains(spec.Value.Required, name), "%s must remain optional", name)
	}
}

func TestVolumeClassSupportedFlavorIDsAreOptionalTypedAndUnique(t *testing.T) {
	t.Parallel()

	swagger, err := openapi.GetSwagger()
	require.NoError(t, err)

	spec := swagger.Components.Schemas["volumeClassV2Spec"]
	require.NotNil(t, spec)
	require.NotNil(t, spec.Value)

	property := spec.Value.Properties["supportedFlavorIds"]
	require.NotNil(t, property)
	require.NotNil(t, property.Value)
	require.True(t, property.Value.Type.Is("array"))
	require.True(t, property.Value.UniqueItems)
	require.NotNil(t, property.Value.Items)
	require.Equal(t, "#/components/schemas/flavorId", property.Value.Items.Ref)
	require.False(t, slices.Contains(spec.Value.Required, "supportedFlavorIds"))
}
