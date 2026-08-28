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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/region/pkg/openapi"
)

func TestVolumeLifecycleContract(t *testing.T) {
	t.Parallel()

	swagger, err := openapi.GetSwagger()
	require.NoError(t, err)

	collection := swagger.Paths.Find("/api/v2/volumes")
	require.NotNil(t, collection)
	require.NotNil(t, collection.Get)
	require.NotNil(t, collection.Post)
	require.NotContains(t, collection.Get.Extensions, "x-hidden")
	require.NotContains(t, collection.Post.Extensions, "x-hidden")
	require.NotNil(t, collection.Post.Responses.Value("202"))
	require.Nil(t, collection.Post.Responses.Value("201"))

	resource := swagger.Paths.Find("/api/v2/volumes/{volumeID}")
	require.NotNil(t, resource)
	require.NotNil(t, resource.Get)
	require.NotNil(t, resource.Put)
	require.NotNil(t, resource.Delete)
	require.NotContains(t, resource.Get.Extensions, "x-hidden")
	require.NotContains(t, resource.Put.Extensions, "x-hidden")
	require.NotContains(t, resource.Delete.Extensions, "x-hidden")
	require.NotNil(t, resource.Put.Responses.Value("200"))
	require.NotNil(t, resource.Put.Responses.Value("409"))
	require.NotNil(t, resource.Delete.Responses.Value("202"))
	require.NotNil(t, resource.Delete.Responses.Value("409"))

	spec := componentSchema(t, swagger, "volumeV2Spec")
	require.ElementsMatch(t, []string{"networkId", "volumeClassId", "sizeGiB"}, spec.Required)
	networkID := schemaProperty(t, spec, "networkId")
	require.Len(t, networkID.AllOf, 1)
	require.Equal(t, "#/components/schemas/networkId", networkID.AllOf[0].Ref)

	requestedSize := schemaProperty(t, spec, "sizeGiB")
	require.True(t, requestedSize.Type.Is("integer"))
	require.Equal(t, "int64", requestedSize.Format)
	require.NotNil(t, requestedSize.Min)
	require.InDelta(t, 1, *requestedSize.Min, 0)

	update := componentSchema(t, swagger, "volumeV2Update")
	require.Equal(t, []string{"metadata"}, update.Required)
	require.Len(t, update.Properties, 1)
	require.Contains(t, update.Properties, "metadata")

	status := componentSchema(t, swagger, "volumeV2Status")
	require.Equal(t, []string{"regionId"}, status.Required)
	require.NotContains(t, status.Properties, "attachedServerIds")
	require.NotContains(t, status.Properties, "attachment")
	require.Contains(t, status.Properties, "sizeGiB")
	require.NotContains(t, status.Properties, "phase")
	require.NotContains(t, swagger.Components.Schemas, "volumeV2Phase")

	volumeID := componentSchema(t, swagger, "volumeId")
	require.Equal(t, "regionids.VolumeID", volumeID.Extensions["x-go-type"])
}

func TestServerVolumeAttachmentStatusContract(t *testing.T) {
	t.Parallel()

	swagger, err := openapi.GetSwagger()
	require.NoError(t, err)

	status := componentSchema(t, swagger, "serverV2VolumeStatus")
	require.ElementsMatch(t, []string{"id", "provisioningStatus"}, status.Required)
	require.Len(t, schemaProperty(t, status, "id").AllOf, 1)
	require.Equal(t, "#/components/schemas/volumeId", schemaProperty(t, status, "id").AllOf[0].Ref)
	requireSchemaPropertyRef(t, status, "provisioningStatus", "#/components/schemas/unikorn-cloud_core_v1.17.1_pkg_openapi_common_resourceProvisioningStatus")
	requireSchemaPropertyRef(t, componentSchema(t, swagger, "serverV2Status"), "volumes", "#/components/schemas/serverV2VolumeStatusList")
}
