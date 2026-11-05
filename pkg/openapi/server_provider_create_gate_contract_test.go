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

// A server takes at most 16 provider-create gates, as the CRD does, so a
// longer list is a 400 rather than a failed write.
func TestServerProviderCreateGatesContract(t *testing.T) {
	t.Parallel()

	swagger, err := openapi.GetSwagger()
	require.NoError(t, err)

	gates := swagger.Components.Schemas["serverProviderCreateGates"]
	require.NotNil(t, gates)
	require.NotNil(t, gates.Value.MaxItems)
	require.EqualValues(t, 16, *gates.Value.MaxItems)
}

// A report whose outputs differ from those stored, or that brings outputs to
// a gate already True, is refused with 409, so the contract declares it for
// generated clients to handle.
func TestServerProviderCreateGateReportContract(t *testing.T) {
	t.Parallel()

	swagger, err := openapi.GetSwagger()
	require.NoError(t, err)

	gates := swagger.Paths.Find("/api/v2/servers/{serverID}/provider-create-gates")
	require.NotNil(t, gates)
	require.NotNil(t, gates.Post)

	for _, code := range []string{"204", "400", "409", "422"} {
		require.NotNil(t, gates.Post.Responses.Value(code), code)
	}
}
