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
	"bytes"
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/legacy"
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

// Withholding is its own operation, so a Region that predates it answers 404
// and the gate stays shut. It declares the conflict for a gate already
// satisfied, and the unprocessable content for one not configured.
func TestServerProviderCreateGateWithholdContract(t *testing.T) {
	t.Parallel()

	swagger, err := openapi.GetSwagger()
	require.NoError(t, err)

	withhold := swagger.Paths.Find("/api/v2/servers/{serverID}/provider-create-gates/withhold")
	require.NotNil(t, withhold)
	require.NotNil(t, withhold.Post)

	for _, code := range []string{"204", "400", "409", "422"} {
		require.NotNil(t, withhold.Post.Responses.Value(code), code)
	}
}

// A withhold report carries no outputs, which are published only by the
// report that satisfies a gate: the request validation refuses any field it
// does not define with a 400 rather than dropping it.
func TestServerProviderCreateGateWithholdRefusesOutputs(t *testing.T) {
	t.Parallel()

	swagger, err := openapi.GetSwagger()
	require.NoError(t, err)

	router, err := legacy.NewRouter(swagger)
	require.NoError(t, err)

	validate := func(body string) error {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
			"/api/v2/servers/9a8c6370-4065-4d4a-9da0-7678df40cd9d/provider-create-gates/withhold", bytes.NewBufferString(body))
		require.NoError(t, err)

		request.Header.Set("Content-Type", "application/json")

		route, pathParams, err := router.FindRoute(request)
		require.NoError(t, err)

		return openapi3filter.ValidateRequest(t.Context(), &openapi3filter.RequestValidationInput{
			Request:    request,
			PathParams: pathParams,
			Route:      route,
			Options: &openapi3filter.Options{
				AuthenticationFunc: openapi3filter.NoopAuthenticationFunc,
			},
		})
	}

	require.NoError(t, validate(`{"conditionType":"example.unikorn-cloud.org/pre-create-ready","reason":"PoolExhausted","message":"no partition key is free"}`))
	require.Error(t, validate(`{"conditionType":"example.unikorn-cloud.org/pre-create-ready","reason":"PoolExhausted","message":"no partition key is free","outputs":{"pkey":"0x0600"}}`))
	require.Error(t, validate(`{"conditionType":"example.unikorn-cloud.org/pre-create-ready","reason":"","message":"no partition key is free"}`))
}
