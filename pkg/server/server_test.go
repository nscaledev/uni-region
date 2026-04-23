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

package server

import (
	"context"
	"errors"
	"testing"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	openapimiddleware "github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type stubAuthorizer struct{}

func (a *stubAuthorizer) Authorize(_ *openapi3filter.AuthenticationInput) (*authorization.Info, error) {
	return &authorization.Info{}, nil
}

func (a *stubAuthorizer) GetACL(_ context.Context, _ string) (*identityopenapi.Acl, error) {
	return &identityopenapi.Acl{}, nil
}

func TestServer_Authorizer(t *testing.T) {
	t.Parallel()

	t.Run("uses configured constructor", func(t *testing.T) {
		t.Parallel()

		server := &Server{
			IdentityOptions: identityclient.NewOptions(),
		}

		var (
			called bool
			stub   = &stubAuthorizer{}
		)

		server.newAuthorizer = func(kubeClient client.Client, identityOptions *identityclient.Options, httpClientOptions *coreclient.HTTPClientOptions) (openapimiddleware.Authorizer, error) {
			called = true
			assert.Nil(t, kubeClient)
			assert.Same(t, server.IdentityOptions, identityOptions)
			assert.Same(t, &server.ClientOptions, httpClientOptions)

			return stub, nil
		}

		authorizer, err := server.authorizer(nil)
		require.NoError(t, err)
		assert.True(t, called)
		assert.Same(t, stub, authorizer)
	})

	t.Run("wraps constructor errors", func(t *testing.T) {
		t.Parallel()

		s := &Server{
			IdentityOptions: identityclient.NewOptions(),
		}

		expected := errors.New("boom")

		s.newAuthorizer = func(_ client.Client, _ *identityclient.Options, _ *coreclient.HTTPClientOptions) (openapimiddleware.Authorizer, error) {
			return nil, expected
		}

		_, err := s.authorizer(nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, expected)
		assert.Contains(t, err.Error(), "failed to initialize API authorizer")
	})
}
