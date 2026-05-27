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

package base

import (
	"context"
	"fmt"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// IdentityClientFactory constructs controller-scoped identity service clients.
type IdentityClientFactory interface {
	ControllerClient(ctx context.Context, cli client.Client, resource client.Object) (identityapi.ClientWithResponsesInterface, error)
}

type defaultIdentityClientFactory struct {
	identityOptions *identityclient.Options
	clientOptions   *coreclient.HTTPClientOptions
}

// NewIdentityClientFactory creates the default identity service client factory.
func NewIdentityClientFactory(identityOptions *identityclient.Options, clientOptions *coreclient.HTTPClientOptions) IdentityClientFactory {
	return defaultIdentityClientFactory{
		identityOptions: identityOptions,
		clientOptions:   clientOptions,
	}
}

func (f defaultIdentityClientFactory) ControllerClient(ctx context.Context, cli client.Client, resource client.Object) (identityapi.ClientWithResponsesInterface, error) {
	return identityclient.New(cli, f.identityOptions, f.clientOptions).ControllerClient(ctx, resource)
}

// WithIdentity extends Base with access to the identity service API.
type WithIdentity struct {
	Base

	IdentityClients IdentityClientFactory
}

// IdentityClient returns an identity service client scoped to the reconciled resource.
func (b *WithIdentity) IdentityClient(ctx context.Context, resource client.Object) (identityapi.ClientWithResponsesInterface, error) {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	if b.IdentityClients == nil {
		return nil, fmt.Errorf("%w: identity client factory not configured", coreerrors.ErrConsistency)
	}

	return b.IdentityClients.ControllerClient(ctx, cli, resource)
}
