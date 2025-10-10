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

package client

import (
	"context"
	"net/http"
	"net/url"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/util"
	"github.com/unikorn-cloud/region/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// References allows references to be added and removed on identity
// resources from remote services.
type References struct {
	serviceDescriptor util.ServiceDescriptor
	serverOptions     *coreclient.HTTPOptions
	clientOptions     *coreclient.HTTPClientOptions
}

func NewReferences(serviceDescriptor util.ServiceDescriptor, serverOptions *coreclient.HTTPOptions, clientOptions *coreclient.HTTPClientOptions) *References {
	return &References{
		serviceDescriptor: serviceDescriptor,
		serverOptions:     serverOptions,
		clientOptions:     clientOptions,
	}
}

func (r *References) httpClient(ctx context.Context, client client.Client, resource client.Object) (openapi.ClientWithResponsesInterface, error) {
	return New(client, r.serverOptions, r.clientOptions).ControllerClient(ctx, resource)
}

func (r *References) AddReferenceToNetwork(ctx context.Context, networkID string, resource client.Object) error {
	client, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	httpClient, err := r.httpClient(ctx, client, resource)
	if err != nil {
		return err
	}

	reference, err := manager.GenerateResourceReference(client, resource)
	if err != nil {
		return err
	}

	response, err := httpClient.PutApiV2NetworksNetworkIDReferencesReferenceWithResponse(ctx, networkID, url.PathEscape(reference))
	if err != nil {
		return err
	}

	if response.StatusCode() != http.StatusCreated {
		return errors.PropagateError(response.HTTPResponse, response)
	}

	return nil
}

func (r *References) RemoveReferenceFromNetwork(ctx context.Context, networkID string, resource client.Object) error {
	client, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	httpClient, err := r.httpClient(ctx, client, resource)
	if err != nil {
		return err
	}

	reference, err := manager.GenerateResourceReference(client, resource)
	if err != nil {
		return err
	}

	response, err := httpClient.DeleteApiV2NetworksNetworkIDReferencesReferenceWithResponse(ctx, networkID, url.PathEscape(reference))
	if err != nil {
		return err
	}

	if response.StatusCode() != http.StatusNoContent {
		return errors.PropagateError(response.HTTPResponse, response)
	}

	return nil
}
