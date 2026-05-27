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

package network

import (
	"context"

	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/provisioners/internal/base"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type staticIdentityClientFactory struct {
	client identityapi.ClientWithResponsesInterface
}

func (f staticIdentityClientFactory) ControllerClient(context.Context, client.Client, client.Object) (identityapi.ClientWithResponsesInterface, error) {
	return f.client, nil
}

// NewForTest constructs a Provisioner directly for unit tests, bypassing the
// CLI-options plumbing handled by New.
func NewForTest(network *unikornv1.Network, providers providers.Providers, identityClient identityapi.ClientWithResponsesInterface) *Provisioner {
	return &Provisioner{
		network: network,
		options: &Options{},
		WithIdentity: base.WithIdentity{
			Base: base.Base{
				Providers: providers,
			},
			IdentityClients: staticIdentityClientFactory{
				client: identityClient,
			},
		},
	}
}
