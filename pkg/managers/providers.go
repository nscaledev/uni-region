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

package managers

import (
	"context"

	coremanager "github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/manager/options"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	"github.com/unikorn-cloud/region/pkg/providers"

	"sigs.k8s.io/controller-runtime/pkg/manager"
)

type ProvisionerCreateFunc func(coremanager.ControllerOptions, providers.Providers) provisioners.ManagerProvisioner

type ProvidersInit struct {
	Providers providers.Providers
}

// This is an optional interface, and it could fail invisibly;
// so here's a guard to make sure we're implementing the right thing.
var _ coremanager.ControllerInitializer = &ProvidersInit{}

func (f *ProvidersInit) Initialize(ctx context.Context, mgr manager.Manager, opts *options.Options) error {
	providers := providers.New(mgr.GetClient(), opts.Namespace)
	f.Providers = providers

	return nil
}

func (f *ProvidersInit) ProvisionerCreate(create ProvisionerCreateFunc) coremanager.ProvisionerCreateFunc {
	return func(opts coremanager.ControllerOptions) provisioners.ManagerProvisioner {
		return create(opts, f.Providers)
	}
}
