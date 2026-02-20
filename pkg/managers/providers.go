package managers

import (
	coremanager "github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/manager/options"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	"github.com/unikorn-cloud/region/pkg/providers"

	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// CreateWithProvidersFunc is like ProvisionerCreateFunc, but accepts a providers.Providers value as well. This is
// typical of the provisioners, since most of them use a provider to create and update things.
type CreateWithProvidersFunc func(coremanager.ControllerOptions, providers.Providers) provisioners.ManagerProvisioner

// ProvisionerFunc adapts between provisioners that need a providers.Providers, and the func type
// coremanager.ProvisionerCreateFunc as required in `coremanager.NewReconciler`. This lets us
// use the coremanager machinery, but supply a providers value to the provisioner.
func ProvisionerFunc(manager manager.Manager, opts *options.Options, create CreateWithProvidersFunc) coremanager.ProvisionerCreateFunc {
	providers := providers.New(manager.GetClient(), opts.Namespace)
	return func(opts coremanager.ControllerOptions) provisioners.ManagerProvisioner {
		return create(opts, providers)
	}
}
