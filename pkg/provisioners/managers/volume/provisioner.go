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

package volume

import (
	"context"
	"errors"

	"github.com/spf13/pflag"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/provisioners/internal/base"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Options allows access to CLI options in the provisioner.
type Options struct {
	// identityOptions allow the identity host and CA to be set.
	identityOptions *identityclient.Options
	// clientOptions give access to client certificate information for controller-to-API calls.
	clientOptions coreclient.HTTPClientOptions
}

// AddFlags registers the Volume controller's downstream client options.
func (o *Options) AddFlags(f *pflag.FlagSet) {
	if o.identityOptions == nil {
		o.identityOptions = identityclient.NewOptions()
	}

	o.identityOptions.AddFlags(f)
	o.clientOptions.AddFlags(f)
}

// Provisioner reconciles provider-backed Volume lifecycle.
type Provisioner struct {
	provisioners.Metadata

	volume  *unikornv1.Volume
	options *Options

	base.WithIdentity
}

// New returns a new initialized Volume provisioner.
func New(options manager.ControllerOptions, providerSet providers.Providers) provisioners.ManagerProvisioner {
	o, _ := options.(*Options)

	return &Provisioner{
		volume:  &unikornv1.Volume{},
		options: o,
		WithIdentity: base.WithIdentity{
			Base: base.Base{
				Providers: providerSet,
			},
			IdentityClients: base.NewIdentityClientFactory(o.identityOptions, &o.clientOptions),
		},
	}
}

var _ provisioners.ManagerProvisioner = &Provisioner{}

// Object returns the Volume reconciled by this provisioner.
func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.volume
}

// Provision reconciles the desired provider Volume.
func (p *Provisioner) Provision(ctx context.Context) error {
	provider, identity, err := p.VolumeProviderAndIdentity(ctx, p.volume)
	if err != nil {
		return err
	}

	if err := manager.ResourceReady(ctx, identity); err != nil {
		return err
	}

	return provider.CreateVolume(ctx, identity, p.volume)
}

func (p *Provisioner) deletionIdentity(ctx context.Context) (*unikornv1.Identity, error) {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	key := client.ObjectKey{
		Namespace: p.volume.Namespace,
		Name:      p.volume.Labels[constants.IdentityLabel],
	}
	identity := &unikornv1.Identity{}

	if err := cli.Get(ctx, key, identity); err != nil {
		if !kerrors.IsNotFound(err) {
			return nil, err
		}

		// Finalizer ordering normally keeps Identity alive, but provider cleanup
		// only needs its stable namespace/name to prove an unrealized backing
		// identity is already absent.
		identity.ObjectMeta = metav1.ObjectMeta{
			Namespace: key.Namespace,
			Name:      key.Name,
		}
	}

	return identity, nil
}

func (p *Provisioner) deleteProviderVolume(ctx context.Context) error {
	provider, err := p.Providers.LookupVolume(p.volume.Labels[constants.RegionLabel])
	if err != nil {
		// Capability absence proves this controller could not have created a
		// provider volume. Treat it as already absent so allocation cleanup and
		// finalizer removal can converge; all other lookup errors remain retryable.
		if errors.Is(err, providers.ErrRegionWrongKind) {
			return nil
		}

		return err
	}

	identity, err := p.deletionIdentity(ctx)
	if err != nil {
		return err
	}

	// Provider cleanup is unconditional and idempotent. The provider owns
	// authoritative rediscovery and already-absent handling, so readiness and
	// best-effort status must never gate this call.
	return provider.DeleteVolume(ctx, identity, p.volume)
}

// Deprovision removes provider state before releasing any Identity allocation.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	if err := p.deleteProviderVolume(ctx); err != nil {
		return err
	}

	if p.volume.Annotations[coreconstants.AllocationAnnotation] == "" {
		return nil
	}

	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	api, err := p.IdentityClient(ctx, p.volume)
	if err != nil {
		return err
	}

	return identityclient.NewAllocations(cli, api).Delete(ctx, p.volume)
}
