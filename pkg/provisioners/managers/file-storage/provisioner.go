/*
Copyright 2024-2025 the Unikorn Authors.
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

package filestorage

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/pflag"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	filestorageprovisioners "github.com/unikorn-cloud/region/pkg/file-storage/provisioners"
	"github.com/unikorn-cloud/region/pkg/file-storage/provisioners/types"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Options allows access to CLI options in the provisioner.
type Options struct {
	// identityOptions allow the identity host and CA to be set.
	identityOptions *identityclient.Options
	// clientOptions give access to client certificate information as
	// we need to talk to identity to get a token, and then to delete
	// the allocation.
	clientOptions coreclient.HTTPClientOptions
}

func (o *Options) AddFlags(f *pflag.FlagSet) {
	if o.identityOptions == nil {
		o.identityOptions = identityclient.NewOptions()
	}

	o.identityOptions.AddFlags(f)
	o.clientOptions.AddFlags(f)
}

// Provisioner encapsulates control plane provisioning.
type Provisioner struct {
	provisioners.Metadata

	// fileStorage is the server we're provisioning.
	fileStorage *unikornv1.FileStorage

	// options are documented for the type.
	options *Options
}

// New returns a new initialized provisioner object.
func New(options manager.ControllerOptions) provisioners.ManagerProvisioner {
	o, _ := options.(*Options)

	return &Provisioner{
		fileStorage: &unikornv1.FileStorage{},
		options:     o,
	}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.fileStorage
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	driver, err := p.getFileStorageDriver(ctx, cli)
	if err != nil {
		return err
	}
	defer driver.Close()

	reference, err := manager.GenerateResourceReference(cli, p.fileStorage)
	if err != nil {
		return err
	}

	if err := p.reconcileFileStorage(ctx, driver); err != nil {
		return err
	}

	if err := p.reconcileNetworkAttachments(ctx, cli, driver, reference); err != nil {
		return err
	}

	// updates this field with the current value of .metadata.generation once it has successfully observed and
	// reconciled the corresponding changes to the resource.
	p.fileStorage.Status.ObservedGeneration = ptr.To(p.fileStorage.GetGeneration())

	return nil
}

// Deprovision implements the Deprovision interface.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	driver, err := p.getFileStorageDriver(ctx, cli)
	if err != nil {
		return err
	}
	defer driver.Close()

	// all networks must be detached before deletion
	if err := p.detachNetworks(ctx, driver); err != nil {
		return err
	}

	if err := p.deleteFileStorage(ctx, driver); err != nil {
		return err
	}

	// Once we know the file storage is gone, remove references to allow deletion of the network.
	reference, err := manager.GenerateResourceReference(cli, p.fileStorage)
	if err != nil {
		return err
	}

	if err := manager.ClearResourceReferences(ctx, cli, &unikornv1.NetworkList{}, p.filestorageListOptions(), reference); err != nil {
		return fmt.Errorf("%w: failed to clear network references", err)
	}

	// And finally remove the allocation
	api, err := p.identityClient(ctx)
	if err != nil {
		return err
	}

	if err := identityclient.NewAllocations(cli, api).Delete(ctx, p.fileStorage); err != nil {
		return err
	}

	return nil
}

func (p *Provisioner) identityClient(ctx context.Context) (identityapi.ClientWithResponsesInterface, error) {
	client, err := coreclient.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	return identityclient.New(client, p.options.identityOptions, &p.options.clientOptions).ControllerClient(ctx, p.fileStorage)
}

func (p *Provisioner) getFileStorageDriver(ctx context.Context, cli client.Client) (types.Driver, error) {
	storageClass := &unikornv1.FileStorageClass{}
	key := client.ObjectKey{
		Namespace: p.fileStorage.GetNamespace(),
		Name:      p.fileStorage.Spec.StorageClassID,
	}

	if err := cli.Get(ctx, key, storageClass); err != nil {
		return nil, err
	}

	return filestorageprovisioners.NewDriver(ctx, cli, p.fileStorage.GetNamespace(), storageClass)
}

// filestorageListOptions lists all resources associated with a filestorage.
func (p *Provisioner) filestorageListOptions() *client.ListOptions {
	selector := map[string]string{
		coreconstants.OrganizationLabel: p.fileStorage.Labels[coreconstants.OrganizationLabel],
		coreconstants.ProjectLabel:      p.fileStorage.Labels[coreconstants.ProjectLabel],
		constants.RegionLabel:           p.fileStorage.Labels[constants.RegionLabel],
	}

	return &client.ListOptions{
		Namespace:     p.fileStorage.Namespace,
		LabelSelector: labels.SelectorFromSet(selector),
	}
}

// ignoreNotFound ignores ErrNotFound errors.
func ignoreNotFound(err error) error {
	if errors.Is(err, types.ErrNotFound) {
		return nil
	}

	return err
}
