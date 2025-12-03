/*
Copyright 2024-2025 the Unikorn Authors.

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

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	filestorageprovisioners "github.com/unikorn-cloud/region/pkg/file-storage/provisioners"
	"github.com/unikorn-cloud/region/pkg/file-storage/provisioners/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Provisioner encapsulates control plane provisioning.
type Provisioner struct {
	provisioners.Metadata

	// fileStorage is the server we're provisioning.
	fileStorage *unikornv1.FileStorage
}

// New returns a new initialized provisioner object.
func New(_ manager.ControllerOptions) provisioners.ManagerProvisioner {
	return &Provisioner{
		fileStorage: &unikornv1.FileStorage{},
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

	if err := p.reconcileFileStorage(ctx, driver); err != nil {
		return err
	}

	if err := p.reconcileNetworkAttachments(ctx, driver); err != nil {
		return err
	}

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

	// all networks must be detached before deletion
	if err := p.detachNetworks(ctx, driver); err != nil {
		return err
	}

	if err := p.deleteFileStorage(ctx, driver); err != nil {
		return err
	}

	return nil
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

// ignoreNotFound ignores ErrNotFound errors.
func ignoreNotFound(err error) error {
	if errors.Is(err, types.ErrNotFound) {
		return nil
	}

	return err
}
