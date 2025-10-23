package storage

import (
	"context"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

type Provisioner struct {
	provisioners.Metadata
	storage *unikornv1.FileStorage
}

func New(_ manager.ControllerOptions) provisioners.ManagerProvisioner {
	return &Provisioner{
		storage: &unikornv1.FileStorage{},
	}
}

var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.storage
}

func (p *Provisioner) Provision(ctx context.Context) error {
	return provisioners.ErrNotFound
}

func (p *Provisioner) Deprovision(ctx context.Context) error {
	return provisioners.ErrNotFound
}
