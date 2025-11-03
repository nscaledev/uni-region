/*
Copyright 2025 the Unikorn Authors.

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

package imagemonitortask

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/spf13/pflag"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coremanager "github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	regionclient "github.com/unikorn-cloud/region/pkg/client"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/region"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"
)

var ErrUnexpectedStatusCode = errors.New("unexpected status code")

type Options struct {
	// clientOptions are for generic TLS client options e.g. certificates.
	clientOptions coreclient.HTTPClientOptions

	// identityOptions are for a shared identity client.
	identityOptions *identityclient.Options

	// regionOptions are for a shared region client.
	regionOptions *regionclient.Options
}

func (o *Options) AddFlags(flags *pflag.FlagSet) {
	if o.identityOptions == nil {
		o.identityOptions = identityclient.NewOptions()
	}

	if o.regionOptions == nil {
		o.regionOptions = regionclient.NewOptions()
	}

	o.clientOptions.AddFlags(flags)
	o.identityOptions.AddFlags(flags)
	o.regionOptions.AddFlags(flags)
}

type Provisioner struct {
	provisioners.Metadata

	// imageMonitorTask is the image monitor task we're provisioning.
	imageMonitorTask *unikornv1.ImageMonitorTask

	// options are CLI options.
	options *Options
}

func New(options coremanager.ControllerOptions) provisioners.ManagerProvisioner {
	return &Provisioner{
		//nolint:forcetypeassert
		options: options.(*Options),
	}
}

var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.imageMonitorTask
}

func (p *Provisioner) getRegionClient(ctx context.Context) (regionapi.ClientWithResponsesInterface, error) {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	tokenIssuer := identityclient.NewTokenIssuer(cli, p.options.identityOptions, &p.options.clientOptions, constants.ServiceDescriptor())

	token, err := tokenIssuer.Issue(ctx)
	if err != nil {
		return nil, err
	}

	getter := regionclient.New(cli, p.options.regionOptions, &p.options.clientOptions)

	client, err := getter.ControllerClient(ctx, token, p.imageMonitorTask)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// Provision implements the Provision interface.
//
//nolint:cyclop
func (p *Provisioner) Provision(ctx context.Context) error {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	task := p.imageMonitorTask

	regionID := task.Labels[constants.RegionLabel]
	if regionID == "" {
		return fmt.Errorf("%w: %s", unikornv1core.ErrMissingLabel, constants.RegionLabel)
	}

	organizationID := task.Labels[coreconstants.OrganizationLabel]
	if organizationID == "" {
		return fmt.Errorf("%w: %s", unikornv1core.ErrMissingLabel, coreconstants.OrganizationLabel)
	}

	imageID := task.Labels[constants.ImageLabel]
	if imageID == "" {
		return fmt.Errorf("%w: %s", unikornv1core.ErrMissingLabel, constants.ImageLabel)
	}

	provider, err := region.NewClient(cli, task.Namespace).Provider(ctx, regionID)
	if err != nil {
		return err
	}

	image, err := provider.GetImage(ctx, organizationID, imageID)
	if err != nil && !errors.Is(err, types.ErrResourceNotFound) {
		return err
	}

	// The only remaining error is that the image was not found. In this case, the monitoring task will be stopped, as the image has likely been deleted.
	if err != nil || image.Status == types.ImageStatusReady || image.Status == types.ImageStatusFailed {
		regionClient, err := p.getRegionClient(ctx)
		if err != nil {
			return err
		}

		response, err := regionClient.DeleteApiV1OrganizationsOrganizationIDRegionsRegionIDCachesImagesWithResponse(ctx, organizationID, regionID)
		if err != nil {
			return err
		}

		if response.StatusCode() != http.StatusNoContent {
			return fmt.Errorf("%w %d when invalidating image cache", ErrUnexpectedStatusCode, response.StatusCode())
		}

		return cli.Delete(ctx, task)
	}

	return provisioners.ErrYield
}

// Deprovision implements the Provision interface.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	return nil
}
