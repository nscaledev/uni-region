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

package agent

import (
	"context"
	"strings"

	"github.com/nats-io/nats.go"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/file-storage/provisioners/types"

	"k8s.io/apimachinery/pkg/api/resource"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Provisioner struct {
	// client is Kubernetes client.
	client client.Client

	// nc is the NATS connection.
	nc *nats.Conn

	// options are the Provisioner options.
	options *Options
}

type Options struct {
	Subject string
}

var _ types.Provisioner = &Provisioner{}

func New(ctx context.Context, cli client.Client, provisioner *unikornv1.FileStorageProvisioner) (*Provisioner, error) {
	nc, err := connectToNATS(provisioner)
	if err != nil {
		return nil, err
	}

	return &Provisioner{
		client: cli,
		nc:     nc,
	}, nil
}

func connectToNATS(_ *unikornv1.FileStorageProvisioner) (*nats.Conn, error) {
	// TODO: Implement proper NATS connection handling.
	// This (the whole agent provisioner) will be moved to a dedicated controller in the future,
	// reducing uni-region's dependency on NATS or any provisioner implementation.
	return nats.Connect(nats.DefaultURL)
}

func (p *Provisioner) GetDetails(ctx context.Context, fs *unikornv1.FileStorage) (*types.FileStorageDetails, error) {
	req := &GetFileSystem{
		RemoteIdentifier: RemoteIdentifier{
			ProjectID: fs.Labels[coreconstants.ProjectLabel],
			VolumeID:  fs.GetName(),
		},
	}

	res, err := doRequest[GetFileSystemResponse](ctx, p.nc, p.subject("getfilesystem"), req)
	if err != nil {
		return nil, err
	}

	return &types.FileStorageDetails{
		Size:              resource.NewQuantity(res.Size, resource.BinarySI),
		Path:              res.Path,
		RootSquashEnabled: res.RootSquashEnabled,
		UsedCapacity:      resource.NewQuantity(res.UsedCapacity, resource.BinarySI),
	}, nil
}

func (p *Provisioner) ListAttachments(ctx context.Context, fs *unikornv1.FileStorage, network *unikornv1.Network) (*types.FileStorageAttachments, error) {
	//nolint:nilnil
	return nil, nil
}

func (p *Provisioner) Create(ctx context.Context, fs *unikornv1.FileStorage) (*types.FileStorageDetails, error) {
	//nolint:nilnil
	return nil, nil
}

func (p *Provisioner) AttachNetwork(ctx context.Context, fs *unikornv1.FileStorage, network *unikornv1.Network) error {
	return nil
}

func (p *Provisioner) DetachNetwork(ctx context.Context, fs *unikornv1.FileStorage, network *unikornv1.Network) error {
	return nil
}

func (p *Provisioner) Resize(ctx context.Context, fs *unikornv1.FileStorage) error {
	return nil
}

// subject composes the base subject with the given suffix, ensuring a single dot separator.
func (p *Provisioner) subject(suffix string) string {
	base := strings.TrimSuffix(p.options.Subject, ".")
	if base == "" {
		return suffix
	}

	return base + "." + suffix
}
