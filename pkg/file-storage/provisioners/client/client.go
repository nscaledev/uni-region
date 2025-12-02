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

package client

import (
	"context"
	"fmt"
	"strings"

	"github.com/nats-io/nats.go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/file-storage/provisioners/types"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Client struct {
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

var _ types.Client = &Client{}

func New(ctx context.Context, cli client.Client, provisioner *unikornv1.FileStorageProvisioner) (*Client, error) {
	configMap := &corev1.ConfigMap{}
	if err := cli.Get(ctx, client.ObjectKey{Namespace: provisioner.Spec.ConfigRef.Namespace, Name: provisioner.Spec.ConfigRef.Name}, configMap); err != nil {
		return nil, err
	}

	subject, ok := configMap.Data["nats_subject"]
	if !ok || subject == "" {
		return nil, fmt.Errorf("%w: nats_subject key missing in provisioner configmap", ErrProvisionerConfig)
	}

	nc, err := connectToNATS(provisioner)
	if err != nil {
		return nil, err
	}

	return &Client{
		client: cli,
		nc:     nc,
		options: &Options{
			Subject: subject,
		},
	}, nil
}

func connectToNATS(_ *unikornv1.FileStorageProvisioner) (*nats.Conn, error) {
	// TODO: Implement proper NATS connection handling.
	// This (the whole agent provisioner) will be moved to a dedicated controller in the future,
	// reducing uni-region's dependency on NATS or any provisioner implementation.
	return nats.Connect(nats.DefaultURL)
}

func (p *Client) GetDetails(ctx context.Context, id *types.ID) (*types.FileStorageDetails, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("GET /file-storage/%s", id.FileStorageID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	req := &GetFileSystem{
		RemoteIdentifier: RemoteIdentifier{
			ProjectID: id.ProjectID,
			VolumeID:  id.FileStorageID,
		},
	}

	res, err := doRequest[GetFileSystemResponse](ctx, p.nc, p.subject("getfilesystem"), req)
	if err != nil {
		return nil, err
	}

	return convertGetFileSystemResponse(res), nil
}

func (p *Client) ListAttachments(ctx context.Context, id *types.ID) (*types.FileStorageAttachments, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("GET /file-storage/%s/attachments", id.FileStorageID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	req := &ListFileSystemMountTargets{
		RemoteIdentifier: RemoteIdentifier{
			ProjectID: id.ProjectID,
			VolumeID:  id.FileStorageID,
		},
	}

	res, err := doRequest[ListFileSystemMountTargetsResponse](ctx, p.nc, p.subject("listmounttargets"), req)
	if err != nil {
		return nil, err
	}

	return convertListFileSystemMountTargetsResponse(res), nil
}

func (p *Client) Create(ctx context.Context, id *types.ID, size int64, rootSquashEnabled bool) (*types.FileStorageDetails, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("POST /file-storage/%s", id.FileStorageID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	req := &CreateFileSystem{
		RemoteIdentifier: RemoteIdentifier{
			ProjectID: id.ProjectID,
			VolumeID:  id.FileStorageID,
		},
		Size:              size,
		RootSquashEnabled: rootSquashEnabled,
	}

	res, err := doRequest[CreateFileSystemResponse](ctx, p.nc, p.subject("createfilesystem"), req)
	if err != nil {
		return nil, err
	}

	return &types.FileStorageDetails{
		Size:              resource.NewQuantity(size, resource.BinarySI),
		Path:              res.Path,
		RootSquashEnabled: rootSquashEnabled,
		UsedCapacity:      resource.NewQuantity(0, resource.BinarySI),
	}, nil
}

func (p *Client) Delete(ctx context.Context, id *types.ID, force bool) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("DELETE /file-storage/%s", id.FileStorageID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	req := &DeleteFileSystem{
		RemoteIdentifier: RemoteIdentifier{
			ProjectID: id.ProjectID,
			VolumeID:  id.FileStorageID,
		},
		Force: force,
	}

	_, err := doRequest[EmptyResponse](ctx, p.nc, p.subject("deletefilesystem"), req)

	return err
}

func (p *Client) AttachNetwork(ctx context.Context, id *types.ID, vlanID int, ipRange *types.IPRange) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("POST /file-storage/%s/attachments/%d", id.FileStorageID, vlanID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	req := &CreateMountTarget{
		RemoteIdentifier: RemoteIdentifier{
			ProjectID: id.ProjectID,
			VolumeID:  id.FileStorageID,
		},
		VlanID:  int64(vlanID),
		StartIP: ipRange.Start.String(),
		EndIP:   ipRange.End.String(),
	}

	_, err := doRequest[EmptyResponse](ctx, p.nc, p.subject("createmounttarget"), req)

	return err
}

func (p *Client) DetachNetwork(ctx context.Context, id *types.ID, vlanID int) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("DELETE /file-storage/%s/attachments/%d", id.FileStorageID, vlanID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	req := &DeleteMountTarget{
		RemoteIdentifier: RemoteIdentifier{
			ProjectID: id.ProjectID,
			VolumeID:  id.FileStorageID,
		},
		VlanID: int64(vlanID),
	}

	_, err := doRequest[EmptyResponse](ctx, p.nc, p.subject("deletemounttarget"), req)

	return err
}

func (p *Client) Resize(ctx context.Context, id *types.ID, size int64) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("PUT /file-storage/%s/size", id.FileStorageID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	req := &Resize{
		RemoteIdentifier: RemoteIdentifier{
			ProjectID: id.ProjectID,
			VolumeID:  id.FileStorageID,
		},
		Size: size,
	}

	_, err := doRequest[ResizeResponse](ctx, p.nc, p.subject("resizefilesystem"), req)

	return err
}

// subject composes the base subject with the given suffix, ensuring a single dot separator.
func (p *Client) subject(suffix string) string {
	base := strings.TrimSuffix(p.options.Subject, ".")
	if base == "" {
		return suffix
	}

	return base + "." + suffix
}
