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

package driver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
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
	Subject           string
	URL               string
	CACertificate     []byte
	ClientCertificate []byte
	ClientPrivateKey  []byte
}

var _ types.Driver = &Client{}

func New(ctx context.Context, cli client.Client, provisioner *unikornv1.FileStorageProvisioner) (*Client, error) {
	cm := &corev1.ConfigMap{}
	if err := cli.Get(ctx, client.ObjectKey{Namespace: provisioner.Spec.ConfigRef.Namespace, Name: provisioner.Spec.ConfigRef.Name}, cm); err != nil {
		return nil, err
	}

	options, err := options(ctx, cli, cm)
	if err != nil {
		return nil, err
	}

	nc, err := connectToNATS(options)
	if err != nil {
		return nil, err
	}

	return &Client{
		client:  cli,
		nc:      nc,
		options: options,
	}, nil
}

func connectToNATS(options *Options) (*nats.Conn, error) {
	u, err := url.Parse(options.URL)
	if err != nil {
		return nil, err
	}

	if u.Scheme == "tls" {
		tlsParser := func() (tls.Certificate, error) {
			return tls.X509KeyPair(options.ClientCertificate, options.ClientPrivateKey)
		}

		caParser := func() (*x509.CertPool, error) {
			pool := x509.NewCertPool()
			if ok := pool.AppendCertsFromPEM(options.CACertificate); !ok {
				return nil, fmt.Errorf("%w: failed to parse NATS client CA", ErrDriverConfig)
			}

			return pool, nil
		}

		tlsOption := nats.ClientTLSConfig(tlsParser, caParser)

		return nats.Connect(options.URL, tlsOption)
	}

	// Connect without TLS for non-secure connection
	return nats.Connect(options.URL)
}

func options(ctx context.Context, cli client.Client, cm *corev1.ConfigMap) (*Options, error) {
	required := func(key string) (string, error) {
		val, ok := cm.Data[key]
		if !ok || val == "" {
			return "", fmt.Errorf("%w: %s key missing", ErrDriverConfig, key)
		}

		return val, nil
	}

	subject, err := required(SubjectKey)
	if err != nil {
		return nil, err
	}

	url, err := required(URLKey)
	if err != nil {
		return nil, err
	}

	secretName, err := required(ClientSecretNameKey)
	if err != nil {
		return nil, err
	}

	secret := &corev1.Secret{}
	if err := cli.Get(ctx, client.ObjectKey{Namespace: cm.Namespace, Name: secretName}, secret); err != nil {
		return nil, err
	}

	ca, ok := secret.Data["ca.crt"]
	if !ok {
		return nil, fmt.Errorf("%w: missing ca.crt", ErrDriverConfig)
	}

	clientCert, ok := secret.Data["tls.crt"]
	if !ok {
		return nil, fmt.Errorf("%w: missing tls.crt", ErrDriverConfig)
	}

	clientKey, ok := secret.Data["tls.key"]
	if !ok {
		return nil, fmt.Errorf("%w: missing tls.key", ErrDriverConfig)
	}

	return &Options{
		Subject:           subject,
		URL:               url,
		CACertificate:     ca,
		ClientCertificate: clientCert,
		ClientPrivateKey:  clientKey,
	}, nil
}

func (p *Client) GetDetails(ctx context.Context, projectID string, fileStorageID string) (*types.FileStorageDetails, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("GET /file-storage/%s", fileStorageID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	req := &GetFileSystem{
		RemoteIdentifier: RemoteIdentifier{
			ProjectID: projectID,
			VolumeID:  fileStorageID,
		},
	}

	res, err := doRequest[GetFileSystemResponse](ctx, p.nc, p.subject("getfilesystem"), req)
	if err != nil {
		return nil, err
	}

	return convertGetFileSystemResponse(res), nil
}

func (p *Client) ListAttachments(ctx context.Context, projectID string, fileStorageID string) (*types.FileStorageAttachments, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("GET /file-storage/%s/attachments", fileStorageID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	req := &ListFileSystemMountTargets{
		RemoteIdentifier: RemoteIdentifier{
			ProjectID: projectID,
			VolumeID:  fileStorageID,
		},
	}

	res, err := doRequest[ListFileSystemMountTargetsResponse](ctx, p.nc, p.subject("listmounttargets"), req)
	if err != nil {
		return nil, err
	}

	return convertListFileSystemMountTargetsResponse(res), nil
}

func (p *Client) Create(ctx context.Context, projectID string, fileStorageID string, size int64, rootSquashEnabled bool) (*types.FileStorageDetails, error) {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("POST /file-storage/%s", fileStorageID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	req := &CreateFileSystem{
		RemoteIdentifier: RemoteIdentifier{
			ProjectID: projectID,
			VolumeID:  fileStorageID,
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

func (p *Client) Delete(ctx context.Context, projectID string, fileStorageID string, force bool) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("DELETE /file-storage/%s", fileStorageID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	req := &DeleteFileSystem{
		RemoteIdentifier: RemoteIdentifier{
			ProjectID: projectID,
			VolumeID:  fileStorageID,
		},
		Force: force,
	}

	_, err := doRequest[EmptyResponse](ctx, p.nc, p.subject("deletefilesystem"), req)

	return err
}

func (p *Client) AttachNetwork(ctx context.Context, projectID string, fileStorageID string, attachment *unikornv1.Attachment) error {
	if attachment.SegmentationID == nil || attachment.IPRange == nil {
		return fmt.Errorf("%w: missing segmentation ID or IP range", ErrInvalidAttachment)
	}

	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("POST /file-storage/%s/attachments/%d", fileStorageID, *attachment.SegmentationID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	req := &CreateMountTarget{
		RemoteIdentifier: RemoteIdentifier{
			ProjectID: projectID,
			VolumeID:  fileStorageID,
		},
		VlanID:  int64(*attachment.SegmentationID),
		StartIP: attachment.IPRange.Start.String(),
		EndIP:   attachment.IPRange.End.String(),
	}

	_, err := doRequest[EmptyResponse](ctx, p.nc, p.subject("createmounttarget"), req)

	return err
}

func (p *Client) DetachNetwork(ctx context.Context, projectID string, fileStorageID string, segmentationID int) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("DELETE /file-storage/%s/attachments/%d", fileStorageID, segmentationID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	req := &DeleteMountTarget{
		RemoteIdentifier: RemoteIdentifier{
			ProjectID: projectID,
			VolumeID:  fileStorageID,
		},
		VlanID: int64(segmentationID),
	}

	_, err := doRequest[EmptyResponse](ctx, p.nc, p.subject("deletemounttarget"), req)

	return err
}

func (p *Client) Resize(ctx context.Context, projectID string, fileStorageID string, size int64) error {
	tracer := otel.GetTracerProvider().Tracer(constants.Application)

	_, span := tracer.Start(ctx, fmt.Sprintf("PUT /file-storage/%s/size", fileStorageID), trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()

	req := &Resize{
		RemoteIdentifier: RemoteIdentifier{
			ProjectID: projectID,
			VolumeID:  fileStorageID,
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
