package types

import (
	"context"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

type Provisioner interface {
	GetDetails(ctx context.Context, fs *unikornv1.FileStorage) (*FileStorageDetails, error)
	ListAttachments(ctx context.Context, fs *unikornv1.FileStorage, network *unikornv1.Network) (*FileStorageAttachments, error)
	Create(ctx context.Context, fs *unikornv1.FileStorage) (*FileStorageDetails, error)
	AttachNetwork(ctx context.Context, fs *unikornv1.FileStorage, network *unikornv1.Network) error
	DetachNetwork(ctx context.Context, fs *unikornv1.FileStorage, network *unikornv1.Network) error
	Resize(ctx context.Context, fs *unikornv1.FileStorage) error
}
