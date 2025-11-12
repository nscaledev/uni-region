package providers

import (
	"context"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

type Provider interface {
	CreateOrUpdateFileStorage(ctx context.Context, fs *unikornv1.FileStorage) error
	DeleteFileStorage(ctx context.Context, fs *unikornv1.FileStorage) error
}
