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

package types

import (
	"context"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

//go:generate mockgen -source=interfaces.go -destination=mock/interfaces.go -package=mock

type Driver interface {
	Close()
	GetDetails(ctx context.Context, projectID string, fileStorageID string) (*FileStorageDetails, error)
	ListAttachments(ctx context.Context, projectID string, fileStorageID string) (*FileStorageAttachments, error)
	Create(ctx context.Context, projectID string, fileStorageID string, size int64, rootSquashEnabled bool) (*FileStorageDetails, error)
	Delete(ctx context.Context, projectID string, fileStorageID string, force bool) error
	AttachNetwork(ctx context.Context, projectID string, fileStorageID string, attachment *unikornv1.Attachment, networkPrefix *unikornv1core.IPv4Prefix) error
	DetachNetwork(ctx context.Context, projectID string, fileStorageID string, segmentationID int) error
	Resize(ctx context.Context, projectID string, fileStorageID string, size int64) error
	UpdateRootSquash(ctx context.Context, projectID string, fileStorageID string, rootSquashEnabled bool) error
}
