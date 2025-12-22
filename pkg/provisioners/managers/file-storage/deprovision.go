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

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/file-storage/provisioners/types"
)

func (p *Provisioner) detachNetworks(ctx context.Context, driver types.Driver) error {
	attachments, err := driver.ListAttachments(ctx, p.fileStorage.Labels[coreconstants.ProjectLabel], p.fileStorage.Name)
	if err != nil {
		// ErrNotFound means there are no attachments; nothing to do.
		if errors.Is(err, types.ErrNotFound) {
			return nil
		}

		return err
	}

	for _, att := range attachments.Items {
		if err := driver.DetachNetwork(ctx, p.fileStorage.Labels[coreconstants.ProjectLabel], p.fileStorage.Name, att.VlanID); err != nil {
			return err
		}
	}

	return nil
}

func (p *Provisioner) deleteFileStorage(ctx context.Context, driver types.Driver) error {
	if err := driver.Delete(ctx, p.fileStorage.Labels[coreconstants.ProjectLabel], p.fileStorage.Name, true); err != nil {
		// nothing to do.
		if errors.Is(err, types.ErrNotFound) {
			return nil
		}

		return err
	}

	return nil
}
