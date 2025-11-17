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

package provisioners

import (
	"context"
	"errors"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/file-storage/provisioners/agent"
	"github.com/unikorn-cloud/region/pkg/file-storage/provisioners/types"

	kerrors "k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrProvisionerNotFound is returned when the requested file storage provisioner is not implemented.
	ErrProvisionerNotFound = errors.New("file storage provisioner not found")
)

func New(ctx context.Context, c client.Client, namespace string, fileStorageClass *unikornv1.FileStorageClass) (types.Provisioner, error) {
	var provisioner unikornv1.FileStorageProvisioner

	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: fileStorageClass.Spec.Provisioner}, &provisioner); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, ErrProvisionerNotFound
		}

		return nil, err
	}

	return agent.New(ctx, c, &provisioner)
}
