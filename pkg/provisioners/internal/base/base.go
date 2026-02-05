/*
Copyright 2025 the Unikorn Authors.
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

package base

import (
	"context"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

func GetIdentity(ctx context.Context, object client.Object) (*unikornv1.Identity, error) {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	identity := &unikornv1.Identity{}

	if err := cli.Get(ctx, client.ObjectKey{Namespace: object.GetNamespace(), Name: object.GetLabels()[constants.IdentityLabel]}, identity); err != nil {
		return nil, err
	}

	return identity, nil
}

func Provider(ctx context.Context, object client.Object) (types.Provider, error) {
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	return providers.New(cli, object.GetNamespace()).LookupCloud(ctx, object.GetLabels()[constants.RegionLabel])
}

func ProviderAndIdentity(ctx context.Context, object client.Object) (types.Provider, *unikornv1.Identity, error) {
	id, err := GetIdentity(ctx, object)
	if err != nil {
		return nil, nil, err
	}

	prov, err := Provider(ctx, object)

	return prov, id, err
}
