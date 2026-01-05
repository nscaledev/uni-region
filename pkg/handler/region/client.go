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

package region

import (
	"cmp"
	"context"
	goerrors "errors"
	"fmt"
	"slices"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/conversion"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var ErrInternal = goerrors.New("internal")

type GetProviderFunc func(ctx context.Context, c client.Client, namespace, regionID string) (Provider, error)

var _ Provider = (types.Provider)(nil)

type Provider interface {
	Flavors(ctx context.Context) (types.FlavorList, error)
	ListExternalNetworks(ctx context.Context) (types.ExternalNetworks, error)
}

func DefaultGetProvider(ctx context.Context, c client.Client, namespace, regionID string) (Provider, error) {
	return providers.New(ctx, c, namespace, regionID)
}

type Client struct {
	client      client.Client
	namespace   string
	getProvider GetProviderFunc
}

func NewClient(client client.Client, namespace string, getProvider GetProviderFunc) *Client {
	return &Client{
		client:      client,
		namespace:   namespace,
		getProvider: getProvider,
	}
}

func (c *Client) List(ctx context.Context) (openapi.Regions, error) {
	regions := &regionv1.RegionList{}

	if err := c.client.List(ctx, regions, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, err
	}

	return ConvertRegions(regions), nil
}

func (c *Client) GetDetail(ctx context.Context, regionID string) (*openapi.RegionDetailRead, error) {
	fmt.Println("getting region", c.namespace, regionID)

	objectKey := client.ObjectKey{
		Namespace: c.namespace,
		Name:      regionID,
	}

	var region regionv1.Region
	if err := c.client.Get(ctx, objectKey, &region); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to lookup region").WithError(err)
	}

	secret, err := c.getKubeconfigSecret(ctx, &region)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to retrieve kubeconfig secret").WithError(err)
	}

	return ConvertRegionDetail(&region, secret)
}

func (c *Client) getKubeconfigSecret(ctx context.Context, region *regionv1.Region) (*corev1.Secret, error) {
	if region.Spec.Provider != regionv1.ProviderKubernetes {
		//nolint:nilnil
		return nil, nil
	}

	if region.Spec.Kubernetes == nil || region.Spec.Kubernetes.KubeconfigSecret == nil {
		return nil, fmt.Errorf("%w: kubeconfig secret not defined for region", ErrInternal)
	}

	objectKey := client.ObjectKey{
		Namespace: c.namespace,
		Name:      region.Spec.Kubernetes.KubeconfigSecret.Name,
	}

	var secret corev1.Secret
	if err := c.client.Get(ctx, objectKey, &secret); err != nil {
		return nil, err
	}

	return &secret, nil
}

func (c *Client) ListFlavors(ctx context.Context, organizationID, regionID string) (openapi.Flavors, error) {
	provider, err := c.getProvider(ctx, c.client, c.namespace, regionID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	result, err := provider.Flavors(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to list flavors").WithError(err)
	}

	// Apply ordering guarantees, ascending order with GPUs taking precedence over
	// CPUs and memory.
	slices.SortStableFunc(result, func(a, b types.Flavor) int {
		if v := cmp.Compare(a.GPUCount(), b.GPUCount()); v != 0 {
			return v
		}

		if v := cmp.Compare(a.CPUs, b.CPUs); v != 0 {
			return v
		}

		return cmp.Compare(a.Memory.Value(), b.Memory.Value())
	})

	return conversion.ConvertFlavors(result), nil
}

func (c *Client) ListExternalNetworks(ctx context.Context, regionID string) (openapi.ExternalNetworks, error) {
	provider, err := c.getProvider(ctx, c.client, c.namespace, regionID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create region provider").WithError(err)
	}

	result, err := provider.ListExternalNetworks(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to list external networks").WithError(err)
	}

	return ConvertExternalNetworks(result), nil
}
