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
	"context"
	"encoding/base64"
	goerrors "errors"
	"fmt"

	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/providers/kubernetes"
	"github.com/unikorn-cloud/region/pkg/providers/openstack"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrResource is raised when a resource is in a bad state.
	ErrResource = goerrors.New("resource error")

	// ErrRegionNotFound is raised when a region doesn't exist.
	ErrRegionNotFound = goerrors.New("region doesn't exist")

	// ErrRegionProviderUnimplmented is raised when you haven't written
	// it yet!
	ErrRegionProviderUnimplmented = goerrors.New("region provider unimplmented")
)

type Client struct {
	client    client.Client
	namespace string
}

func NewClient(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

// list is a canonical lister function that allows filtering to be applied
// in one place e.g. health, ownership, etc.
func (c *Client) list(ctx context.Context) (*unikornv1.RegionList, error) {
	var regions unikornv1.RegionList

	if err := c.client.List(ctx, &regions, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, err
	}

	return &regions, nil
}

func findRegion(regions *unikornv1.RegionList, regionID string) (*unikornv1.Region, error) {
	for i := range regions.Items {
		if regions.Items[i].Name == regionID {
			return &regions.Items[i], nil
		}
	}

	return nil, ErrRegionNotFound
}

//nolint:gochecknoglobals
var cache = map[string]providers.Provider{}

func (c *Client) newProvider(ctx context.Context, region *unikornv1.Region) (providers.Provider, error) {
	switch region.Spec.Provider {
	case unikornv1.ProviderKubernetes:
		return kubernetes.New(ctx, c.client, region)
	case unikornv1.ProviderOpenstack:
		return openstack.New(ctx, c.client, region)
	}

	return nil, ErrRegionProviderUnimplmented
}

func (c *Client) Provider(ctx context.Context, regionID string) (providers.Provider, error) {
	regions, err := c.list(ctx)
	if err != nil {
		return nil, err
	}

	region, err := findRegion(regions, regionID)
	if err != nil {
		return nil, err
	}

	if provider, ok := cache[region.Name]; ok {
		return provider, nil
	}

	provider, err := c.newProvider(ctx, region)
	if err != nil {
		return nil, err
	}

	cache[region.Name] = provider

	return provider, nil
}

func convertRegionType(in unikornv1.Provider) openapi.RegionType {
	switch in {
	case unikornv1.ProviderKubernetes:
		return openapi.Kubernetes
	case unikornv1.ProviderOpenstack:
		return openapi.Openstack
	}

	return ""
}

func convert(in *unikornv1.Region) *openapi.RegionRead {
	out := &openapi.RegionRead{
		Metadata: conversion.ResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.RegionSpec{
			Type: convertRegionType(in.Spec.Provider),
		},
	}

	// Calculate any region specific configuration.
	if in.Spec.Provider == unikornv1.ProviderOpenstack {
		if in.Spec.Openstack.Network != nil && in.Spec.Openstack.Network.ProviderNetworks != nil {
			out.Spec.Features.PhysicalNetworks = true
		}
	}

	return out
}

func (c *Client) convertDetail(ctx context.Context, in *unikornv1.Region) (*openapi.RegionDetailRead, error) {
	out := &openapi.RegionDetailRead{
		Metadata: conversion.ResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.RegionDetailSpec{
			Type: convertRegionType(in.Spec.Provider),
		},
	}

	// Calculate any region specific configuration.
	switch in.Spec.Provider {
	case unikornv1.ProviderKubernetes:
		secret := &corev1.Secret{}

		if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: in.Spec.Kubernetes.KubeconfigSecret.Name}, secret); err != nil {
			return nil, err
		}

		kubeconfig, ok := secret.Data["kubeconfig"]
		if !ok {
			return nil, fmt.Errorf("%w: kubeconfig kye missing in region secret", ErrResource)
		}

		out.Spec.Kubernetes = &openapi.RegionDetailKubernetes{
			Kubeconfig: base64.RawURLEncoding.EncodeToString(kubeconfig),
		}
	case unikornv1.ProviderOpenstack:
		if in.Spec.Openstack.Network != nil && in.Spec.Openstack.Network.ProviderNetworks != nil {
			out.Spec.Features.PhysicalNetworks = true
		}
	}

	return out, nil
}

func convertList(in *unikornv1.RegionList) openapi.Regions {
	out := make(openapi.Regions, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i])
	}

	return out
}

func (c *Client) List(ctx context.Context) (openapi.Regions, error) {
	regions, err := c.list(ctx)
	if err != nil {
		return nil, err
	}

	return convertList(regions), nil
}

func (c *Client) GetDetail(ctx context.Context, regionID string) (*openapi.RegionDetailRead, error) {
	result := &unikornv1.Region{}

	fmt.Println("getting region", c.namespace, regionID)

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: regionID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to lookup region").WithError(err)
	}

	return c.convertDetail(ctx, result)
}
