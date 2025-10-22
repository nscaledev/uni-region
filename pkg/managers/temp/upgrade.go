/*
Copyright 2025 the Unikorn Authors.

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

package temp

import (
	"context"
	"fmt"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

func getRegion(ctx context.Context, cli client.Client, resource metav1.Object) (*unikornv1.Region, error) {
	id, ok := resource.GetLabels()[constants.RegionLabel]
	if !ok {
		//nolint:err113
		return nil, fmt.Errorf("resource has no region label")
	}

	out := &unikornv1.Region{}

	if err := cli.Get(ctx, client.ObjectKey{Namespace: resource.GetNamespace(), Name: id}, out); err != nil {
		return nil, fmt.Errorf("%w: region %s does not exist", err, id)
	}

	return out, nil
}

func getIdentity(ctx context.Context, cli client.Client, resource metav1.Object) (*unikornv1.OpenstackIdentity, error) {
	id, ok := resource.GetLabels()[constants.IdentityLabel]
	if !ok {
		//nolint:err113
		return nil, fmt.Errorf("resource has no region label")
	}

	out := &unikornv1.OpenstackIdentity{}

	if err := cli.Get(ctx, client.ObjectKey{Namespace: resource.GetNamespace(), Name: id}, out); err != nil {
		return nil, fmt.Errorf("%w: identity %s does not exist", err, id)
	}

	return out, nil
}

func getProvider(ctx context.Context, cli client.Client, resource metav1.Object) (*gophercloud.ProviderClient, error) {
	region, err := getRegion(ctx, cli, resource)
	if err != nil {
		return nil, err
	}

	identity, err := getIdentity(ctx, cli, resource)
	if err != nil {
		return nil, err
	}

	options := gophercloud.AuthOptions{
		IdentityEndpoint: region.Spec.Openstack.Endpoint,
		UserID:           *identity.Spec.UserID,
		Password:         *identity.Spec.Password,
		TenantID:         *identity.Spec.ProjectID,
	}

	return openstack.AuthenticatedClient(ctx, options)
}

func GetNetworkClient(ctx context.Context, cli client.Client, resource metav1.Object) (*gophercloud.ServiceClient, error) {
	provider, err := getProvider(ctx, cli, resource)
	if err != nil {
		return nil, err
	}

	return openstack.NewNetworkV2(provider, gophercloud.EndpointOpts{})
}
