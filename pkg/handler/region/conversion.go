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

package region

import (
	"encoding/base64"
	"fmt"

	coreconversion "github.com/unikorn-cloud/core/pkg/server/conversion"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	corev1 "k8s.io/api/core/v1"
)

func ConvertRegionType(in regionv1.Provider) openapi.RegionType {
	switch in {
	case regionv1.ProviderKubernetes:
		return openapi.RegionTypeKubernetes
	case regionv1.ProviderOpenstack:
		return openapi.RegionTypeOpenstack
	}

	return ""
}

func ConvertRegion(in *regionv1.Region) *openapi.RegionRead {
	out := &openapi.RegionRead{
		Metadata: coreconversion.ResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.RegionSpec{
			Type: ConvertRegionType(in.Spec.Provider),
		},
	}

	// Calculate any region specific configuration.
	if in.Spec.Provider == regionv1.ProviderOpenstack {
		if in.Spec.Openstack.Network != nil && in.Spec.Openstack.Network.ProviderNetworks != nil {
			out.Spec.Features.PhysicalNetworks = true
		}
	}

	return out
}

func ConvertRegionDetail(sourceRegion *regionv1.Region, sourceSecret *corev1.Secret) (*openapi.RegionDetailRead, error) {
	out := &openapi.RegionDetailRead{
		Metadata: coreconversion.ResourceReadMetadata(sourceRegion, sourceRegion.Spec.Tags),
		Spec: openapi.RegionDetailSpec{
			Type: ConvertRegionType(sourceRegion.Spec.Provider),
		},
	}

	// Calculate any region specific configuration.
	switch sourceRegion.Spec.Provider {
	case regionv1.ProviderKubernetes:
		if sourceSecret == nil {
			return nil, fmt.Errorf("%w: missing Kubernetes region secret", ErrInternal)
		}

		kubeconfig, ok := sourceSecret.Data["kubeconfig"]
		if !ok {
			return nil, fmt.Errorf("%w: missing key 'kubeconfig' in region secret", ErrInternal)
		}

		out.Spec.Kubernetes = &openapi.RegionDetailKubernetes{
			Kubeconfig: base64.RawURLEncoding.EncodeToString(kubeconfig),
		}

		if sourceRegion.Spec.Kubernetes.DomainName != "" {
			out.Spec.Kubernetes.DomainName = &sourceRegion.Spec.Kubernetes.DomainName
		}
	case regionv1.ProviderOpenstack:
		if sourceRegion.Spec.Openstack.Network != nil && sourceRegion.Spec.Openstack.Network.ProviderNetworks != nil {
			out.Spec.Features.PhysicalNetworks = true
		}
	}

	return out, nil
}

func ConvertRegions(in *regionv1.RegionList) openapi.Regions {
	out := make(openapi.Regions, len(in.Items))

	for i := range in.Items {
		out[i] = *ConvertRegion(&in.Items[i])
	}

	return out
}

func ConvertExternalNetwork(in types.ExternalNetwork) openapi.ExternalNetwork {
	out := openapi.ExternalNetwork{
		Id:   in.ID,
		Name: in.Name,
	}

	return out
}

func ConvertExternalNetworks(in types.ExternalNetworks) openapi.ExternalNetworks {
	out := make(openapi.ExternalNetworks, len(in))

	for i := range in {
		out[i] = ConvertExternalNetwork(in[i])
	}

	return out
}
