/*
Copyright 2026 the Unikorn Authors.

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

//nolint:testpackage
package region

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/util/testutil"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func RegionTypeKubernetes() *testutil.TypeConversion[regionv1.Provider, regionapi.RegionType] {
	return &testutil.TypeConversion[regionv1.Provider, regionapi.RegionType]{
		Source: regionv1.ProviderKubernetes,
		Target: regionapi.RegionTypeKubernetes,
	}
}

func RegionTypeOpenstack() *testutil.TypeConversion[regionv1.Provider, regionapi.RegionType] {
	return &testutil.TypeConversion[regionv1.Provider, regionapi.RegionType]{
		Source: regionv1.ProviderOpenstack,
		Target: regionapi.RegionTypeOpenstack,
	}
}

func TestConvertRegionType(t *testing.T) {
	t.Parallel()

	type TestCase struct {
		Name string
		Data *testutil.TypeConversion[regionv1.Provider, regionapi.RegionType]
	}

	testCases := []TestCase{
		{
			Name: "Kubernetes provider",
			Data: RegionTypeKubernetes(),
		},
		{
			Name: "OpenStack provider",
			Data: RegionTypeOpenstack(),
		},
		{
			Name: "unknown provider",
			Data: &testutil.TypeConversion[regionv1.Provider, regionapi.RegionType]{
				Source: "!@#$%^&*()-+",
				Target: "",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			regionType := ConvertRegionType(testCase.Data.Source)
			require.Equal(t, testCase.Data.Target, regionType)
		})
	}
}

// RegionNorway represents an OpenStack region without physical networks.
func RegionNorway() *testutil.TypeConversion[*regionv1.Region, *regionapi.RegionRead] {
	regionType := RegionTypeOpenstack()

	return &testutil.TypeConversion[*regionv1.Region, *regionapi.RegionRead]{
		Source: &regionv1.Region{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "e59060c5-84ee-4554-a5ab-a2ede10e6216",
				Namespace:         "unikorn-region",
				CreationTimestamp: metav1.Date(2025, 12, 30, 16, 0, 0, 0, time.UTC),
				Labels: map[string]string{
					"unikorn-cloud.org/name": "europe-west1",
				},
			},
			Spec: regionv1.RegionSpec{
				Tags: unikornv1.TagList{
					{
						Name:  "Country",
						Value: "Norway",
					},
				},
				Provider:  regionType.Source,
				Openstack: &regionv1.RegionOpenstackSpec{},
			},
		},
		Target: &regionapi.RegionRead{
			Metadata: coreapi.ResourceReadMetadata{
				CreationTime:       time.Date(2025, 12, 30, 16, 0, 0, 0, time.UTC),
				HealthStatus:       coreapi.ResourceHealthStatusHealthy,
				Id:                 "e59060c5-84ee-4554-a5ab-a2ede10e6216",
				Name:               "europe-west1",
				ProvisioningStatus: coreapi.ResourceProvisioningStatusProvisioned,
				Tags: &coreapi.TagList{
					{
						Name:  "Country",
						Value: "Norway",
					},
				},
			},
			Spec: regionapi.RegionSpec{
				Features: regionapi.RegionFeatures{
					PhysicalNetworks: false,
				},
				Type: regionType.Target,
			},
		},
	}
}

// RegionUnitedKingdom represents an OpenStack region with physical networks enabled.
func RegionUnitedKingdom() *testutil.TypeConversion[*regionv1.Region, *regionapi.RegionRead] {
	regionType := RegionTypeOpenstack()

	return &testutil.TypeConversion[*regionv1.Region, *regionapi.RegionRead]{
		Source: &regionv1.Region{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "60448c3d-bc08-4e9d-ab90-83f0b215fa74",
				Namespace:         "unikorn-region",
				CreationTimestamp: metav1.Date(2025, 12, 30, 17, 0, 0, 0, time.UTC),
				Labels: map[string]string{
					"unikorn-cloud.org/name": "europe-west2",
				},
			},
			Spec: regionv1.RegionSpec{
				Tags: unikornv1.TagList{
					{
						Name:  "Country",
						Value: "United Kingdom",
					},
				},
				Provider: regionType.Source,
				Openstack: &regionv1.RegionOpenstackSpec{
					Network: &regionv1.RegionOpenstackNetworkSpec{
						ProviderNetworks: &regionv1.ProviderNetworks{},
					},
				},
			},
		},
		Target: &regionapi.RegionRead{
			Metadata: coreapi.ResourceReadMetadata{
				CreationTime:       time.Date(2025, 12, 30, 17, 0, 0, 0, time.UTC),
				HealthStatus:       coreapi.ResourceHealthStatusHealthy,
				Id:                 "60448c3d-bc08-4e9d-ab90-83f0b215fa74",
				Name:               "europe-west2",
				ProvisioningStatus: coreapi.ResourceProvisioningStatusProvisioned,
				Tags: &coreapi.TagList{
					{
						Name:  "Country",
						Value: "United Kingdom",
					},
				},
			},
			Spec: regionapi.RegionSpec{
				Features: regionapi.RegionFeatures{
					PhysicalNetworks: true,
				},
				Type: regionType.Target,
			},
		},
	}
}

// RegionSpain represents a Kubernetes region.
func RegionSpain() *testutil.TypeConversion[*regionv1.Region, *regionapi.RegionRead] {
	regionType := RegionTypeKubernetes()

	return &testutil.TypeConversion[*regionv1.Region, *regionapi.RegionRead]{
		Source: &regionv1.Region{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "ebadadad-279e-44ee-bd79-8092933f1098",
				Namespace:         "unikorn-region",
				CreationTimestamp: metav1.Date(2025, 12, 30, 18, 0, 0, 0, time.UTC),
				Labels: map[string]string{
					"unikorn-cloud.org/name": "europe-west3",
				},
			},
			Spec: regionv1.RegionSpec{
				Tags: unikornv1.TagList{
					{
						Name:  "Country",
						Value: "Spain",
					},
				},
				Provider: regionType.Source,
			},
		},
		Target: &regionapi.RegionRead{
			Metadata: coreapi.ResourceReadMetadata{
				CreationTime:       time.Date(2025, 12, 30, 18, 0, 0, 0, time.UTC),
				HealthStatus:       coreapi.ResourceHealthStatusHealthy,
				Id:                 "ebadadad-279e-44ee-bd79-8092933f1098",
				Name:               "europe-west3",
				ProvisioningStatus: coreapi.ResourceProvisioningStatusProvisioned,
				Tags: &coreapi.TagList{
					{
						Name:  "Country",
						Value: "Spain",
					},
				},
			},
			Spec: regionapi.RegionSpec{
				Features: regionapi.RegionFeatures{
					PhysicalNetworks: false,
				},
				Type: regionType.Target,
			},
		},
	}
}

func TestConvertRegion(t *testing.T) {
	t.Parallel()

	type TestCase struct {
		Name string
		Data *testutil.TypeConversion[*regionv1.Region, *regionapi.RegionRead]
	}

	testCases := []TestCase{
		{
			Name: "Kubernetes region",
			Data: RegionSpain(),
		},
		{
			Name: "OpenStack region without physical networks",
			Data: RegionNorway(),
		},
		{
			Name: "OpenStack region with physical networks",
			Data: RegionUnitedKingdom(),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			region := ConvertRegion(testCase.Data.Source)
			require.Equal(t, testCase.Data.Target, region)
		})
	}
}

func nonZeroPointer[T comparable](value T) *T {
	var zero T
	if value == zero {
		return nil
	}

	return &value
}

func RegionDetailSpain(domainName, kubeconfig string) *testutil.TypeConversion[*testutil.T2[*regionv1.Region, *corev1.Secret], *regionapi.RegionDetailRead] {
	region := RegionSpain()

	region.Source.Spec.Kubernetes = &regionv1.RegionKubernetesSpec{
		DomainName: domainName,
	}

	kubeconfigBytes := []byte(kubeconfig)

	return &testutil.TypeConversion[*testutil.T2[*regionv1.Region, *corev1.Secret], *regionapi.RegionDetailRead]{
		Source: &testutil.T2[*regionv1.Region, *corev1.Secret]{
			A: region.Source,
			B: &corev1.Secret{
				Data: map[string][]byte{
					"kubeconfig": kubeconfigBytes,
				},
			},
		},
		Target: &regionapi.RegionDetailRead{
			Metadata: region.Target.Metadata,
			Spec: regionapi.RegionDetailSpec{
				Features: region.Target.Spec.Features,
				Kubernetes: &regionapi.RegionDetailKubernetes{
					DomainName: nonZeroPointer(domainName),
					Kubeconfig: base64.RawURLEncoding.EncodeToString(kubeconfigBytes),
				},
				Type: region.Target.Spec.Type,
			},
		},
	}
}

func TestConvertRegionDetail(t *testing.T) {
	t.Parallel()

	type TestCase struct {
		Name        string
		Data        *testutil.TypeConversion[*testutil.T2[*regionv1.Region, *corev1.Secret], *regionapi.RegionDetailRead]
		ExpectError bool
	}

	testCases := []TestCase{
		{
			Name: "returns error when Kubernetes region secret is missing",
			Data: &testutil.TypeConversion[*testutil.T2[*regionv1.Region, *corev1.Secret], *regionapi.RegionDetailRead]{
				Source: &testutil.T2[*regionv1.Region, *corev1.Secret]{
					A: &regionv1.Region{
						Spec: regionv1.RegionSpec{
							Provider: regionv1.ProviderKubernetes,
						},
					},
					B: nil,
				},
				Target: nil,
			},
			ExpectError: true,
		},
		{
			Name: "returns error when Kubernetes region secret is missing kubeconfig key",
			Data: &testutil.TypeConversion[*testutil.T2[*regionv1.Region, *corev1.Secret], *regionapi.RegionDetailRead]{
				Source: &testutil.T2[*regionv1.Region, *corev1.Secret]{
					A: &regionv1.Region{
						Spec: regionv1.RegionSpec{
							Provider: regionv1.ProviderKubernetes,
						},
					},
					B: &corev1.Secret{
						Data: make(map[string][]byte),
					},
				},
				Target: nil,
			},
			ExpectError: true,
		},
		{
			Name:        "returns region detail when Kubernetes region and secret are valid #1",
			Data:        RegionDetailSpain("domain-name-placeholder-1", "kubeconfig-placeholder-1"),
			ExpectError: false,
		},
		{
			Name:        "returns region detail when Kubernetes region and secret are valid #2",
			Data:        RegionDetailSpain("", "kubeconfig-placeholder-2"),
			ExpectError: false,
		},
		{
			Name: "returns OpenStack region detail #1",
			Data: &testutil.TypeConversion[*testutil.T2[*regionv1.Region, *corev1.Secret], *regionapi.RegionDetailRead]{
				Source: &testutil.T2[*regionv1.Region, *corev1.Secret]{
					A: RegionNorway().Source,
					B: nil,
				},
				Target: &regionapi.RegionDetailRead{
					Metadata: RegionNorway().Target.Metadata,
					Spec: regionapi.RegionDetailSpec{
						Features: RegionNorway().Target.Spec.Features,
						Type:     RegionNorway().Target.Spec.Type,
					},
				},
			},
			ExpectError: false,
		},
		{
			Name: "returns OpenStack region detail #2",
			Data: &testutil.TypeConversion[*testutil.T2[*regionv1.Region, *corev1.Secret], *regionapi.RegionDetailRead]{
				Source: &testutil.T2[*regionv1.Region, *corev1.Secret]{
					A: RegionUnitedKingdom().Source,
					B: nil,
				},
				Target: &regionapi.RegionDetailRead{
					Metadata: RegionUnitedKingdom().Target.Metadata,
					Spec: regionapi.RegionDetailSpec{
						Features: RegionUnitedKingdom().Target.Spec.Features,
						Type:     RegionUnitedKingdom().Target.Spec.Type,
					},
				},
			},
			ExpectError: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			regionDetail, err := ConvertRegionDetail(testCase.Data.Source.A, testCase.Data.Source.B)
			require.Equal(t, testCase.ExpectError, err != nil)
			require.Equal(t, testCase.Data.Target, regionDetail)
		})
	}
}

func TestConvertRegions(t *testing.T) {
	t.Parallel()

	type TestCase struct {
		Name     string
		Input    *regionv1.RegionList
		Expected regionapi.Regions
	}

	testCases := []TestCase{
		{
			Name:     "#1",
			Input:    &regionv1.RegionList{},
			Expected: regionapi.Regions{},
		},
		{
			Name: "#2",
			Input: &regionv1.RegionList{
				Items: []regionv1.Region{
					*RegionNorway().Source,
				},
			},
			Expected: regionapi.Regions{
				*RegionNorway().Target,
			},
		},
		{
			Name: "#3",
			Input: &regionv1.RegionList{
				Items: []regionv1.Region{
					*RegionNorway().Source,
					*RegionUnitedKingdom().Source,
				},
			},
			Expected: regionapi.Regions{
				*RegionNorway().Target,
				*RegionUnitedKingdom().Target,
			},
		},
		{
			Name: "#4",
			Input: &regionv1.RegionList{
				Items: []regionv1.Region{
					*RegionNorway().Source,
					*RegionUnitedKingdom().Source,
					*RegionSpain().Source,
				},
			},
			Expected: regionapi.Regions{
				*RegionNorway().Target,
				*RegionUnitedKingdom().Target,
				*RegionSpain().Target,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			regions := ConvertRegions(testCase.Input)
			require.Equal(t, testCase.Expected, regions)
		})
	}
}

func ExternalNetworkA() *testutil.TypeConversion[*types.ExternalNetwork, *regionapi.ExternalNetwork] {
	return &testutil.TypeConversion[*types.ExternalNetwork, *regionapi.ExternalNetwork]{
		Source: &types.ExternalNetwork{
			ID:   "1647e3c2-3cd4-4796-8e97-e99900c91da0",
			Name: "external-network-a",
		},
		Target: &regionapi.ExternalNetwork{
			Id:   "1647e3c2-3cd4-4796-8e97-e99900c91da0",
			Name: "external-network-a",
		},
	}
}

func ExternalNetworkB() *testutil.TypeConversion[*types.ExternalNetwork, *regionapi.ExternalNetwork] {
	return &testutil.TypeConversion[*types.ExternalNetwork, *regionapi.ExternalNetwork]{
		Source: &types.ExternalNetwork{
			ID:   "ad3a6385-ea00-423c-9b3c-cdb1f7c36fa7",
			Name: "external-network-b",
		},
		Target: &regionapi.ExternalNetwork{
			Id:   "ad3a6385-ea00-423c-9b3c-cdb1f7c36fa7",
			Name: "external-network-b",
		},
	}
}

func ExternalNetworkC() *testutil.TypeConversion[*types.ExternalNetwork, *regionapi.ExternalNetwork] {
	return &testutil.TypeConversion[*types.ExternalNetwork, *regionapi.ExternalNetwork]{
		Source: &types.ExternalNetwork{
			ID:   "bbd4f3c1-5678-4abc-9def-1234567890ab",
			Name: "external-network-c",
		},
		Target: &regionapi.ExternalNetwork{
			Id:   "bbd4f3c1-5678-4abc-9def-1234567890ab",
			Name: "external-network-c",
		},
	}
}

func TestConvertExternalNetwork(t *testing.T) {
	t.Parallel()

	type TestCase struct {
		Name string
		Data *testutil.TypeConversion[*types.ExternalNetwork, *regionapi.ExternalNetwork]
	}

	testCases := []TestCase{
		{
			Name: "#1",
			Data: ExternalNetworkA(),
		},
		{
			Name: "#2",
			Data: ExternalNetworkB(),
		},
		{
			Name: "#3",
			Data: ExternalNetworkC(),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			network := ConvertExternalNetwork(*testCase.Data.Source)
			require.Equal(t, testCase.Data.Target, &network)
		})
	}
}

func TestConvertExternalNetworks(t *testing.T) {
	t.Parallel()

	type TestCase struct {
		Name     string
		Input    types.ExternalNetworks
		Expected regionapi.ExternalNetworks
	}

	testCases := []TestCase{
		{
			Name:     "#1",
			Input:    types.ExternalNetworks{},
			Expected: regionapi.ExternalNetworks{},
		},
		{
			Name: "#2",
			Input: types.ExternalNetworks{
				*ExternalNetworkA().Source,
			},
			Expected: regionapi.ExternalNetworks{
				*ExternalNetworkA().Target,
			},
		},
		{
			Name: "#3",
			Input: types.ExternalNetworks{
				*ExternalNetworkA().Source,
				*ExternalNetworkB().Source,
			},
			Expected: regionapi.ExternalNetworks{
				*ExternalNetworkA().Target,
				*ExternalNetworkB().Target,
			},
		},
		{
			Name: "#4",
			Input: types.ExternalNetworks{
				*ExternalNetworkA().Source,
				*ExternalNetworkB().Source,
				*ExternalNetworkC().Source,
			},
			Expected: regionapi.ExternalNetworks{
				*ExternalNetworkA().Target,
				*ExternalNetworkB().Target,
				*ExternalNetworkC().Target,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			networks := ConvertExternalNetworks(testCase.Input)
			require.Equal(t, testCase.Expected, networks)
		})
	}
}
