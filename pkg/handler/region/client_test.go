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
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/region/mock"
	"github.com/unikorn-cloud/region/pkg/handler/util/testutil"
	"github.com/unikorn-cloud/region/pkg/handler/util/unit"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	kubeclient "sigs.k8s.io/controller-runtime/pkg/client"
	kubefake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	kubeinterceptor "sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func setupTestKubeClientBuilder(t *testing.T) *kubefake.ClientBuilder {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))
	require.NoError(t, regionv1.AddToScheme(scheme))

	return kubefake.NewClientBuilder().WithScheme(scheme)
}

func normalizeResourceReadMetadata(metadata *coreapi.ResourceReadMetadata) {
	metadata.CreationTime = metadata.CreationTime.UTC()
}

func TestClient_List(t *testing.T) {
	t.Parallel()

	type TestCases struct {
		Name         string
		Interceptors *kubeinterceptor.Funcs
		ExpectError  bool
		Expected     regionapi.Regions
	}

	testCases := []TestCases{
		{
			Name: "returns error when list fails",
			Interceptors: &kubeinterceptor.Funcs{
				List: func(ctx context.Context, client kubeclient.WithWatch, list kubeclient.ObjectList, opts ...kubeclient.ListOption) error {
					return kerrors.NewInternalError(testutil.ErrMustFail)
				},
			},
			ExpectError: true,
			Expected:    nil,
		},
		{
			Name:        "returns regions when list succeeds",
			ExpectError: false,
			Expected: regionapi.Regions{
				*RegionNorway().Target,
				*RegionSpain().Target,
				*RegionUnitedKingdom().Target,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			kubeClientBuilder := setupTestKubeClientBuilder(t).
				WithObjects(
					RegionNorway().Source,
					RegionUnitedKingdom().Source,
					RegionSpain().Source,
				)

			if testCase.Interceptors != nil {
				kubeClientBuilder.WithInterceptorFuncs(*testCase.Interceptors)
			}

			kubeClient := kubeClientBuilder.Build()

			client := NewClient(kubeClient, "unikorn-region", nil)

			regions, err := client.List(t.Context())
			require.Equal(t, testCase.ExpectError, err != nil)

			for i := range regions {
				normalizeResourceReadMetadata(&regions[i].Metadata)
			}

			require.ElementsMatch(t, testCase.Expected, regions)
		})
	}
}

func TestClient_GetDetail(t *testing.T) {
	t.Parallel()

	type TestCase struct {
		Name         string
		Objects      []kubeclient.Object
		Interceptors *kubeinterceptor.Funcs
		RegionID     string
		ExpectError  bool
		Expected     *regionapi.RegionDetailRead
	}

	testCases := []TestCase{
		{
			Name:         "returns error when region is missing",
			Objects:      nil,
			Interceptors: nil,
			RegionID:     "",
			ExpectError:  true,
			Expected:     nil,
		},
		{
			Name:    "returns error when region retrieval fails",
			Objects: nil,
			Interceptors: &kubeinterceptor.Funcs{
				Get: func(ctx context.Context, client kubeclient.WithWatch, key kubeclient.ObjectKey, obj kubeclient.Object, opts ...kubeclient.GetOption) error {
					return kerrors.NewInternalError(testutil.ErrMustFail)
				},
			},
			RegionID:    "",
			ExpectError: true,
			Expected:    nil,
		},
		{
			Name: "returns OpenStack region detail when retrieval succeeds",
			Objects: []kubeclient.Object{
				RegionNorway().Source,
			},
			Interceptors: nil,
			RegionID:     RegionNorway().Source.Name,
			ExpectError:  false,
			Expected: &regionapi.RegionDetailRead{
				Metadata: RegionNorway().Target.Metadata,
				Spec: regionapi.RegionDetailSpec{
					Features: RegionNorway().Target.Spec.Features,
					Type:     RegionNorway().Target.Spec.Type,
				},
			},
		},
		{
			Name: "returns error when Kubernetes region spec.kubernetes is missing",
			Objects: []kubeclient.Object{
				testutil.Mutate(RegionSpain().Source, func(region *regionv1.Region) {
					region.Spec.Kubernetes = nil
				}),
			},
			Interceptors: nil,
			RegionID:     RegionSpain().Source.Name,
			ExpectError:  true,
			Expected:     nil,
		},
		{
			Name: "returns error when Kubernetes region spec.kubernetes.kubeConfigSecret is missing",
			Objects: []kubeclient.Object{
				testutil.Mutate(RegionSpain().Source, func(region *regionv1.Region) {
					region.Spec.Kubernetes = &regionv1.RegionKubernetesSpec{}
				}),
			},
			Interceptors: nil,
			RegionID:     RegionSpain().Source.Name,
			ExpectError:  true,
			Expected:     nil,
		},
		{
			Name: "returns error when Kubernetes region secret is missing",
			Objects: []kubeclient.Object{
				testutil.Mutate(RegionSpain().Source, func(region *regionv1.Region) {
					region.Spec.Kubernetes = &regionv1.RegionKubernetesSpec{
						KubeconfigSecret: &regionv1.NamespacedObject{},
					}
				}),
			},
			Interceptors: nil,
			RegionID:     RegionSpain().Source.Name,
			ExpectError:  true,
			Expected:     nil,
		},
		{
			Name: "returns Kubernetes region detail when retrieval succeeds",
			Objects: []kubeclient.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "704e9947-1982-4b33-a943-8564e666aa26",
						Namespace: "unikorn-region",
					},
					Data: map[string][]byte{
						"kubeconfig": []byte("kubeconfig-placeholder"),
					},
				},
				testutil.Mutate(RegionSpain().Source, func(region *regionv1.Region) {
					region.Spec.Kubernetes = &regionv1.RegionKubernetesSpec{
						KubeconfigSecret: &regionv1.NamespacedObject{
							Name: "704e9947-1982-4b33-a943-8564e666aa26",
						},
					}
				}),
			},
			Interceptors: nil,
			RegionID:     RegionSpain().Source.Name,
			ExpectError:  false,
			Expected: &regionapi.RegionDetailRead{
				Metadata: RegionSpain().Target.Metadata,
				Spec: regionapi.RegionDetailSpec{
					Features: RegionSpain().Target.Spec.Features,
					Kubernetes: &regionapi.RegionDetailKubernetes{
						Kubeconfig: "a3ViZWNvbmZpZy1wbGFjZWhvbGRlcg",
					},
					Type: RegionSpain().Target.Spec.Type,
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			kubeClientBuilder := setupTestKubeClientBuilder(t).
				WithObjects(testCase.Objects...)

			if testCase.Interceptors != nil {
				kubeClientBuilder.WithInterceptorFuncs(*testCase.Interceptors)
			}

			kubeClient := kubeClientBuilder.Build()

			client := NewClient(kubeClient, "unikorn-region", nil)

			regionDetail, err := client.GetDetail(t.Context(), testCase.RegionID)
			// FIXME: We should either make all the error properties public, or provide a helper function to check the error code.
			require.Equal(t, testCase.ExpectError, err != nil)

			if regionDetail != nil {
				normalizeResourceReadMetadata(&regionDetail.Metadata)
			}

			require.Equal(t, testCase.Expected, regionDetail)
		})
	}
}

func fakeOpenStackFlavor(name string, cpu int, memoryGiB int64, gpuLogicalCount int) types.Flavor {
	return types.Flavor{
		Name:   name,
		CPUs:   cpu,
		Memory: unit.ResourceQuantityGiB(memoryGiB),
		Disk:   unit.ResourceQuantityGB(0),
		GPU: &types.GPU{
			LogicalCount: gpuLogicalCount,
			Memory:       unit.ResourceQuantityGiB(0),
		},
	}
}

func fakeOpenAPIFlavor(name string, cpu, memoryGiB, gpuLogicalCount int) regionapi.Flavor {
	return regionapi.Flavor{
		Metadata: coreapi.StaticResourceMetadata{
			Name: name,
		},
		Spec: regionapi.FlavorSpec{
			Cpus:   cpu,
			Memory: memoryGiB,
			Gpu: &regionapi.GpuSpec{
				LogicalCount: gpuLogicalCount,
			},
		},
	}
}

type ListFlavorsTestCase struct {
	Name        string
	GetProvider func(t *testing.T, expectedNamespace, expectedRegionID string) GetProviderFunc
	ExpectError bool
	Expected    regionapi.Flavors
}

func listFlavorsSuccessCase(name string, flavors types.FlavorList, expected regionapi.Flavors) ListFlavorsTestCase {
	return ListFlavorsTestCase{
		Name: name,
		GetProvider: func(t *testing.T, expectedNamespace, expectedRegionID string) GetProviderFunc {
			t.Helper()

			return func(ctx context.Context, c kubeclient.Client, namespace, regionID string) (Provider, error) {
				require.NotNil(t, c)
				require.Equal(t, expectedNamespace, namespace)
				require.Equal(t, expectedRegionID, regionID)

				mockController := gomock.NewController(t)

				mockProvider := mock.NewMockProvider(mockController)

				mockProvider.EXPECT().
					Flavors(gomock.Any()).
					Return(flavors, nil)

				return mockProvider, nil
			}
		},
		ExpectError: false,
		Expected:    expected,
	}
}

func TestClient_ListFlavors(t *testing.T) {
	t.Parallel()

	testCases := []ListFlavorsTestCase{
		{
			Name: "returns error when provider creation fails",
			GetProvider: func(t *testing.T, expectedNamespace, expectedRegionID string) GetProviderFunc {
				t.Helper()

				return func(ctx context.Context, c kubeclient.Client, namespace, regionID string) (Provider, error) {
					require.NotNil(t, c)
					require.Equal(t, expectedNamespace, namespace)
					require.Equal(t, expectedRegionID, regionID)

					return nil, testutil.ErrMustFail
				}
			},
			ExpectError: true,
			Expected:    nil,
		},
		{
			Name: "returns error when listing flavors fails",
			GetProvider: func(t *testing.T, expectedNamespace, expectedRegionID string) GetProviderFunc {
				t.Helper()

				return func(ctx context.Context, c kubeclient.Client, namespace, regionID string) (Provider, error) {
					require.NotNil(t, c)
					require.Equal(t, expectedNamespace, namespace)
					require.Equal(t, expectedRegionID, regionID)

					mockController := gomock.NewController(t)

					mockProvider := mock.NewMockProvider(mockController)

					mockProvider.EXPECT().
						Flavors(gomock.Any()).
						Return(nil, testutil.ErrMustFail)

					return mockProvider, nil
				}
			},
			ExpectError: true,
			Expected:    nil,
		},
		listFlavorsSuccessCase(
			"returns flavors when provider retrieval succeeds with no flavors",
			types.FlavorList{},
			regionapi.Flavors{},
		),
		listFlavorsSuccessCase(
			"returns flavors when provider retrieval succeeds with a single flavor",
			types.FlavorList{
				fakeOpenStackFlavor("6925e8d4-1ff4-479f-92cc-ed54ac143182", 0, 0, 0),
			},
			regionapi.Flavors{
				fakeOpenAPIFlavor("6925e8d4-1ff4-479f-92cc-ed54ac143182", 0, 0, 0),
			},
		),
		listFlavorsSuccessCase(
			"returns flavors sorted by memory when provider retrieval succeeds with already sorted flavors",
			types.FlavorList{
				fakeOpenStackFlavor("8b040575-144d-4d8e-befc-ceb0141c043e", 0, 1, 0),
				fakeOpenStackFlavor("dbb55177-4894-4d7c-ab95-a2dfbb8490c0", 0, 2, 0),
			},
			regionapi.Flavors{
				fakeOpenAPIFlavor("8b040575-144d-4d8e-befc-ceb0141c043e", 0, 1, 0),
				fakeOpenAPIFlavor("dbb55177-4894-4d7c-ab95-a2dfbb8490c0", 0, 2, 0),
			},
		),
		listFlavorsSuccessCase(
			"returns flavors sorted by memory when provider retrieval succeeds with unsorted flavors",
			types.FlavorList{
				fakeOpenStackFlavor("db90b257-cb69-48fc-90b0-fa140162e107", 0, 2, 0),
				fakeOpenStackFlavor("5c530d64-4bdc-41bb-ba62-0036db90c2cf", 0, 1, 0),
			},
			regionapi.Flavors{
				fakeOpenAPIFlavor("5c530d64-4bdc-41bb-ba62-0036db90c2cf", 0, 1, 0),
				fakeOpenAPIFlavor("db90b257-cb69-48fc-90b0-fa140162e107", 0, 2, 0),
			},
		),
		listFlavorsSuccessCase(
			"returns flavors sorted by memory when provider retrieval succeeds with identical flavors",
			types.FlavorList{
				fakeOpenStackFlavor("0839c35e-8742-4fb5-aa08-f5f27ee131af", 0, 1, 0),
				fakeOpenStackFlavor("073a36cb-5858-4ba4-a9bb-57fed062f399", 0, 1, 0),
			},
			regionapi.Flavors{
				fakeOpenAPIFlavor("0839c35e-8742-4fb5-aa08-f5f27ee131af", 0, 1, 0),
				fakeOpenAPIFlavor("073a36cb-5858-4ba4-a9bb-57fed062f399", 0, 1, 0),
			},
		),
		listFlavorsSuccessCase(
			"returns flavors sorted by CPU when provider retrieval succeeds with already sorted flavors",
			types.FlavorList{
				fakeOpenStackFlavor("d913396c-c565-47bd-a426-7c5fb3b8b34c", 1, 0, 0),
				fakeOpenStackFlavor("cfa14cbc-c762-482b-856f-de6ffcbaf7df", 2, 0, 0),
			},
			regionapi.Flavors{
				fakeOpenAPIFlavor("d913396c-c565-47bd-a426-7c5fb3b8b34c", 1, 0, 0),
				fakeOpenAPIFlavor("cfa14cbc-c762-482b-856f-de6ffcbaf7df", 2, 0, 0),
			},
		),
		listFlavorsSuccessCase(
			"returns flavors sorted by CPU when provider retrieval succeeds with unsorted flavors",
			types.FlavorList{
				fakeOpenStackFlavor("2fa0ebba-cee2-4686-ae7b-331ac51348b3", 2, 0, 0),
				fakeOpenStackFlavor("bbb64d20-bbea-44df-a483-113e84b2d249", 1, 0, 0),
			},
			regionapi.Flavors{
				fakeOpenAPIFlavor("bbb64d20-bbea-44df-a483-113e84b2d249", 1, 0, 0),
				fakeOpenAPIFlavor("2fa0ebba-cee2-4686-ae7b-331ac51348b3", 2, 0, 0),
			},
		),
		listFlavorsSuccessCase(
			"returns flavors sorted by GPU when provider retrieval succeeds with already sorted flavors",
			types.FlavorList{
				fakeOpenStackFlavor("1ec332d6-ffb6-4bd5-aa58-5e11781e86e7", 0, 0, 1),
				fakeOpenStackFlavor("73dfb1f3-f2a8-4a5f-85f0-c29bb3104679", 0, 0, 2),
			},
			regionapi.Flavors{
				fakeOpenAPIFlavor("1ec332d6-ffb6-4bd5-aa58-5e11781e86e7", 0, 0, 1),
				fakeOpenAPIFlavor("73dfb1f3-f2a8-4a5f-85f0-c29bb3104679", 0, 0, 2),
			},
		),
		listFlavorsSuccessCase(
			"returns flavors sorted by GPU when provider retrieval succeeds with unsorted flavors",
			types.FlavorList{
				fakeOpenStackFlavor("e6a5c73f-7490-4c2a-aa5d-e5870f676daa", 0, 0, 2),
				fakeOpenStackFlavor("91204f3e-75f8-449d-9f76-93dae1cb49ce", 0, 0, 1),
			},
			regionapi.Flavors{
				fakeOpenAPIFlavor("91204f3e-75f8-449d-9f76-93dae1cb49ce", 0, 0, 1),
				fakeOpenAPIFlavor("e6a5c73f-7490-4c2a-aa5d-e5870f676daa", 0, 0, 2),
			},
		),
		listFlavorsSuccessCase(
			"returns flavors when provider retrieval succeeds",
			types.FlavorList{
				fakeOpenStackFlavor("eacfff13-67ab-4c3c-a4cd-e50e54813771", 2, 32, 8),
				fakeOpenStackFlavor("6c0b1f69-c353-49c2-9f06-25ca08400eba", 8, 128, 32),
				fakeOpenStackFlavor("91c3410f-cf6e-4898-ba25-04e5f5fd2037", 8, 64, 32),
				fakeOpenStackFlavor("180d8633-12a7-4e07-9802-cad200e35218", 8, 64, 32),
				fakeOpenStackFlavor("9f246199-d51a-4e69-b742-5fa417947e8d", 4, 32, 8),
				fakeOpenStackFlavor("7a37724c-89f0-41ad-b8a6-c4000512668e", 8, 64, 16),
				fakeOpenStackFlavor("2f3c02bc-8823-4aec-88c2-8c71175caf6f", 2, 32, 8),
			},
			regionapi.Flavors{
				fakeOpenAPIFlavor("eacfff13-67ab-4c3c-a4cd-e50e54813771", 2, 32, 8),
				fakeOpenAPIFlavor("2f3c02bc-8823-4aec-88c2-8c71175caf6f", 2, 32, 8),
				fakeOpenAPIFlavor("9f246199-d51a-4e69-b742-5fa417947e8d", 4, 32, 8),
				fakeOpenAPIFlavor("7a37724c-89f0-41ad-b8a6-c4000512668e", 8, 64, 16),
				fakeOpenAPIFlavor("91c3410f-cf6e-4898-ba25-04e5f5fd2037", 8, 64, 32),
				fakeOpenAPIFlavor("180d8633-12a7-4e07-9802-cad200e35218", 8, 64, 32),
				fakeOpenAPIFlavor("6c0b1f69-c353-49c2-9f06-25ca08400eba", 8, 128, 32),
			},
		),
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			var (
				kubeClient  = setupTestKubeClientBuilder(t).Build()
				namespace   = uuid.NewString()
				regionID    = uuid.NewString()
				getProvider = testCase.GetProvider(t, namespace, regionID)
				client      = NewClient(kubeClient, namespace, getProvider)
			)

			flavors, err := client.ListFlavors(t.Context(), "", regionID)
			require.Equal(t, testCase.ExpectError, err != nil)
			require.Equal(t, testCase.Expected, flavors)
		})
	}
}

func TestClient_ListExternalNetworks(t *testing.T) {
	t.Parallel()

	type TestCase struct {
		Name        string
		GetProvider func(t *testing.T, expectedNamespace, expectedRegionID string) GetProviderFunc
		ExpectError bool
		Expected    regionapi.ExternalNetworks
	}

	testCases := []TestCase{
		{
			Name: "returns error when provider creation fails",
			GetProvider: func(t *testing.T, expectedNamespace, expectedRegionID string) GetProviderFunc {
				t.Helper()

				return func(ctx context.Context, c kubeclient.Client, namespace, regionID string) (Provider, error) {
					require.NotNil(t, c)
					require.Equal(t, expectedNamespace, namespace)
					require.Equal(t, expectedRegionID, regionID)

					return nil, testutil.ErrMustFail
				}
			},
			ExpectError: true,
			Expected:    nil,
		},
		{
			Name: "returns error when listing external networks fails",
			GetProvider: func(t *testing.T, expectedNamespace, expectedRegionID string) GetProviderFunc {
				t.Helper()

				return func(ctx context.Context, c kubeclient.Client, namespace, regionID string) (Provider, error) {
					require.NotNil(t, c)
					require.Equal(t, expectedNamespace, namespace)
					require.Equal(t, expectedRegionID, regionID)

					mockController := gomock.NewController(t)

					mockProvider := mock.NewMockProvider(mockController)

					mockProvider.EXPECT().
						ListExternalNetworks(gomock.Any()).
						Return(nil, testutil.ErrMustFail)

					return mockProvider, nil
				}
			},
			ExpectError: true,
			Expected:    nil,
		},
		{
			Name: "returns external networks when provider retrieval succeeds",
			GetProvider: func(t *testing.T, expectedNamespace, expectedRegionID string) GetProviderFunc {
				t.Helper()

				return func(ctx context.Context, c kubeclient.Client, namespace, regionID string) (Provider, error) {
					require.NotNil(t, c)
					require.Equal(t, expectedNamespace, namespace)
					require.Equal(t, expectedRegionID, regionID)

					mockController := gomock.NewController(t)

					mockProvider := mock.NewMockProvider(mockController)

					networks := types.ExternalNetworks{
						{
							ID:   "f16d3d0c-4201-4c91-bf9a-f620ac00622e",
							Name: "a2a4a761-fc46-4c41-8f76-1a2a7790655a",
						},
						{
							ID:   "6ca3ccf6-d477-466b-adca-331519589f29",
							Name: "32393cc6-f95c-4064-bf3e-2cfba6f85273",
						},
						{
							ID:   "4156597f-b3cd-4c7c-8919-dfa7f1f2ce15",
							Name: "d872f507-5804-428c-863a-fd89d3430b48",
						},
					}

					mockProvider.EXPECT().
						ListExternalNetworks(gomock.Any()).
						Return(networks, nil)

					return mockProvider, nil
				}
			},
			ExpectError: false,
			Expected: regionapi.ExternalNetworks{
				{
					Id:   "f16d3d0c-4201-4c91-bf9a-f620ac00622e",
					Name: "a2a4a761-fc46-4c41-8f76-1a2a7790655a",
				},
				{
					Id:   "6ca3ccf6-d477-466b-adca-331519589f29",
					Name: "32393cc6-f95c-4064-bf3e-2cfba6f85273",
				},
				{
					Id:   "4156597f-b3cd-4c7c-8919-dfa7f1f2ce15",
					Name: "d872f507-5804-428c-863a-fd89d3430b48",
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()

			var (
				kubeClient  = setupTestKubeClientBuilder(t).Build()
				namespace   = uuid.NewString()
				regionID    = uuid.NewString()
				getProvider = testCase.GetProvider(t, namespace, regionID)
				client      = NewClient(kubeClient, namespace, getProvider)
			)

			networks, err := client.ListExternalNetworks(t.Context(), regionID)
			require.Equal(t, testCase.ExpectError, err != nil)
			require.Equal(t, testCase.Expected, networks)
		})
	}
}
