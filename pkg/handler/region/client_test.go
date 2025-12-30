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

//nolint:testpackage
package region

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	regionapi "github.com/unikorn-cloud/region/pkg/openapi"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	kubeclient "sigs.k8s.io/controller-runtime/pkg/client"
	kubefake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	kubeinterceptor "sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

var ErrMustFail = errors.New("an expected failure for testing purposes")

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
		Name            string
		Interceptors    *kubeinterceptor.Funcs
		ExpectError     bool
		ExpectedRegions regionapi.Regions
	}

	testCases := []TestCases{
		{
			Name: "returns error when list fails",
			Interceptors: &kubeinterceptor.Funcs{
				List: func(ctx context.Context, client kubeclient.WithWatch, list kubeclient.ObjectList, opts ...kubeclient.ListOption) error {
					return kerrors.NewInternalError(ErrMustFail)
				},
			},
			ExpectError:     true,
			ExpectedRegions: nil,
		},
		{
			Name:        "returns regions when list succeeds",
			ExpectError: false,
			ExpectedRegions: regionapi.Regions{
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

			require.ElementsMatch(t, testCase.ExpectedRegions, regions)
		})
	}
}

func MutateKubernetesRegion(region *regionv1.Region, mutator func(*regionv1.Region)) *regionv1.Region {
	mutator(region)
	return region
}

func TestClient_GetDetail(t *testing.T) {
	t.Parallel()

	type TestCase struct {
		Name                 string
		Objects              []kubeclient.Object
		Interceptors         *kubeinterceptor.Funcs
		RegionID             string
		ExpectError          bool
		ExpectedRegionDetail *regionapi.RegionDetailRead
	}

	testCases := []TestCase{
		{
			Name:                 "returns error when region is missing",
			Objects:              nil,
			Interceptors:         nil,
			RegionID:             "",
			ExpectError:          true,
			ExpectedRegionDetail: nil,
		},
		{
			Name:    "returns error when region retrieval fails",
			Objects: nil,
			Interceptors: &kubeinterceptor.Funcs{
				Get: func(ctx context.Context, client kubeclient.WithWatch, key kubeclient.ObjectKey, obj kubeclient.Object, opts ...kubeclient.GetOption) error {
					return kerrors.NewInternalError(ErrMustFail)
				},
			},
			RegionID:             "",
			ExpectError:          true,
			ExpectedRegionDetail: nil,
		},
		{
			Name: "returns OpenStack region detail when retrieval succeeds",
			Objects: []kubeclient.Object{
				RegionNorway().Source,
			},
			Interceptors: nil,
			RegionID:     RegionNorway().Source.Name,
			ExpectError:  false,
			ExpectedRegionDetail: &regionapi.RegionDetailRead{
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
				MutateKubernetesRegion(RegionSpain().Source, func(region *regionv1.Region) {
					region.Spec.Kubernetes = nil
				}),
			},
			Interceptors:         nil,
			RegionID:             RegionSpain().Source.Name,
			ExpectError:          true,
			ExpectedRegionDetail: nil,
		},
		{
			Name: "returns error when Kubernetes region spec.kubernetes.kubeConfigSecret is missing",
			Objects: []kubeclient.Object{
				MutateKubernetesRegion(RegionSpain().Source, func(region *regionv1.Region) {
					region.Spec.Kubernetes = &regionv1.RegionKubernetesSpec{}
				}),
			},
			Interceptors:         nil,
			RegionID:             RegionSpain().Source.Name,
			ExpectError:          true,
			ExpectedRegionDetail: nil,
		},
		{
			Name: "returns error when Kubernetes region secret is missing",
			Objects: []kubeclient.Object{
				MutateKubernetesRegion(RegionSpain().Source, func(region *regionv1.Region) {
					region.Spec.Kubernetes = &regionv1.RegionKubernetesSpec{
						KubeconfigSecret: &regionv1.NamespacedObject{},
					}
				}),
			},
			Interceptors:         nil,
			RegionID:             RegionSpain().Source.Name,
			ExpectError:          true,
			ExpectedRegionDetail: nil,
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
				MutateKubernetesRegion(RegionSpain().Source, func(region *regionv1.Region) {
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
			ExpectedRegionDetail: &regionapi.RegionDetailRead{
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

			require.Equal(t, testCase.ExpectedRegionDetail, regionDetail)
		})
	}
}

func TestClient_ListFlavors(t *testing.T) {
	t.Parallel()

	type TestCase struct {
		Name            string
		GetProvider     func(t *testing.T, expectedNamespace, expectedRegionID string) GetProviderFunc
		ExpectError     bool
		ExpectedFlavors regionapi.Flavors
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

					return nil, ErrMustFail
				}
			},
			ExpectError:     true,
			ExpectedFlavors: nil,
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

			flavors, err := client.ListFlavors(t.Context(), "", regionID)
			require.Equal(t, testCase.ExpectError, err != nil)
			require.Equal(t, testCase.ExpectedFlavors, flavors)
		})
	}
}

//  func TestClient_ListExternalNetworks(t *testing.T) {
//  	t.Parallel()
//
//  	type TestCase struct {
//  		Name 	   string
//  	}
//
//  	testCases := []TestCase{}
//
//  	for _, testCase := range testCases {
//  		t.Run(testCase.Name, func(t *testing.T) {})
//  	}
//  }
