/*
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

package providers_test

import (
	"testing"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestLookupCommonLoadsRegionOnMiss(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()

	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("adding client-go scheme: %v", err)
	}

	if err := unikornv1.AddToScheme(scheme); err != nil {
		t.Fatalf("adding unikorn scheme: %v", err)
	}

	namespace := "test"
	ctx := t.Context()

	region := &unikornv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "sim-public",
		},
		Spec: unikornv1.RegionSpec{
			Provider: unikornv1.ProviderSimulated,
		},
	}

	runtimeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	providerSet, err := providers.New(ctx, runtimeClient, runtimeClient, namespace, providers.Options{})
	if err != nil {
		t.Fatalf("creating providers: %v", err)
	}

	if err := runtimeClient.Create(ctx, region); err != nil {
		t.Fatalf("creating region after startup: %v", err)
	}

	if _, err := providerSet.LookupCommon("sim-public"); err != nil {
		t.Fatalf("lookup on miss: %v", err)
	}

	if err := runtimeClient.Delete(ctx, region); err != nil {
		t.Fatalf("deleting region after lazy load: %v", err)
	}

	if _, err := providerSet.LookupCommon("sim-public"); err != nil {
		t.Fatalf("lookup from cache after delete: %v", err)
	}
}
