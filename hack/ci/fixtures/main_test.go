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

package main

import (
	"strings"
	"testing"

	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const testRegionNamespace = "unikorn-region"

func TestFirstEnv(t *testing.T) {
	t.Setenv("FIXTURE_TEST_FIRST_EMPTY", "")
	t.Setenv("FIXTURE_TEST_FIRST_CONFIGURED", "first")
	t.Setenv("FIXTURE_TEST_SECOND_CONFIGURED", "second")

	got := firstEnv(
		"FIXTURE_TEST_FIRST_EMPTY",
		"FIXTURE_TEST_FIRST_CONFIGURED",
		"FIXTURE_TEST_SECOND_CONFIGURED",
	)
	if got != "first" {
		t.Fatalf("firstEnv() = %q, want first", got)
	}
}

func TestResolveRegionFixture(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		provider     string
		explicitID   string
		objects      []client.Object
		wantProvider regionv1.Provider
		wantRegionID string
		wantExisting bool
		wantErr      string
	}{
		{
			name:         "default simulated",
			wantProvider: regionv1.ProviderSimulated,
			wantRegionID: publicRegion,
		},
		{
			name:         "infer openstack from test region",
			explicitID:   "gb-north-1",
			objects:      []client.Object{regionFixture("gb-north-1", regionv1.ProviderOpenstack)},
			wantProvider: regionv1.ProviderOpenstack,
			wantRegionID: "gb-north-1",
			wantExisting: true,
		},
		{
			name:         "openstack safeguard matches",
			provider:     string(regionv1.ProviderOpenstack),
			explicitID:   "gb-north-1",
			objects:      []client.Object{regionFixture("gb-north-1", regionv1.ProviderOpenstack)},
			wantProvider: regionv1.ProviderOpenstack,
			wantRegionID: "gb-north-1",
			wantExisting: true,
		},
		{
			name:     "openstack missing ID",
			provider: string(regionv1.ProviderOpenstack),
			wantErr:  "TEST_REGION_ID",
		},
		{
			name:       "safeguard mismatch",
			provider:   string(regionv1.ProviderSimulated),
			explicitID: "gb-north-1",
			objects:    []client.Object{regionFixture("gb-north-1", regionv1.ProviderOpenstack)},
			wantErr:    "unexpected provider",
		},
		{
			name:       "explicit region missing",
			explicitID: "gb-north-1",
			wantErr:    "was not found",
		},
		{
			name:     "unsupported safeguard",
			provider: string(regionv1.ProviderKubernetes),
			wantErr:  "unsupported region provider",
		},
		{
			name:       "unsupported inferred provider",
			explicitID: "k8s",
			objects:    []client.Object{regionFixture("k8s", regionv1.ProviderKubernetes)},
			wantErr:    "unsupported region provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, regionID, existing, err := resolveRegionFixture(
				t.Context(),
				fixtureClient(t, tt.objects...),
				testRegionNamespace,
				tt.provider,
				tt.explicitID,
			)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("resolveRegionFixture() error = %v, want containing %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("resolveRegionFixture() error = %v", err)
			}

			if provider != tt.wantProvider {
				t.Fatalf("resolveRegionFixture() provider = %q, want %q", provider, tt.wantProvider)
			}

			if regionID != tt.wantRegionID {
				t.Fatalf("resolveRegionFixture() region ID = %q, want %q", regionID, tt.wantRegionID)
			}

			if existing != tt.wantExisting {
				t.Fatalf("resolveRegionFixture() existing = %t, want %t", existing, tt.wantExisting)
			}
		})
	}
}

func TestGetExistingRegionProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		objects []client.Object
		want    regionv1.Provider
		wantErr string
	}{
		{
			name: "openstack region exists",
			objects: []client.Object{
				regionFixture("gb-north-1", regionv1.ProviderOpenstack),
			},
			want: regionv1.ProviderOpenstack,
		},
		{
			name:    "region missing",
			wantErr: "was not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := getExistingRegionProvider(
				t.Context(),
				fixtureClient(t, tt.objects...),
				testRegionNamespace,
				"gb-north-1",
			)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("getExistingRegionProvider() error = %v, want containing %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("getExistingRegionProvider() error = %v", err)
			}

			if got != tt.want {
				t.Fatalf("getExistingRegionProvider() = %q, want %q", got, tt.want)
			}
		})
	}
}

func regionFixture(name string, provider regionv1.Provider) *regionv1.Region {
	return &regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testRegionNamespace,
			Name:      name,
		},
		Spec: regionv1.RegionSpec{
			Provider: provider,
		},
	}
}

func fixtureClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := regionv1.AddToScheme(scheme); err != nil {
		t.Fatalf("adding region scheme: %v", err)
	}

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}
