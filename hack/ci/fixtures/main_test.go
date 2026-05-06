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

func TestEnvDefault(t *testing.T) {
	t.Setenv("FIXTURE_TEST_ENV_DEFAULT", "")

	if got := envDefault("FIXTURE_TEST_ENV_DEFAULT", "fallback"); got != "fallback" {
		t.Fatalf("empty environment value = %q, want fallback", got)
	}

	t.Setenv("FIXTURE_TEST_ENV_DEFAULT", "configured")

	if got := envDefault("FIXTURE_TEST_ENV_DEFAULT", "fallback"); got != "configured" {
		t.Fatalf("configured environment value = %q, want configured", got)
	}
}

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

func TestResolveTestRegionID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		provider     string
		explicitID   string
		wantProvider regionv1.Provider
		wantRegionID string
		wantErr      string
	}{
		{
			name:         "simulated",
			provider:     string(regionv1.ProviderSimulated),
			wantProvider: regionv1.ProviderSimulated,
			wantRegionID: publicRegion,
		},
		{
			name:         "openstack",
			provider:     string(regionv1.ProviderOpenstack),
			explicitID:   "gb-north-1",
			wantProvider: regionv1.ProviderOpenstack,
			wantRegionID: "gb-north-1",
		},
		{
			name:     "openstack missing ID",
			provider: string(regionv1.ProviderOpenstack),
			wantErr:  "TEST_REGION_ID",
		},
		{
			name:     "kubernetes",
			provider: string(regionv1.ProviderKubernetes),
			wantErr:  "unsupported region provider",
		},
		{
			name:     "unknown",
			provider: "unknown",
			wantErr:  "unsupported region provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, regionID, err := resolveTestRegionID(tt.provider, tt.explicitID)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("resolveTestRegionID() error = %v, want containing %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("resolveTestRegionID() error = %v", err)
			}

			if provider != tt.wantProvider {
				t.Fatalf("resolveTestRegionID() provider = %q, want %q", provider, tt.wantProvider)
			}

			if regionID != tt.wantRegionID {
				t.Fatalf("resolveTestRegionID() region ID = %q, want %q", regionID, tt.wantRegionID)
			}
		})
	}
}

func TestValidateExistingRegion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		objects  []client.Object
		provider regionv1.Provider
		wantErr  string
	}{
		{
			name: "openstack region exists",
			objects: []client.Object{
				regionFixture("gb-north-1", regionv1.ProviderOpenstack),
			},
			provider: regionv1.ProviderOpenstack,
		},
		{
			name:     "region missing",
			provider: regionv1.ProviderOpenstack,
			wantErr:  "was not found",
		},
		{
			name: "provider mismatch",
			objects: []client.Object{
				regionFixture("gb-north-1", regionv1.ProviderSimulated),
			},
			provider: regionv1.ProviderOpenstack,
			wantErr:  "has provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateExistingRegion(
				t.Context(),
				fixtureClient(t, tt.objects...),
				testRegionNamespace,
				"gb-north-1",
				tt.provider,
			)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("validateExistingRegion() error = %v, want containing %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("validateExistingRegion() error = %v", err)
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
