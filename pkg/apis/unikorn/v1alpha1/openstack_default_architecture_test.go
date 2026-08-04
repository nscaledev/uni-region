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

package v1alpha1_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	structuraldefaulting "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/defaulting"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestOpenstackDefaultArchitectureValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		architecture *string
		valid        bool
	}{
		{name: "omitted", valid: true},
		{name: "x86_64", architecture: architectureValue("x86_64"), valid: true},
		{name: "aarch64", architecture: architectureValue("aarch64"), valid: true},
		{name: "amd64", architecture: architectureValue("amd64")},
		{name: "arm64", architecture: architectureValue("arm64")},
		{name: "empty", architecture: architectureValue("")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resource := regionWithOpenstackDefaultArchitecture(tc.architecture)
			valid := newCRDValidator(t, regionCRDFile).validatesUnstructured(t, resource)

			require.Equal(t, tc.valid, valid)
		})
	}
}

func TestOpenstackDefaultArchitectureDefaulting(t *testing.T) {
	t.Parallel()

	resource := regionWithOpenstackDefaultArchitecture(nil)
	validator := newCRDValidator(t, regionCRDFile)

	structuraldefaulting.Default(resource, validator.structural)

	architecture, found, err := unstructured.NestedString(resource, "spec", "openstack", "defaultArchitecture")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "x86_64", architecture)
}

func architectureValue(value string) *string {
	return &value
}

func regionWithOpenstackDefaultArchitecture(architecture *string) map[string]any {
	openstack := map[string]any{
		"endpoint": "https://openstack.example.com:5000",
		"serviceAccountSecret": map[string]any{
			"name":      "credentials",
			"namespace": "default",
		},
	}

	if architecture != nil {
		openstack["defaultArchitecture"] = *architecture
	}

	return map[string]any{
		"apiVersion": "region.unikorn-cloud.org/v1alpha1",
		"kind":       "Region",
		"metadata": map[string]any{
			"name":      "region",
			"namespace": "default",
		},
		"spec": map[string]any{
			"provider":  "openstack",
			"openstack": openstack,
		},
	}
}
