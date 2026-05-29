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

package image_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/handler/image"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"
)

// minimalImage returns a types.Image with the minimum valid fields so that
// architecture, virtualization, kernel, and package variants can be set per test.
func minimalImage() *types.Image {
	return &types.Image{
		ID:             "img-1",
		Name:           "ubuntu-24.04",
		Architecture:   types.X86_64,
		Virtualization: types.Virtualized,
		Status:         types.ImageStatusReady,
		OS: types.ImageOS{
			Kernel: types.Linux,
			Family: "debian",
			Distro: "ubuntu",
		},
	}
}

// TestConvertImageArchitecture verifies the architecture enum mapping for all
// known values and the empty-string fallback.
func TestConvertImageArchitecture(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input types.Architecture
		want  openapi.Architecture
	}{
		{
			name:  "x86_64",
			input: types.X86_64,
			want:  openapi.ArchitectureX8664,
		},
		{
			name:  "aarch64",
			input: types.Aarch64,
			want:  openapi.ArchitectureAarch64,
		},
		{
			name:  "unknown architecture returns empty string",
			input: "riscv64",
			want:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			img := minimalImage()
			img.Architecture = tc.input

			out := image.ConvertImage(img)
			require.Equal(t, tc.want, out.Spec.Architecture)
		})
	}
}

// TestConvertImageVirtualization verifies the virtualization enum mapping for all
// known values and the empty-string fallback.
func TestConvertImageVirtualization(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input types.ImageVirtualization
		want  openapi.ImageVirtualization
	}{
		{
			name:  "Virtualized",
			input: types.Virtualized,
			want:  openapi.ImageVirtualizationVirtualized,
		},
		{
			name:  "Baremetal",
			input: types.Baremetal,
			want:  openapi.ImageVirtualizationBaremetal,
		},
		{
			name:  "Any",
			input: types.Any,
			want:  openapi.ImageVirtualizationAny,
		},
		{
			name:  "unknown virtualization returns empty string",
			input: "container",
			want:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			img := minimalImage()
			img.Virtualization = tc.input

			out := image.ConvertImage(img)
			require.Equal(t, tc.want, out.Spec.Virtualization)
		})
	}
}

// TestConvertImageKernel verifies the OS kernel enum mapping.
func TestConvertImageKernel(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input types.OsKernel
		want  openapi.OsKernel
	}{
		{
			name:  "Linux",
			input: types.Linux,
			want:  openapi.OsKernelLinux,
		},
		{
			name:  "unknown kernel returns empty string",
			input: "bsd",
			want:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			img := minimalImage()
			img.OS.Kernel = tc.input

			out := image.ConvertImage(img)
			require.Equal(t, tc.want, out.Spec.Os.Kernel)
		})
	}
}

// TestConvertImagePackages verifies that nil Packages produces nil SoftwareVersions
// and a non-nil map is faithfully copied.
func TestConvertImagePackages(t *testing.T) {
	t.Parallel()

	t.Run("nil packages produces nil SoftwareVersions", func(t *testing.T) {
		t.Parallel()

		img := minimalImage()
		img.Packages = nil

		out := image.ConvertImage(img)
		require.Nil(t, out.Spec.SoftwareVersions)
	})

	t.Run("packages map is copied to SoftwareVersions", func(t *testing.T) {
		t.Parallel()

		pkgs := types.ImagePackages{
			"cuda":  "v12.3.0",
			"nccl":  "v2.19.3",
		}

		img := minimalImage()
		img.Packages = &pkgs

		out := image.ConvertImage(img)
		require.NotNil(t, out.Spec.SoftwareVersions)
		require.Equal(t, "v12.3.0", (*out.Spec.SoftwareVersions)["cuda"])
		require.Equal(t, "v2.19.3", (*out.Spec.SoftwareVersions)["nccl"])
	})
}

// TestGenerateTags verifies the tag-merge semantics: both nil returns nil, extra
// map entries overwrite request-tag entries on collision, and an empty extra map
// does not suppress request tags.
func TestGenerateTags(t *testing.T) {
	t.Parallel()

	t.Run("both nil returns nil", func(t *testing.T) {
		t.Parallel()

		require.Nil(t, image.GenerateTags(nil, nil))
	})

	t.Run("nil request tags with extra returns extra content", func(t *testing.T) {
		t.Parallel()

		extra := map[string]string{"env": "prod"}
		out := image.GenerateTags(nil, extra)
		require.Equal(t, map[string]string{"env": "prod"}, out)
	})

	t.Run("request tags with nil extra returns request content", func(t *testing.T) {
		t.Parallel()

		tags := coreapi.TagList{
			{Name: "owner", Value: "alice"},
		}
		out := image.GenerateTags(&tags, nil)
		require.Equal(t, map[string]string{"owner": "alice"}, out)
	})

	t.Run("extra entries overwrite request tags on collision", func(t *testing.T) {
		t.Parallel()

		tags := coreapi.TagList{
			{Name: "env", Value: "staging"},
			{Name: "owner", Value: "alice"},
		}
		extra := map[string]string{"env": "prod"}

		out := image.GenerateTags(&tags, extra)
		require.Equal(t, "prod", out["env"], "extra must win on collision")
		require.Equal(t, "alice", out["owner"])
	})

	t.Run("empty extra map does not suppress request tags", func(t *testing.T) {
		t.Parallel()

		tags := coreapi.TagList{
			{Name: "team", Value: "ml"},
		}
		out := image.GenerateTags(&tags, map[string]string{})
		require.Equal(t, map[string]string{"team": "ml"}, out)
	})

	t.Run("both non-nil with no overlap merges all entries", func(t *testing.T) {
		t.Parallel()

		tags := coreapi.TagList{
			{Name: "region", Value: "us-east"},
		}
		extra := map[string]string{"instance": "i-abc"}

		out := image.GenerateTags(&tags, extra)
		require.Len(t, out, 2)
		require.Equal(t, "us-east", out["region"])
		require.Equal(t, "i-abc", out["instance"])
	})
}
