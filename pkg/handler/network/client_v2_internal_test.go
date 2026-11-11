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

package network

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/openapi"

	"k8s.io/utils/ptr"
)

func TestGenerateReservations(t *testing.T) {
	t.Parallel()

	_, prefix, err := net.ParseCIDR("192.168.0.0/24")
	require.NoError(t, err)

	t.Run("NilReservations", func(t *testing.T) {
		t.Parallel()

		out, err := generateReservations(prefix, nil)
		require.NoError(t, err)
		require.Nil(t, out)
	})

	t.Run("RejectsReservationPrefixAtNetworkBoundary", func(t *testing.T) {
		t.Parallel()

		_, err := generateReservations(prefix, &openapi.NetworkReservations{
			PrefixLength: 24,
		})
		require.Error(t, err)
		require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422, got: %v", err)
	})

	t.Run("RejectsInfrastructurePrefixSmallerThanReservation", func(t *testing.T) {
		t.Parallel()

		_, err := generateReservations(prefix, &openapi.NetworkReservations{
			PrefixLength:                 25,
			ProviderReservedPrefixLength: ptr.To(24),
		})
		require.Error(t, err)
		require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422, got: %v", err)
	})

	t.Run("AcceptsValidReservation", func(t *testing.T) {
		t.Parallel()

		out, err := generateReservations(prefix, &openapi.NetworkReservations{
			PrefixLength:                 25,
			ProviderReservedPrefixLength: ptr.To(28),
		})
		require.NoError(t, err)
		require.NotNil(t, out)
		require.Equal(t, 25, out.PrefixLength)
		require.Equal(t, ptr.To(28), out.ProviderReservedPrefixLength)
	})
}

func TestValidateCreateRequestBlockedPrefix(t *testing.T) {
	t.Parallel()

	_, blocked, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)

	region := &regionv1.Region{
		Spec: regionv1.RegionSpec{
			BlockedNetworkPrefixes: []unikornv1core.IPv4Prefix{{IPNet: *blocked}},
		},
	}

	request := func(prefix string) *openapi.NetworkV2Create {
		return &openapi.NetworkV2Create{
			Spec: openapi.NetworkV2CreateSpec{
				Prefix: prefix,
			},
		}
	}

	t.Run("RejectsBlockedPrefix", func(t *testing.T) {
		t.Parallel()

		_, _, err := validateCreateRequest(region, request("10.0.0.0/24"))
		require.Error(t, err)
		require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422, got: %v", err)
		require.ErrorContains(t, err, "10.0.0.0/8")
	})

	t.Run("AcceptsOtherPrefix", func(t *testing.T) {
		t.Parallel()

		prefix, _, err := validateCreateRequest(region, request("192.168.0.0/24"))
		require.NoError(t, err)
		require.Equal(t, "192.168.0.0/24", prefix.String())
	})
}
