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

	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
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
