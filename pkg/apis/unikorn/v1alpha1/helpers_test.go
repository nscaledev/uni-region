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

	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"

	"k8s.io/utils/ptr"
)

func TestEffectiveReservations(t *testing.T) {
	t.Parallel()

	t.Run("UsesLegacyImplicitDefault", func(t *testing.T) {
		t.Parallel()

		network := &regionv1.Network{}
		require.NotNil(t, network.EffectiveReservations())
		require.Equal(t, constants.LegacyNetworkReservationPrefixLength, network.EffectiveReservations().PrefixLength)
		require.Equal(t, ptr.To(constants.LegacyNetworkProviderReservedPrefixLength), network.EffectiveReservations().ProviderReservedPrefixLength)
	})

	t.Run("UsesNoImplicitReservationsWhenAnnotated", func(t *testing.T) {
		t.Parallel()

		network := &regionv1.Network{}
		network.Annotations = map[string]string{
			constants.NetworkReservationDefaultsAnnotation: constants.MarshalAPIVersion(constants.NetworkReservationDefaultsV2),
		}

		require.Nil(t, network.EffectiveReservations())
	})

	t.Run("PrefersExplicitReservations", func(t *testing.T) {
		t.Parallel()

		network := &regionv1.Network{
			Spec: regionv1.NetworkSpec{
				Reservations: &regionv1.NetworkReservations{
					PrefixLength:                 25,
					ProviderReservedPrefixLength: ptr.To(28),
				},
			},
		}

		require.Equal(t, 25, network.EffectiveReservations().PrefixLength)
		require.Equal(t, ptr.To(28), network.EffectiveReservations().ProviderReservedPrefixLength)
	})
}
