/*
Copyright 2024 the Unikorn Authors.

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

package openstack_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/openstack"
)

func TestVLANAllocateRanges(t *testing.T) {
	tests := []struct {
		name       string
		options    *unikornv1.RegionOpenstackNetworkSpec
		fail       bool
		expectedID int
	}{
		{
			name:       "DefaultRange",
			expectedID: 1,
		},
		{
			name: "SingleSegment",
			options: &unikornv1.RegionOpenstackNetworkSpec{
				ProviderNetworks: &unikornv1.ProviderNetworks{
					VLAN: &unikornv1.VLANSpec{
						Segments: []unikornv1.VLANSegment{
							{
								StartID: 100,
								EndID:   200,
							},
						},
					},
				},
			},
			expectedID: 100,
		},
	}

	for _, test := range tests {
		t.Run(t.Name()+"_"+test.name, func(t *testing.T) {
			client := openstack.NewTestNetworkClient(test.options)

			id, err := client.AllocateVLAN(context.Background())
			if err != nil {
				require.True(t, test.fail)
				return
			}

			require.Equal(t, test.expectedID, id)
		})
	}
}
