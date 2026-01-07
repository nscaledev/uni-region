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

package vlan_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/allocation/vlan"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	namespace    = "foo"
	regionID1    = "eefa3333-b6d2-4b5a-aec1-f00509f64291"
	regionID2    = "b1ee8c1e-fcb6-43cb-98c1-20679fad65e3"
	segmentStart = 1
	segmentEnd   = 2
	networkID1   = "net1"
	networkID2   = "net2"
	networkID3   = "net3"
	networkID4   = "net4"
)

func newClient(t *testing.T) client.Client {
	t.Helper()

	scheme, err := coreclient.NewScheme(regionv1.AddToScheme)
	require.NoError(t, err)

	return fake.NewClientBuilder().WithScheme(scheme).Build()
}

func segmentFixture(start, end int) regionv1.VLANSegment {
	return regionv1.VLANSegment{
		StartID: start,
		EndID:   end,
	}
}

func defaultSegmentFixture() regionv1.VLANSegment {
	return segmentFixture(segmentStart, segmentEnd)
}

func regionFixture(id string, segments ...regionv1.VLANSegment) *regionv1.Region {
	return &regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      id,
		},
		Spec: regionv1.RegionSpec{
			Provider: regionv1.ProviderOpenstack,
			Openstack: &regionv1.RegionOpenstackSpec{
				Network: &regionv1.RegionOpenstackNetworkSpec{
					ProviderNetworks: &regionv1.ProviderNetworks{
						VLAN: &regionv1.VLANSpec{
							Segments: segments,
						},
					},
				},
			},
		},
	}
}

// TestVLANAllocationCreate checks basic allocation functionality.
func TestVLANAllocationCreate(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	region := regionFixture(regionID1, defaultSegmentFixture())
	allocator := vlan.New(client, region)

	id1, err := allocator.Allocate(t.Context(), networkID1)
	require.NoError(t, err)
	require.Equal(t, segmentStart, id1)

	id2, err := allocator.Allocate(t.Context(), networkID2)
	require.NoError(t, err)
	require.Equal(t, segmentStart+1, id2)

	_, err = allocator.Allocate(t.Context(), networkID3)
	require.ErrorIs(t, err, vlan.ErrAllocation)
}

// TestVLANAllocationCreateMultiSegment tests multi segment allocation works.
func TestVLANAllocationCreateMultiSegment(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	region := regionFixture(regionID1, segmentFixture(1, 1), segmentFixture(100, 100))
	allocator := vlan.New(client, region)

	id1, err := allocator.Allocate(t.Context(), networkID1)
	require.NoError(t, err)
	require.Equal(t, 1, id1)

	id2, err := allocator.Allocate(t.Context(), networkID2)
	require.NoError(t, err)
	require.Equal(t, 100, id2)

	_, err = allocator.Allocate(t.Context(), networkID3)
	require.ErrorIs(t, err, vlan.ErrAllocation)
}

// TestVLANAllocationCreateMutliRegion test multi region allocation works.
func TestVLANAllocationCreateMutliRegion(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	region1 := regionFixture(regionID1, defaultSegmentFixture())
	region2 := regionFixture(regionID2, defaultSegmentFixture())
	allocator1 := vlan.New(client, region1)
	allocator2 := vlan.New(client, region2)

	id1, err := allocator1.Allocate(t.Context(), networkID1)
	require.NoError(t, err)
	require.Equal(t, segmentStart, id1)

	id2, err := allocator2.Allocate(t.Context(), networkID2)
	require.NoError(t, err)
	require.Equal(t, segmentStart, id2)
}

// TestVLANAllocationIllegalRangeLow tests the smallest VLAN ID that can be returned
// is a valid one, in the face of dodgy configuration.
func TestVLANAllocationIllegalRangeLow(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	region := regionFixture(regionID1, segmentFixture(0, 1))
	allocator := vlan.New(client, region)

	id, err := allocator.Allocate(t.Context(), networkID1)
	require.NoError(t, err)
	require.Equal(t, 1, id)

	_, err = allocator.Allocate(t.Context(), networkID2)
	require.ErrorIs(t, err, vlan.ErrAllocation)
}

// TestVLANAllocationIllegalRangeHigh tests the largest VLAN ID that can be returned
// is a valid one, in the face of dodgy configuration.
func TestVLANAllocationIllegalRangeHigh(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	region := regionFixture(regionID1, segmentFixture(4094, 4095))
	allocator := vlan.New(client, region)

	id, err := allocator.Allocate(t.Context(), networkID1)
	require.NoError(t, err)
	require.Equal(t, 4094, id)

	_, err = allocator.Allocate(t.Context(), networkID2)
	require.ErrorIs(t, err, vlan.ErrAllocation)
}

// TestVLANFree tests an allocated VLAN can be freed, and not freed multiple times.
func TestVLANFree(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	region := regionFixture(regionID1, defaultSegmentFixture())
	allocator := vlan.New(client, region)

	id, err := allocator.Allocate(t.Context(), networkID1)
	require.NoError(t, err)
	require.Equal(t, segmentStart, id)

	require.NoError(t, allocator.Free(t.Context(), id))
	require.ErrorIs(t, allocator.Free(t.Context(), id), vlan.ErrAllocation)
}

// TestVLANFreeIllegalID tests illegaly VLAN IDs are caught.
func TestVLANFreeIllegalID(t *testing.T) {
	t.Parallel()

	client := newClient(t)
	region := regionFixture(regionID1)
	allocator := vlan.New(client, region)

	require.ErrorIs(t, allocator.Free(t.Context(), -1), vlan.ErrAllocation)
	require.ErrorIs(t, allocator.Free(t.Context(), 0), vlan.ErrAllocation)
	require.ErrorIs(t, allocator.Free(t.Context(), 4095), vlan.ErrAllocation)
	require.ErrorIs(t, allocator.Free(t.Context(), 4096), vlan.ErrAllocation)
}
