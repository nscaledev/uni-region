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

//nolint:testpackage
package openstack

import (
	"context"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2/openstack/baremetal/v1/nodes"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"

	"k8s.io/utils/ptr"
)

// Two distinct image UUIDs, canonical form, for exercising agreement and
// disagreement without a one-character literal masking normalisation bugs.
const (
	appliedImageA          = "11111111-1111-4111-a111-111111111111"
	appliedImageAUppercase = "11111111-1111-4111-A111-111111111111"
	appliedImageB          = "22222222-2222-4222-a222-222222222222"
)

func TestRebuildAppliedImageFromNode(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		node    *nodes.Node
		want    *string
		wantErr bool
	}{
		{name: "no node — no second channel", node: nil, want: nil},
		{name: "bare UUID",
			node: &nodes.Node{InstanceInfo: map[string]any{"image_source": appliedImageA}}, want: ptr.To(appliedImageA)},
		{name: "a different bare UUID",
			node: &nodes.Node{InstanceInfo: map[string]any{"image_source": appliedImageB}}, want: ptr.To(appliedImageB)},
		{name: "uppercase UUID normalises to canonical lowercase",
			node: &nodes.Node{InstanceInfo: map[string]any{"image_source": appliedImageAUppercase}}, want: ptr.To(appliedImageA)},
		{name: "a Glance href ending in the image UUID resolves to it",
			node: &nodes.Node{InstanceInfo: map[string]any{
				"image_source": "http://glance.example.com:9292/v2/images/" + appliedImageA,
			}},
			want: ptr.To(appliedImageA)},
		{name: "node without instance info — the channel exists but is unreadable",
			node: &nodes.Node{}, wantErr: true},
		{name: "instance info without image_source — unreadable",
			node: &nodes.Node{InstanceInfo: map[string]any{}}, wantErr: true},
		{name: "image_source not a string — unreadable",
			node: &nodes.Node{InstanceInfo: map[string]any{"image_source": 42}}, wantErr: true},
		{name: "image_source empty — unreadable",
			node: &nodes.Node{InstanceInfo: map[string]any{"image_source": ""}}, wantErr: true},
		{name: "image_source unresolvable garbage — unreadable",
			node: &nodes.Node{InstanceInfo: map[string]any{"image_source": "not-a-uuid"}}, wantErr: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			got, err := appliedImageFromNode(c.node)

			if c.wantErr {
				require.Error(t, err)
				require.ErrorIs(t, err, errAppliedImageUnreadable)
				assert.Nil(t, got)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

// stubBaremetalClient lets a test drive GetNodeByInstanceUUID to either
// result, including a transport-level failure — which recordingBaremetalClient
// (provisioning_status_test.go) cannot express.
type stubBaremetalClient struct {
	node         *nodes.Node
	err          error
	instanceUUID string
}

func (c *stubBaremetalClient) GetNodeByInstanceUUID(_ context.Context, instanceUUID string) (*nodes.Node, error) {
	c.instanceUUID = instanceUUID

	return c.node, c.err
}

func baremetalRebuildProvider() *Provider {
	return &Provider{
		openstack: &openStackClients{
			_region: &unikornv1.Region{
				Spec: unikornv1.RegionSpec{
					Openstack: &unikornv1.RegionOpenstackSpec{
						Compute: &unikornv1.RegionOpenstackComputeSpec{
							Flavors: &unikornv1.OpenstackFlavorsSpec{
								Metadata: []unikornv1.FlavorMetadata{{ID: flavorMetalID, Baremetal: true}},
							},
						},
					},
				},
			},
		},
	}
}

// TestRebuildAppliedImageSkipsNonBaremetal proves a VM server never reaches the
// baremetal factory: nil is "no second channel", the correct answer for a
// server that never had one, and must not cost an Ironic round trip.
func TestRebuildAppliedImageSkipsNonBaremetal(t *testing.T) {
	t.Parallel()

	provider := baremetalRebuildProvider()
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{FlavorID: idstest.MustParseFlavorID(flavorVMID)}}
	factoryCalled := false

	applied, err := provider.rebuildAppliedImage(t.Context(), &unikornv1.Identity{}, server, &servers.Server{ID: "nova-id"},
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			factoryCalled = true

			return nil, errIronicUnavailable
		})

	require.NoError(t, err)
	assert.Nil(t, applied)
	assert.False(t, factoryCalled)
}

// TestRebuildAppliedImageUnreachableChannelIsNotNil is the property this task
// exists for: a baremetal server whose second channel could not be reached, or
// whose bound node cannot be read, must return an error, never a nil
// AppliedImage. A nil here would silently downgrade the two-channel check to
// one channel at exactly the moment the second opinion is missing or
// unintelligible, which is how a false success gets declared.
func TestRebuildAppliedImageUnreachableChannelIsNotNil(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{FlavorID: idstest.MustParseFlavorID(flavorMetalID)}}
	openstackServer := &servers.Server{ID: "nova-id"}

	t.Run("client factory fails", func(t *testing.T) {
		t.Parallel()

		provider := baremetalRebuildProvider()

		applied, err := provider.rebuildAppliedImage(t.Context(), &unikornv1.Identity{}, server, openstackServer,
			func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
				return nil, errIronicUnavailable
			})

		require.Error(t, err)
		require.ErrorIs(t, err, errIronicUnavailable)
		assert.Nil(t, applied)
	})

	t.Run("node lookup fails", func(t *testing.T) {
		t.Parallel()

		provider := baremetalRebuildProvider()
		client := &stubBaremetalClient{err: errIronicUnavailable}

		applied, err := provider.rebuildAppliedImage(t.Context(), &unikornv1.Identity{}, server, openstackServer,
			func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
				return client, nil
			})

		require.Error(t, err)
		require.ErrorIs(t, err, errIronicUnavailable)
		assert.Nil(t, applied)
	})

	t.Run("node exists but its image_source is unreadable", func(t *testing.T) {
		t.Parallel()

		provider := baremetalRebuildProvider()
		client := &stubBaremetalClient{node: &nodes.Node{InstanceInfo: map[string]any{"image_source": "not-a-uuid"}}}

		applied, err := provider.rebuildAppliedImage(t.Context(), &unikornv1.Identity{}, server, openstackServer,
			func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
				return client, nil
			})

		require.Error(t, err)
		require.ErrorIs(t, err, errAppliedImageUnreadable)
		assert.Nil(t, applied)
	})
}

// TestRebuildAppliedImageNoNodeYetIsNotAFailure proves a baremetal lookup that
// succeeds but finds no bound node (Ironic has not caught up with Nova yet) is
// the benign "no evidence yet" case, not a lookup failure: it returns a nil
// AppliedImage with no error, matching how the rest of the package treats an
// absent node (baremetalBuildPhase, GetNodeByInstanceUUID itself).
func TestRebuildAppliedImageNoNodeYetIsNotAFailure(t *testing.T) {
	t.Parallel()

	provider := baremetalRebuildProvider()
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{FlavorID: idstest.MustParseFlavorID(flavorMetalID)}}
	client := &stubBaremetalClient{}

	applied, err := provider.rebuildAppliedImage(t.Context(), &unikornv1.Identity{}, server, &servers.Server{ID: "nova-id"},
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return client, nil
		})

	require.NoError(t, err)
	assert.Nil(t, applied)
}

// TestRebuildAppliedImageReportsTheNodesImage is the end-to-end wiring case:
// a baremetal server with a bound node reporting its deployed image surfaces
// that image, using the identity and instance UUID the caller supplied.
func TestRebuildAppliedImageReportsTheNodesImage(t *testing.T) {
	t.Parallel()

	provider := baremetalRebuildProvider()
	server := &unikornv1.Server{Spec: unikornv1.ServerSpec{FlavorID: idstest.MustParseFlavorID(flavorMetalID)}}
	client := &stubBaremetalClient{node: &nodes.Node{InstanceInfo: map[string]any{"image_source": appliedImageA}}}
	identity := &unikornv1.Identity{}

	applied, err := provider.rebuildAppliedImage(t.Context(), identity, server, &servers.Server{ID: "nova-id"},
		func(_ context.Context, gotIdentity *unikornv1.Identity) (BaremetalInterface, error) {
			require.Same(t, identity, gotIdentity)

			return client, nil
		})

	require.NoError(t, err)
	require.NotNil(t, applied)
	assert.Equal(t, appliedImageA, *applied)
	assert.Equal(t, "nova-id", client.instanceUUID)
}

// TestReconcileServerUnreadableAppliedImageYieldsWithoutDeciding is the wiring
// test at the caller: a baremetal server whose bound node reports an
// unreadable image_source must not reach rebuildDecision at all. The scenario
// is set up so that, absent the fix, the decision would be rebuildCall — a
// committed marker, provider idle at the recorded pre-arm image — and
// stubComputeClient.RebuildServer fails the test if it is ever invoked.
func TestReconcileServerUnreadableAppliedImageYieldsWithoutDeciding(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{
		Spec: unikornv1.ServerSpec{
			FlavorID: idstest.MustParseFlavorID(flavorMetalID),
			Image:    &unikornv1.ServerImage{ID: idstest.MustParseImageID(appliedImageB)},
		},
	}
	server.Status.Rebuild = &unikornv1.ServerRebuildStatus{
		TargetImageID:  idstest.MustParseImageID(appliedImageB),
		PreArmImageRef: appliedImageA,
		Accepted:       true,
	}

	openstackServer := &servers.Server{
		ID:         "nova-id",
		Status:     "ACTIVE",
		Image:      map[string]any{"id": appliedImageA},
		LaunchedAt: time.Now().Add(-time.Hour),
	}

	client := &stubComputeClient{server: openstackServer}
	provider := baremetalRebuildProvider()
	baremetal := &stubBaremetalClient{node: &nodes.Node{InstanceInfo: map[string]any{"image_source": "not-a-uuid"}}}

	_, err := provider.reconcileServer(t.Context(), &unikornv1.Identity{}, client, server, nil, "", nil,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			return baremetal, nil
		})

	require.Error(t, err)
	require.ErrorIs(t, err, errAppliedImageUnreadable)
	require.NotErrorIs(t, err, errUnexpectedRebuild, "RebuildServer must not be called when the second channel cannot be read")
}

// TestReconcileServerSkipsSecondChannelWithoutADecision proves the gate at the
// call site: a baremetal server with no outstanding rebuild marker, and whose
// provider image already matches the desired one, has no rebuild decision to
// make and must not pay for the Ironic round trip at all. Without the gate,
// GetNodeByInstanceUUID returning a node before Ironic's instance_info has
// caught up would turn this steady-state pass into a hard reconcile failure
// for a server with nothing to converge.
func TestReconcileServerSkipsSecondChannelWithoutADecision(t *testing.T) {
	t.Parallel()

	server := &unikornv1.Server{
		Spec: unikornv1.ServerSpec{
			FlavorID: idstest.MustParseFlavorID(flavorMetalID),
			Image:    &unikornv1.ServerImage{ID: idstest.MustParseImageID(appliedImageA)},
		},
	}

	openstackServer := &servers.Server{
		ID:     "nova-id",
		Status: "ACTIVE",
		Image:  map[string]any{"id": appliedImageA},
	}

	client := &stubComputeClient{server: openstackServer}
	provider := baremetalRebuildProvider()
	factoryCalled := false

	_, err := provider.reconcileServer(t.Context(), &unikornv1.Identity{}, client, server, nil, "", nil,
		func(context.Context, *unikornv1.Identity) (BaremetalInterface, error) {
			factoryCalled = true

			return nil, errIronicUnavailable
		})

	require.NoError(t, err)
	assert.False(t, factoryCalled, "the second channel must not be consulted when there is no rebuild decision to make")
}
