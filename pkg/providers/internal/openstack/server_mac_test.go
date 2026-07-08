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
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	"k8s.io/utils/ptr"
)

const (
	primaryNetworkID   = "ee2b52e3-a844-42bd-864d-a9ff2f39a026"
	secondaryNetworkID = "aa11bb22-cc33-dd44-ee55-ff6677889900"
)

// novaAddressEntry builds one Nova address entry carrying the given MAC. An
// empty mac omits the MAC key entirely (as Nova does before a port is bound).
func novaAddressEntry(mac string) map[string]any {
	entry := map[string]any{
		"OS-EXT-IPS:type": "fixed",
		"addr":            "7.247.33.145",
		"version":         float64(4),
	}

	if mac != "" {
		entry["OS-EXT-IPS-MAC:mac_addr"] = mac
	}

	return entry
}

// novaAddresses builds a Nova server `addresses` block for the primary network
// with a single fixed IP carrying the given MAC, mirroring the raw shape
// gophercloud preserves in servers.Server.Addresses.
func novaAddresses(mac string) map[string]any {
	return map[string]any{
		networkNameForID(primaryNetworkID): []any{novaAddressEntry(mac)},
	}
}

func TestSetServerMACAddress(t *testing.T) {
	t.Parallel()

	const (
		realMAC  = "e0:9d:73:86:cc:18"
		otherMAC = "fa:16:3e:00:11:22"
	)

	tests := []struct {
		name          string
		networks      []unikornv1.ServerNetworkSpec
		existing      *string
		openstack     *servers.Server
		wantMACadress *string
	}{
		{
			// The core case: server is ACTIVE and the port MAC is present, so
			// the monitor records it. For baremetal this is the real NIC MAC
			// bound by Ironic (Intel OUI), not the ephemeral Neutron one.
			name:          "active with mac sets it",
			networks:      []unikornv1.ServerNetworkSpec{{ID: primaryNetworkID}},
			existing:      nil,
			openstack:     &servers.Server{Status: "ACTIVE", Addresses: novaAddresses(realMAC)},
			wantMACadress: ptr.To(realMAC),
		},
		{
			// Before ACTIVE the port MAC is not guaranteed to be the final one
			// (baremetal rebinds during deploy), so the monitor must not record
			// it yet.
			name:          "building leaves mac untouched",
			networks:      []unikornv1.ServerNetworkSpec{{ID: primaryNetworkID}},
			existing:      nil,
			openstack:     &servers.Server{Status: "BUILD", Addresses: novaAddresses(realMAC)},
			wantMACadress: nil,
		},
		{
			// A read that yields no MAC must never clear a value we already
			// hold: the monitor is the sole owner and only ever writes a
			// non-empty MAC.
			name:          "active without mac preserves existing",
			networks:      []unikornv1.ServerNetworkSpec{{ID: primaryNetworkID}},
			existing:      ptr.To(realMAC),
			openstack:     &servers.Server{Status: "ACTIVE", Addresses: novaAddresses("")},
			wantMACadress: ptr.To(realMAC),
		},
		{
			// Self-healing: if the recorded MAC ever drifts from the observed
			// one, the ACTIVE read corrects it.
			name:          "active with different mac overwrites",
			networks:      []unikornv1.ServerNetworkSpec{{ID: primaryNetworkID}},
			existing:      ptr.To(otherMAC),
			openstack:     &servers.Server{Status: "ACTIVE", Addresses: novaAddresses(realMAC)},
			wantMACadress: ptr.To(realMAC),
		},
		{
			// Determinism: the MAC is read from the primary network
			// (Networks[0]) specifically, not an arbitrary entry of Nova's
			// unordered addresses map, so a second network's MAC never wins.
			name:     "reads the primary network mac not another",
			networks: []unikornv1.ServerNetworkSpec{{ID: primaryNetworkID}},
			existing: nil,
			openstack: &servers.Server{Status: "ACTIVE", Addresses: map[string]any{
				networkNameForID(primaryNetworkID):   []any{novaAddressEntry(realMAC)},
				networkNameForID(secondaryNetworkID): []any{novaAddressEntry(otherMAC)},
			}},
			wantMACadress: ptr.To(realMAC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := &unikornv1.Server{}
			server.Spec.Networks = tt.networks
			server.Status.MACAddress = tt.existing

			setServerMACAddress(t.Context(), server, tt.openstack)

			require.Equal(t, tt.wantMACadress, server.Status.MACAddress)
		})
	}
}
