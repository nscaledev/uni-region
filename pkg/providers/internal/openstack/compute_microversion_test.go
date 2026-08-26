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

//nolint:testpackage // Pins the unexported microversion constant directly.
package openstack

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestComputeMicroversionPin pins the Nova compute microversion to exactly
// 2.90. This is a load-bearing ceiling, not a floor: at 2.93 and above Nova
// sets reimage_boot_volume on every rebuild request and the Ironic virt driver
// refuses the flag outright ("Ironic doesn't support rebuilding volume backed
// instances") even for image-backed servers, so every baremetal rebuild fails
// — an upstream defect measured live on 2025.1
// (https://bugs.launchpad.net/nova/+bug/2127017). A dependency bump or client
// tidy-up that lets the negotiated microversion float breaks every baremetal
// rebuild in the fleet; if you are here to change this value, read the rebuild
// caveats in this package's README first.
func TestComputeMicroversionPin(t *testing.T) {
	t.Parallel()

	require.Equal(t, "2.90", computeMicroversion,
		"the compute microversion must stay >=2.64 for server groups and <2.93 for baremetal rebuilds; see this test's comment before changing it")
}
