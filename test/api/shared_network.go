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

//nolint:revive,staticcheck // dot imports are standard for Ginkgo/Gomega test code
package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
)

// SharedTestNetworkName is the stable name of the long-lived network reused across
// precondition suites. It deliberately sits outside the auto-uni-region- sweep prefix:
// the sweep skips it for free, and the stable name is the find-by-name key. A future
// reader must not "fix" it by adding the prefix — see ADR INST-1550.
const SharedTestNetworkName = "uni-region-e2e-shared"

// MustResolveSharedNetwork returns the long-lived shared network for the configured
// org, project, and region, creating it once if absent. It registers no cleanup: the
// network persists between runs.
func MustResolveSharedNetwork(c *APIClient, ctx context.Context) *regionopenapi.NetworkV2Read {
	if existing := findSharedNetwork(c, ctx); existing != nil {
		return reuseSharedNetwork(c, ctx, existing)
	}

	createReq := NewNetworkPayload(c.config.OrgID, c.config.ProjectID, c.config.RegionID).
		WithName(SharedTestNetworkName).
		WithPrefix(c.config.SharedNetworkCIDR).
		Build()

	network, err := c.CreateNetwork(ctx, createReq)
	if err != nil {
		var statusErr *StatusError
		if errors.As(err, &statusErr) {
			switch statusErr.StatusCode {
			case http.StatusConflict:
				// Another run created it between our list and create; reuse it.
				raced := findSharedNetwork(c, ctx)
				Expect(raced).NotTo(BeNil(), "shared network create conflicted but it was not found on re-list")

				return reuseSharedNetwork(c, ctx, raced)
			case http.StatusForbidden:
				Expect(err).NotTo(HaveOccurred(),
					"shared network create was refused by quota (%s). The pre-suite sweep reclaims only "+
						"test-named networks over 6h, so a leaked or shared network may hold a slot — "+
						"free one or raise the quota.", statusErr.Body)

				return nil
			}
		}

		Expect(err).NotTo(HaveOccurred(), "failed to create shared network")

		return nil
	}

	Expect(network).NotTo(BeNil())

	WaitForNetworkVisible(c, ctx, network.Metadata.Id)

	return waitForSharedNetworkProvisioned(c, ctx, network.Metadata.Id, network.Metadata.Name)
}

// waitForSharedNetworkProvisioned polls until the network is provisioned, failing
// fast with a diagnosis the moment it reaches a terminal error or deprovisioning
// state rather than waiting out the full timeout.
func waitForSharedNetworkProvisioned(c *APIClient, ctx context.Context, networkID, name string) *regionopenapi.NetworkV2Read {
	var settled *regionopenapi.NetworkV2Read

	Eventually(func() coreapi.ResourceProvisioningStatus {
		net, err := c.GetNetwork(ctx, networkID)
		if err != nil {
			GinkgoWriter.Printf("Error retrieving shared network %s: %v\n", networkID, err)
			return ""
		}

		settled = net

		status := net.Metadata.ProvisioningStatus
		if status == coreapi.ResourceProvisioningStatusError || status == coreapi.ResourceProvisioningStatusDeprovisioning {
			StopTrying(sharedNetworkErrorMessage(name, c.config.RegionID, status)).Now()
		}

		return status
	}).WithTimeout(5*time.Minute).WithPolling(5*time.Second).
		Should(Equal(coreapi.ResourceProvisioningStatusProvisioned), "shared network should provision")

	return settled
}

// sharedNetworkErrorMessage names the likeliest causes of a shared network's error
// state, which the region API does not expose a reason for.
func sharedNetworkErrorMessage(name, region string, status coreapi.ResourceProvisioningStatus) string {
	return fmt.Sprintf("shared network %q is in error state (%s); the region API exposes no reason — "+
		"most commonly VLAN pool exhaustion in region %s or a CIDR overlap with a VAST VIP pool. "+
		"Reset it with 'make reset-shared-network'.", name, status, region)
}

// reuseSharedNetwork returns an already-existing shared network, waiting for it to
// provision if necessary and failing loudly if it is in error or deprovisioning.
func reuseSharedNetwork(c *APIClient, ctx context.Context, existing *regionopenapi.NetworkV2Read) *regionopenapi.NetworkV2Read {
	// A same-named network with a different prefix (a stale fixture from an earlier
	// CIDR, or one created by hand) would otherwise be reused silently and fail File
	// Storage attachment. The status prefix is only populated once known, so an
	// as-yet-unset prefix is left for the provisioning wait below.
	if c.config.SharedNetworkCIDR != "" && existing.Status.Prefix != "" &&
		existing.Status.Prefix != c.config.SharedNetworkCIDR {
		Expect(existing.Status.Prefix).To(Equal(c.config.SharedNetworkCIDR),
			"shared network %q exists with CIDR %s but config wants %s; reset it with 'make reset-shared-network'",
			existing.Metadata.Name, existing.Status.Prefix, c.config.SharedNetworkCIDR)

		return existing
	}

	switch existing.Metadata.ProvisioningStatus {
	case coreapi.ResourceProvisioningStatusProvisioned:
		return existing
	case coreapi.ResourceProvisioningStatusPending, coreapi.ResourceProvisioningStatusProvisioning:
		return waitForSharedNetworkProvisioned(c, ctx, existing.Metadata.Id, existing.Metadata.Name)
	case coreapi.ResourceProvisioningStatusError, coreapi.ResourceProvisioningStatusDeprovisioning:
		// The region API carries no reason for the error state, so name the
		// likeliest causes. This fails the run; the return is reached only when a
		// test intercepts the failure, and keeps a dead network from falling
		// through to the provisioning wait.
		Expect(existing.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned),
			sharedNetworkErrorMessage(existing.Metadata.Name, c.config.RegionID, existing.Metadata.ProvisioningStatus))

		return existing
	}

	// An unhandled status must not read as usable: a new or unexpected API value
	// would otherwise let suites run against a network that is not provisioned.
	Expect(existing.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned),
		"shared network %q has an unhandled provisioning status %q",
		existing.Metadata.Name, existing.Metadata.ProvisioningStatus)

	return existing
}

// findSharedNetwork returns the shared network if it already exists in the configured
// org/project/region, or nil if it does not.
func findSharedNetwork(c *APIClient, ctx context.Context) *regionopenapi.NetworkV2Read {
	networks, err := c.ListNetworks(ctx, c.config.OrgID, c.config.ProjectID, c.config.RegionID)
	Expect(err).NotTo(HaveOccurred(), "failed to list networks resolving the shared network")

	for i := range networks {
		if networks[i].Metadata.Name == SharedTestNetworkName {
			return &networks[i]
		}
	}

	return nil
}
