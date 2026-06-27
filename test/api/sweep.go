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
	"time"

	. "github.com/onsi/ginkgo/v2"
)

// StaleTestNetworkTTL is how old a test-prefixed network must be before the
// pre-suite sweep reclaims it. Suites complete well within an hour, so a 6-hour
// floor guarantees the sweep never races a concurrent or in-flight run and only
// ever removes orphans left behind by a previously killed runner.
const StaleTestNetworkTTL = 6 * time.Hour

// SweepStaleTestNetworks deletes test-prefixed networks in the configured
// org/project/region that are older than StaleTestNetworkTTL.
//
// A killed CI runner (timeout/OOM/SIGKILL) never runs in-process cleanup, so the
// networks it created — and their scarce VLANs — leak until reclaimed by hand.
// Running this before the suite means each run reclaims the previous run's
// orphans, which is the only mechanism that survives a hard process kill.
//
// It is best-effort: list and delete failures are logged and tolerated so a
// sweep problem can never fail the suite under test.
func SweepStaleTestNetworks(c *APIClient, ctx context.Context, config *TestConfig) {
	networks, err := c.ListNetworks(ctx, config.OrgID, config.ProjectID, config.RegionID)
	if err != nil {
		GinkgoWriter.Printf("Sweep: skipping, failed to list networks: %v\n", err)
		return
	}

	for i := range networks {
		network := &networks[i]

		if !IsTestResourceName(network.Metadata.Name) {
			continue
		}

		// Skip resources already being torn down.
		if network.Metadata.DeletionTime != nil {
			continue
		}

		age := time.Since(network.Metadata.CreationTime)
		if age < StaleTestNetworkTTL {
			continue
		}

		GinkgoWriter.Printf("Sweep: deleting stale test network %s (%s), age %s\n",
			network.Metadata.Name, network.Metadata.Id, age.Round(time.Minute))

		if err := c.DeleteNetwork(ctx, network.Metadata.Id); err != nil {
			GinkgoWriter.Printf("Sweep: failed to delete network %s: %v\n", network.Metadata.Id, err)
		}
	}
}
