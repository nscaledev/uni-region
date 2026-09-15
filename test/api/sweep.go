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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
)

// StaleTestResourceTTL is how old a test-prefixed resource must be before the
// pre-suite sweep reclaims it. Suites complete well within an hour, so a 6-hour
// floor guarantees the sweep never races a concurrent or in-flight run and only
// ever removes orphans left behind by a previously killed runner.
const StaleTestResourceTTL = 6 * time.Hour

// SweepStaleTestResources deletes test-prefixed servers, file storage, and
// networks in the configured org/project/region that are older than
// StaleTestResourceTTL.
//
// A killed CI runner (timeout/OOM/SIGKILL) never runs in-process cleanup, so the
// resources it created — and their scarce VLANs — leak until reclaimed by hand.
// Running this before the suite means each run reclaims the previous run's
// orphans, which is the only mechanism that survives a hard process kill.
//
// Servers are deleted before file storage, and file storage before networks,
// because both dependents can block network deletion. Cleanup failures
// intentionally fail BeforeSuite: starting a new run while stale resources still
// hold VLANs would compound the leak.
func SweepStaleTestResources(c *APIClient, ctx context.Context, config *TestConfig) {
	if c.InternalAPIConfigured() {
		servers, err := c.ListServers(ctx, config.OrgID, config.ProjectID, config.RegionID, "")
		Expect(err).NotTo(HaveOccurred(), "sweep should list servers")

		for i := range servers {
			server := &servers[i]
			sweepStaleTestResource("server", server.Metadata.Id, server.Metadata.Name,
				server.Metadata.CreationTime, server.Metadata.DeletionTime,
				func() error { return c.DeleteServer(ctx, server.Metadata.Id) },
				func() { WaitForServerGone(c, ctx, server.Metadata.Id) })
		}
	}

	fileStorage, err := c.ListFileStorage(ctx, config.OrgID, config.ProjectID, config.RegionID)
	Expect(err).NotTo(HaveOccurred(), "sweep should list file storage")

	for i := range fileStorage {
		storage := &fileStorage[i]
		sweepStaleTestResource("file storage", storage.Metadata.Id, storage.Metadata.Name,
			storage.Metadata.CreationTime, storage.Metadata.DeletionTime,
			func() error { return c.DeleteFileStorage(ctx, storage.Metadata.Id) },
			func() { WaitForFileStorageGone(c, ctx, storage.Metadata.Id) })
	}

	networks, err := c.ListNetworks(ctx, config.OrgID, config.ProjectID, config.RegionID)
	Expect(err).NotTo(HaveOccurred(), "sweep should list networks")

	for i := range networks {
		network := &networks[i]
		sweepStaleTestResource("network", network.Metadata.Id, network.Metadata.Name,
			network.Metadata.CreationTime, network.Metadata.DeletionTime,
			func() error { return c.DeleteNetwork(ctx, network.Metadata.Id) },
			func() { WaitForNetworkGone(c, ctx, network.Metadata.Id) })
	}
}

func sweepStaleTestResource(resourceType, id, name string, creationTime time.Time, deletionTime *time.Time,
	deleteResource func() error, waitForGone func(),
) {
	age := time.Since(creationTime)
	if !IsTestResourceName(name) || age < StaleTestResourceTTL {
		return
	}

	if deletionTime == nil {
		GinkgoWriter.Printf("Sweep: deleting stale test %s %s (%s), age %s\n",
			resourceType, name, id, age.Round(time.Minute))

		err := deleteResource()
		ExpectWithOffset(1, err == nil || errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue(),
			"sweep should delete stale %s %s: %v", resourceType, id, err)
	}

	waitForGone()
}
