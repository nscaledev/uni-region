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

// Command reset-shared-network deletes the long-lived shared test network so the
// next run recreates it. Use it when the shared network is stuck in error.
//
// Network deletion cascades to servers but is blocked by LoadBalancer and File
// Storage references; those consumers must be released first (see ADR INST-1550).
// Slice 1 has only servers on the network, which cascade, so a direct delete is
// enough for now.
package main

import (
	"context"
	"errors"
	"log"
	"time"

	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	"github.com/unikorn-cloud/region/test/api"
)

func main() {
	cfg, err := api.LoadTestConfig()
	if err != nil {
		log.Fatalf("loading test config: %v", err)
	}

	client := api.NewAPIClientWithConfig(cfg)
	ctx := context.Background()

	networks, err := client.ListNetworks(ctx, cfg.OrgID, cfg.ProjectID, cfg.RegionID)
	if err != nil {
		log.Fatalf("listing networks: %v", err)
	}

	for i := range networks {
		if networks[i].Metadata.Name != api.SharedTestNetworkName {
			continue
		}

		id := networks[i].Metadata.Id
		if err := client.DeleteNetwork(ctx, id); err != nil {
			log.Fatalf("deleting shared network %s: %v", id, err)
		}

		// Deletion is asynchronous; wait for the network to disappear so the next run
		// recreates it cleanly instead of hitting a deprovisioning network.
		deadline := time.Now().Add(5 * time.Minute)

		for {
			_, err := client.GetNetwork(ctx, id)
			if errors.Is(err, coreclient.ErrResourceNotFound) {
				break
			}

			if err != nil {
				log.Fatalf("waiting for shared network %s to delete: %v", id, err)
			}

			if time.Now().After(deadline) {
				log.Fatalf("shared network %s still present 5m after delete", id)
			}

			time.Sleep(5 * time.Second)
		}

		log.Printf("deleted shared network %s (%s)", api.SharedTestNetworkName, id)

		return
	}

	log.Printf("no shared network named %q in the configured org/project/region", api.SharedTestNetworkName)
}
