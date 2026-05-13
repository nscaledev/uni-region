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

package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
)

const staleResourceMinimumAge = time.Hour

type staleTestResource struct {
	name    string
	id      string
	created time.Time
}

func isStaleTestResource(name string, created time.Time, prefix string, now time.Time) bool {
	return strings.HasPrefix(name, prefix) && now.Sub(created) > staleResourceMinimumAge
}

// CleanupStaleTestResources requests deletion for leaked region API test resources.
func CleanupStaleTestResources(ctx context.Context, client *APIClient, orgID, projectID, regionID, prefix string) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		fmt.Println("::error::Skipping stale region API resource cleanup: prefix is empty")

		return
	}

	now := time.Now()

	cleanupStaleListedResources(
		func() ([]regionopenapi.LoadBalancerV2Read, error) {
			return client.ListLoadBalancers(ctx, orgID, projectID, regionID)
		},
		func(resource regionopenapi.LoadBalancerV2Read) staleTestResource {
			return staleTestResourceFromMetadata(resource.Metadata.Name, resource.Metadata.Id, resource.Metadata.CreationTime)
		},
		func(resource staleTestResource) error {
			return client.DeleteLoadBalancer(ctx, resource.id)
		},
		"load balancers",
		"load balancer",
		prefix,
		now,
	)

	cleanupStaleListedResources(
		func() ([]regionopenapi.StorageV2Read, error) {
			return client.ListFileStorage(ctx, orgID, projectID, regionID)
		},
		func(resource regionopenapi.StorageV2Read) staleTestResource {
			return staleTestResourceFromMetadata(resource.Metadata.Name, resource.Metadata.Id, resource.Metadata.CreationTime)
		},
		func(resource staleTestResource) error {
			return client.DeleteFileStorage(ctx, resource.id)
		},
		"file storage resources",
		"file storage",
		prefix,
		now,
	)

	cleanupStaleListedResources(
		func() ([]regionopenapi.SshCertificateAuthorityV2Read, error) {
			return client.ListSSHCertificateAuthorities(ctx, orgID, projectID)
		},
		func(resource regionopenapi.SshCertificateAuthorityV2Read) staleTestResource {
			return staleTestResourceFromMetadata(resource.Metadata.Name, resource.Metadata.Id, resource.Metadata.CreationTime)
		},
		func(resource staleTestResource) error {
			return client.DeleteSSHCertificateAuthority(ctx, resource.id)
		},
		"SSH certificate authorities",
		"SSH certificate authority",
		prefix,
		now,
	)

	cleanupStaleListedResources(
		func() ([]regionopenapi.Image, error) {
			return client.ListImages(ctx, orgID, regionID)
		},
		func(resource regionopenapi.Image) staleTestResource {
			return staleTestResourceFromMetadata(resource.Metadata.Name, resource.Metadata.Id, resource.Metadata.CreationTime)
		},
		func(resource staleTestResource) error {
			return client.DeleteImage(ctx, orgID, regionID, resource.id)
		},
		"images",
		"image",
		prefix,
		now,
	)

	cleanupStaleListedResources(
		func() ([]regionopenapi.NetworkV2Read, error) {
			return client.ListNetworks(ctx, orgID, projectID, regionID)
		},
		func(resource regionopenapi.NetworkV2Read) staleTestResource {
			return staleTestResourceFromMetadata(resource.Metadata.Name, resource.Metadata.Id, resource.Metadata.CreationTime)
		},
		func(resource staleTestResource) error {
			return client.DeleteNetwork(ctx, resource.id)
		},
		"networks",
		"network",
		prefix,
		now,
	)
}

func staleTestResourceFromMetadata(name, id string, created time.Time) staleTestResource {
	return staleTestResource{
		name:    name,
		id:      id,
		created: created,
	}
}

func cleanupStaleListedResources[T any](
	list func() ([]T, error),
	staleResource func(T) staleTestResource,
	deleteResource func(staleTestResource) error,
	listLabel string,
	resourceLabel string,
	prefix string,
	now time.Time,
) {
	resources, err := list()
	if err != nil {
		fmt.Printf("::error::Failed to list stale region API %s: %v\n", listLabel, err)

		return
	}

	for _, resource := range resources {
		stale := staleResource(resource)
		if !isStaleTestResource(stale.name, stale.created, prefix, now) {
			continue
		}

		fmt.Printf("::error::Found stale region API %s %q (%s), created=%s\n",
			resourceLabel,
			stale.name,
			stale.id,
			stale.created.Format(time.RFC3339),
		)

		if err := deleteResource(stale); err != nil {
			fmt.Printf("::error::Failed to delete stale region API %s %q (%s): %v\n",
				resourceLabel,
				stale.name,
				stale.id,
				err,
			)

			continue
		}

		fmt.Printf("Requested cleanup for stale region API %s %q (%s)\n", resourceLabel, stale.name, stale.id)
	}
}
