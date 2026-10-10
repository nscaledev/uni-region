//go:build integration
// +build integration

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

//nolint:revive,testpackage // Dot imports and package naming follow the Ginkgo suites.
package suites

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	"github.com/unikorn-cloud/region/pkg/ids"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"

	"k8s.io/utils/ptr"
)

func createSnapshotLifecycleIntent(parentID string, request regionopenapi.FileStorageSnapshotV2Create) *regionopenapi.FileStorageSnapshotV2Read {
	created, err := regionClient.CreateFileStorageSnapshot(ctx, parentID, request)
	Expect(err).NotTo(HaveOccurred())
	Expect(created).NotTo(BeNil())
	DeferCleanup(func() {
		err := regionClient.DeleteFileStorageSnapshot(ctx, parentID, created.Metadata.Id)
		Expect(err == nil || errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
	})

	// Writes go directly to Kubernetes, while subsequent API reads use a cache.
	// Wait for visibility before dependent operations, including customer DELETE.
	Eventually(func(g Gomega) {
		visible, err := regionClient.GetFileStorageSnapshot(ctx, parentID, created.Metadata.Id)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(visible.Metadata.Id).To(Equal(created.Metadata.Id))
	}).WithTimeout(10 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

	return created
}

var _ = Describe("Manual File Storage Snapshot lifecycle", func() {
	Context("When creating Manual Snapshots through the deployed Region API", func() {
		Describe("Given an authorized File Storage parent", func() {
			It("returns complete pending immutable intent that can be read under its parent", func() {
				parent := createSnapshotReadTestStorage()
				expiration := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
				request := regionopenapi.FileStorageSnapshotV2Create{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        "Manual." + uuid.NewString(),
						Description: ptr.To("Before upgrading the model"),
						Tags: &coreapi.TagList{{
							Name:  "environment",
							Value: "integration",
						}},
					},
					Spec: regionopenapi.FileStorageSnapshotV2CreateSpec{
						ExpirationTime: ptr.To(expiration),
						ProtectedPath:  ptr.To("datasets/model"),
					},
				}
				created := createSnapshotLifecycleIntent(parent.Metadata.Id, request)
				parentID, err := ids.ParseFileStorageID(parent.Metadata.Id)
				Expect(err).NotTo(HaveOccurred())
				Expect(uuid.Validate(created.Metadata.Id)).To(Succeed())
				Expect(created.Metadata.Name).To(Equal(request.Metadata.Name))
				Expect(created.Metadata.OrganizationId).To(Equal(parent.Metadata.OrganizationId))
				Expect(created.Metadata.ProjectId).To(Equal(parent.Metadata.ProjectId))
				Expect(created.Metadata.CreatedBy).NotTo(BeNil())
				Expect(created.Metadata.Description).To(Equal(request.Metadata.Description))
				Expect(created.Metadata.Tags).To(Equal(request.Metadata.Tags))
				Expect(created.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusPending))
				Expect(created.Metadata.HealthStatus).To(Equal(coreapi.ResourceHealthStatusUnknown))
				Expect(created.Spec.FileStorageId).To(Equal(parentID))
				Expect(created.Spec.ExpirationTime).To(Equal(&expiration))
				Expect(created.Spec.ProtectedPath).To(Equal(request.Spec.ProtectedPath))
				Expect(created.Status).To(Equal(regionopenapi.FileStorageSnapshotV2Status{}))
				Eventually(func(g Gomega) {
					read, err := regionClient.GetFileStorageSnapshot(ctx, parent.Metadata.Id, created.Metadata.Id)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(read.Metadata.Id).To(Equal(created.Metadata.Id))
					g.Expect(read.Metadata.Name).To(Equal(created.Metadata.Name))
					g.Expect(read.Metadata.OrganizationId).To(Equal(created.Metadata.OrganizationId))
					g.Expect(read.Metadata.ProjectId).To(Equal(created.Metadata.ProjectId))
					g.Expect(read.Metadata.Tags).To(Equal(created.Metadata.Tags))
					g.Expect(read.Spec.FileStorageId).To(Equal(created.Spec.FileStorageId))
					g.Expect(read.Spec.ExpirationTime).NotTo(BeNil())
					g.Expect(*read.Spec.ExpirationTime).To(BeTemporally("==", *created.Spec.ExpirationTime))
					g.Expect(read.Spec.ProtectedPath).To(Equal(created.Spec.ProtectedPath))
					list, err := regionClient.ListFileStorageSnapshots(ctx, parent.Metadata.Id)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(list).To(ContainElement(HaveField("Metadata.Id", created.Metadata.Id)))
				}).WithTimeout(10 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())
			})
			It("accepts omitted expiration and protected path while preserving case-sensitive names", func() {
				parent := createSnapshotReadTestStorage()
				name := "Manual-" + uuid.NewString()
				upper := createSnapshotLifecycleIntent(parent.Metadata.Id, regionopenapi.FileStorageSnapshotV2Create{Metadata: coreapi.ResourceWriteMetadata{Name: name}})
				lower := createSnapshotLifecycleIntent(parent.Metadata.Id, regionopenapi.FileStorageSnapshotV2Create{Metadata: coreapi.ResourceWriteMetadata{Name: strings.ToLower(name)}})
				Expect(upper.Metadata.Id).NotTo(Equal(lower.Metadata.Id))
				Expect(upper.Metadata.Name).To(Equal(name))
				Expect(lower.Metadata.Name).To(Equal(strings.ToLower(name)))
				Expect(upper.Spec.ExpirationTime).To(BeNil())
				Expect(upper.Spec.ProtectedPath).To(BeNil())
			})
		})
	})
	Context("When deleting Manual Snapshots through the deployed Region API", func() {
		Describe("Given a non-expired Manual Snapshot", func() {
			It("records deletion intent and keeps retries safe until final removal", func() {
				parent := createSnapshotReadTestStorage()
				created := createSnapshotLifecycleIntent(parent.Metadata.Id, regionopenapi.FileStorageSnapshotV2Create{
					Metadata: coreapi.ResourceWriteMetadata{Name: "Manual-" + uuid.NewString()},
				})
				Expect(regionClient.DeleteFileStorageSnapshot(ctx, parent.Metadata.Id, created.Metadata.Id)).To(Succeed())
				// A deployed controller may finish between requests. Both outcomes
				// are valid; an existing terminating CR must still return 202.
				err := regionClient.DeleteFileStorageSnapshot(ctx, parent.Metadata.Id, created.Metadata.Id)
				Expect(err == nil || errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
				Eventually(func(g Gomega) {
					current, err := regionClient.GetFileStorageSnapshot(ctx, parent.Metadata.Id, created.Metadata.Id)
					if errors.Is(err, coreclient.ErrResourceNotFound) {
						return
					}
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(current.Metadata.Id).To(Equal(created.Metadata.Id))
					g.Expect(current.Metadata.DeletionTime).NotTo(BeNil())
					g.Expect(current.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusDeprovisioning))
					g.Expect(current.Metadata.CreatedBy).To(Equal(created.Metadata.CreatedBy))
				}).WithTimeout(10 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())
			})
		})
	})
})
