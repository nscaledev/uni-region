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
	"net/http"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"
)

func createSnapshotReadTestStorage() *regionopenapi.StorageV2Read {
	request := api.NewFileStoragePayload(config.OrgID, config.ProjectID, config.RegionID, requireFileStorageClassID()).WithSizeGiB(1).Build()
	request.Spec.Attachments = nil

	created, err := regionClient.CreateFileStorage(ctx, request)
	Expect(err).NotTo(HaveOccurred())
	Expect(created).NotTo(BeNil())
	DeferCleanup(func() {
		err := regionClient.DeleteFileStorage(ctx, created.Metadata.Id)
		Expect(err == nil || errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
	})

	Eventually(func(g Gomega) {
		storage, err := regionClient.GetFileStorage(ctx, created.Metadata.Id)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(storage.Metadata.Id).To(Equal(created.Metadata.Id))
		g.Expect(storage.Metadata.Name).To(Equal(request.Metadata.Name))
		g.Expect(storage.Metadata.OrganizationId).To(Equal(config.OrgID))
		g.Expect(storage.Metadata.ProjectId).To(Equal(config.ProjectID))
	}).WithTimeout(10 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

	return created
}

func expectSnapshotReadNotFound(apiError *coreapi.Error) {
	Expect(apiError).NotTo(BeNil())
	Expect(apiError.Error).To(Equal(coreapi.NotFound))
	Expect(apiError.ErrorDescription).To(Equal("resource not found"))
	Expect(apiError.TraceId).NotTo(BeNil())
}

var _ = Describe("Manual File Storage Snapshot reads", func() {
	Context("When reading snapshots from the deployed Region API", func() {
		Describe("Given a new File Storage with no Manual Snapshots", func() {
			It("returns an empty snapshot collection, including tag-filtered reads", func() {
				storage := createSnapshotReadTestStorage()
				snapshots, err := regionClient.ListFileStorageSnapshots(ctx, storage.Metadata.Id)
				Expect(err).NotTo(HaveOccurred())
				Expect(snapshots).To(Equal(regionopenapi.FileStorageSnapshotsV2Read{}))

				filtered, err := regionClient.ListFileStorageSnapshots(ctx, storage.Metadata.Id, "environment=production", "team=ml")
				Expect(err).NotTo(HaveOccurred())
				Expect(filtered).To(Equal(regionopenapi.FileStorageSnapshotsV2Read{}))
			})
			It("returns the canonical item 404 for a missing Manual Snapshot", func() {
				storage := createSnapshotReadTestStorage()
				snapshotID := uuid.NewString()
				snapshot, err := regionClient.GetFileStorageSnapshot(ctx, storage.Metadata.Id, snapshotID)
				Expect(snapshot).To(BeNil())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())

				apiError, err := regionClient.GetFileStorageSnapshotExpectError(ctx, storage.Metadata.Id, snapshotID, http.StatusNotFound)
				Expect(err).NotTo(HaveOccurred())
				expectSnapshotReadNotFound(apiError)
			})
			It("rejects malformed tag selectors with a standard 400 body", func() {
				storage := createSnapshotReadTestStorage()
				apiError, err := regionClient.ListFileStorageSnapshotsExpectError(ctx, storage.Metadata.Id, http.StatusBadRequest, "malformed")
				Expect(err).NotTo(HaveOccurred())
				Expect(apiError.Error).To(Equal(coreapi.InvalidRequest))
				Expect(apiError.ErrorDescription).NotTo(BeEmpty())
			})
		})
		Describe("Given a missing parent File Storage", func() {
			It("returns canonical collection and item 404 bodies", func() {
				parentID, snapshotID := uuid.NewString(), uuid.NewString()
				collectionError, err := regionClient.ListFileStorageSnapshotsExpectError(ctx, parentID, http.StatusNotFound)
				Expect(err).NotTo(HaveOccurred())
				expectSnapshotReadNotFound(collectionError)
				itemError, err := regionClient.GetFileStorageSnapshotExpectError(ctx, parentID, snapshotID, http.StatusNotFound)
				Expect(err).NotTo(HaveOccurred())
				expectSnapshotReadNotFound(itemError)
			})
		})
		Describe("Given a parent owned by another organization", func() {
			It("returns canonical 404s before exposing any child inventory", func() {
				if secondaryClient == nil {
					Skip("TEST_SECONDARY_ORG_ID and TEST_SECONDARY_AUTH_TOKEN not configured")
				}

				storage := createSnapshotReadTestStorage()
				collectionError, err := secondaryClient.ListFileStorageSnapshotsExpectError(ctx, storage.Metadata.Id, http.StatusNotFound)
				Expect(err).NotTo(HaveOccurred())
				expectSnapshotReadNotFound(collectionError)
				itemError, err := secondaryClient.GetFileStorageSnapshotExpectError(ctx, storage.Metadata.Id, uuid.NewString(), http.StatusNotFound)
				Expect(err).NotTo(HaveOccurred())
				expectSnapshotReadNotFound(itemError)
			})
		})
		Describe("Given malformed path identifiers", func() {
			It("rejects non-UUID parent and snapshot identifiers with standard 400 bodies", func() {
				collectionError, err := regionClient.ListFileStorageSnapshotsExpectError(ctx, "not-a-uuid", http.StatusBadRequest)
				Expect(err).NotTo(HaveOccurred())
				Expect(collectionError.Error).To(Equal(coreapi.InvalidRequest))
				for _, ids := range [][2]string{{"not-a-uuid", uuid.NewString()}, {uuid.NewString(), "not-a-uuid"}} {
					itemError, err := regionClient.GetFileStorageSnapshotExpectError(ctx, ids[0], ids[1], http.StatusBadRequest)
					Expect(err).NotTo(HaveOccurred())
					Expect(itemError.Error).To(Equal(coreapi.InvalidRequest))
					Expect(itemError.ErrorDescription).NotTo(BeEmpty())
				}
			})
		})
	})
})
