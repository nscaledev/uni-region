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

//nolint:revive,testpackage // Ginkgo suites use dot imports and package-local helpers.
package suites

import (
	"errors"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"

	"k8s.io/utils/ptr"
)

const (
	directoryQuotaTimeout = 5 * time.Minute
	directoryQuotaPolling = 5 * time.Second
	// The uni-storage usage monitor refreshes status.usage every five minutes.
	directoryQuotaUsageTimeout = 6 * time.Minute
	directoryQuotaPath         = "e2e/datasets"
	// Usernames and group names depend on the tenant's identity provider on VAST,
	// so rules that must succeed use numeric ids. Not 0: VAST stores uid 0 as root.
	directoryQuotaRuleID = int64(60001)
	gib                  = int64(1) << 30
)

func directoryQuotaLimits(capacityBytes, inodes int64) *regionopenapi.FileStorageDirectoryQuotaLimits {
	return &regionopenapi.FileStorageDirectoryQuotaLimits{CapacityBytes: ptr.To(capacityBytes), Inodes: ptr.To(inodes)}
}

func directoryQuotaRule(kind regionopenapi.FileStorageDirectoryQuotaSubjectKind, id *int64, name *string, capacityBytes, inodes int64) regionopenapi.FileStorageDirectoryQuotaRule {
	return regionopenapi.FileStorageDirectoryQuotaRule{
		Subject: regionopenapi.FileStorageDirectoryQuotaSubject{Kind: kind, Id: id, Name: name},
		Limits:  *directoryQuotaLimits(capacityBytes, inodes),
	}
}

func directoryQuotaListIDs(g Gomega, storageID string, tags ...string) []string {
	quotas, err := regionClient.ListFileStorageDirectoryQuotas(ctx, storageID, tags...)
	g.Expect(err).NotTo(HaveOccurred())

	ids := make([]string, len(quotas))
	for i := range quotas {
		ids[i] = quotas[i].Metadata.Id
	}

	return ids
}

// eventuallyDirectoryQuotaApplied waits until a read shows spec and the quota and
// each rule reach the expected status. Rule statuses go back to pending on every
// update, so a rule in its final state shows the new spec reached the backend.
func eventuallyDirectoryQuotaApplied(storageID, quotaID string, spec regionopenapi.FileStorageDirectoryQuotaV2UpdateSpec, ruleStatuses ...coreapi.ResourceProvisioningStatus) *regionopenapi.FileStorageDirectoryQuotaV2Read {
	var quota *regionopenapi.FileStorageDirectoryQuotaV2Read

	Eventually(func(g Gomega) {
		read, err := regionClient.GetFileStorageDirectoryQuota(ctx, storageID, quotaID)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(read.Spec.Path).To(Equal(directoryQuotaPath))
		g.Expect(read.Spec.DirectoryLimits).To(Equal(spec.DirectoryLimits))
		g.Expect(read.Spec.DefaultUserLimits).To(Equal(spec.DefaultUserLimits))
		g.Expect(read.Spec.DefaultGroupLimits).To(Equal(spec.DefaultGroupLimits))
		g.Expect(read.Spec.Rules).To(Equal(spec.Rules))
		// Health is not asserted: the API does not yet promise when a quota is degraded.
		g.Expect(read.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))

		g.Expect(read.Status.Rules).NotTo(BeNil())
		g.Expect(*read.Status.Rules).To(HaveLen(len(ruleStatuses)))

		for i, status := range *read.Status.Rules {
			g.Expect(status.Subject).To(Equal((*spec.Rules)[i].Subject))
			g.Expect(status.ProvisioningStatus).To(Equal(ruleStatuses[i]), "rule %d (%s id=%d name=%q) message: %q", i, status.Subject.Kind, ptr.Deref(status.Subject.Id, 0), ptr.Deref(status.Subject.Name, ""), ptr.Deref(status.Message, ""))
		}

		quota = read
	}).WithTimeout(directoryQuotaTimeout).WithPolling(directoryQuotaPolling).Should(Succeed(), "directory quota and its rules should be applied on the storage backend")

	return quota
}

func mustDeleteDirectoryQuota(storageID, quotaID string) {
	err := regionClient.DeleteFileStorageDirectoryQuota(ctx, storageID, quotaID)
	Expect(err == nil || errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue(), "delete directory quota: %v", err)

	Eventually(func(g Gomega) {
		_, err := regionClient.GetFileStorageDirectoryQuota(ctx, storageID, quotaID)
		g.Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue(), "directory quota should no longer be readable: %v", err)
	}).WithTimeout(directoryQuotaTimeout).WithPolling(directoryQuotaPolling).Should(Succeed(), "directory quota deletion should complete")
}

var _ = Describe("File Storage directory quotas", func() {
	BeforeEach(func() {
		// Only staging runs the uni-storage quota controller.
		if config.Environment != "uat" {
			Skip("directory quotas need the uni-storage quota controller, which only runs on uat")
		}
	})

	Context("When managing a Directory Quota on a deployed region", func() {
		Describe("Given a provisioned NFS File Storage", func() {
			It("creates, provisions, reads, lists, updates and deletes the quota and its rules", func() {
				storageID := createProvisionedNFSTestStorage(&regionopenapi.NFSV2Spec{RootSquash: true}).Metadata.Id

				By("creating a Directory Quota with directory, default and uid/gid rule limits")

				tags := &coreapi.TagList{{Name: "environment", Value: "e2e"}}
				request := regionopenapi.FileStorageDirectoryQuotaV2Create{
					Metadata: coreapi.ResourceWriteMetadata{
						Name:        api.UniqueName("dirquota"),
						Description: ptr.To("Directory quota happy flow"),
						Tags:        tags,
					},
					Spec: regionopenapi.FileStorageDirectoryQuotaV2CreateSpec{
						Path:               directoryQuotaPath,
						DirectoryLimits:    directoryQuotaLimits(2*gib, 100000),
						DefaultUserLimits:  directoryQuotaLimits(gib, 10000),
						DefaultGroupLimits: directoryQuotaLimits(gib, 10000),
						Rules: &regionopenapi.FileStorageDirectoryQuotaRules{
							directoryQuotaRule(regionopenapi.FileStorageDirectoryQuotaSubjectKindUser, ptr.To(directoryQuotaRuleID), nil, gib/2, 5000),
							directoryQuotaRule(regionopenapi.FileStorageDirectoryQuotaSubjectKindGroup, ptr.To(directoryQuotaRuleID), nil, gib/2, 5000),
						},
					},
				}

				created, err := regionClient.CreateFileStorageDirectoryQuota(ctx, storageID, request)
				Expect(err).NotTo(HaveOccurred())

				quotaID := created.Metadata.Id
				deleted := false

				DeferCleanup(func() {
					if !deleted {
						mustDeleteDirectoryQuota(storageID, quotaID)
					}
				})

				Expect(uuid.Validate(quotaID)).To(Succeed())
				Expect(created.Metadata.Name).To(Equal(request.Metadata.Name))
				Expect(created.Metadata.Description).To(Equal(request.Metadata.Description))
				Expect(created.Metadata.Tags).To(Equal(tags))
				Expect(created.Metadata.OrganizationId).To(Equal(config.OrgID))
				Expect(created.Metadata.ProjectId).To(Equal(config.ProjectID))
				Expect(created.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusPending))
				Expect(created.Spec.FileStorageId.String()).To(Equal(storageID))
				Expect(created.Spec.Path).To(Equal(directoryQuotaPath))
				Expect(created.Spec.DirectoryLimits).To(Equal(request.Spec.DirectoryLimits))
				Expect(created.Spec.DefaultUserLimits).To(Equal(request.Spec.DefaultUserLimits))
				Expect(created.Spec.DefaultGroupLimits).To(Equal(request.Spec.DefaultGroupLimits))
				Expect(created.Spec.Rules).To(Equal(request.Spec.Rules))

				By("waiting for the quota and both rules to be provisioned")

				eventuallyDirectoryQuotaApplied(storageID, quotaID, regionopenapi.FileStorageDirectoryQuotaV2UpdateSpec{
					DirectoryLimits:    request.Spec.DirectoryLimits,
					DefaultUserLimits:  request.Spec.DefaultUserLimits,
					DefaultGroupLimits: request.Spec.DefaultGroupLimits,
					Rules:              request.Spec.Rules,
				}, coreapi.ResourceProvisioningStatusProvisioned, coreapi.ResourceProvisioningStatusProvisioned)

				By("waiting for the usage monitor to report directory usage")

				Eventually(func(g Gomega) {
					read, err := regionClient.GetFileStorageDirectoryQuota(ctx, storageID, quotaID)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(read.Status.Usage).NotTo(BeNil())
					g.Expect(read.Status.Usage.UpdatedAt).NotTo(BeNil())
					g.Expect(read.Status.Usage.UsedBytes).To(HaveValue(BeNumerically(">=", 0)))
					g.Expect(read.Status.Usage.UsedInodes).To(HaveValue(BeNumerically(">=", 0)))
				}).WithTimeout(directoryQuotaUsageTimeout).WithPolling(directoryQuotaPolling).Should(Succeed(), "directory usage should be reported")

				By("listing quotas, with and without a tag filter")

				Eventually(func(g Gomega) {
					g.Expect(directoryQuotaListIDs(g, storageID)).To(ConsistOf(quotaID))
					g.Expect(directoryQuotaListIDs(g, storageID, "environment=e2e")).To(ConsistOf(quotaID))
					g.Expect(directoryQuotaListIDs(g, storageID, "environment=production")).To(BeEmpty())
				}).WithTimeout(directoryQuotaTimeout).WithPolling(directoryQuotaPolling).Should(Succeed())

				By("raising the limits, replacing the rules and adding a rule for an unknown username")

				unknownUser := "e2e-missing-" + uuid.NewString()[:8]
				update := regionopenapi.FileStorageDirectoryQuotaV2Update{
					Metadata: request.Metadata,
					Spec: regionopenapi.FileStorageDirectoryQuotaV2UpdateSpec{
						DirectoryLimits:   directoryQuotaLimits(4*gib, 200000),
						DefaultUserLimits: request.Spec.DefaultUserLimits,
						Rules: &regionopenapi.FileStorageDirectoryQuotaRules{
							directoryQuotaRule(regionopenapi.FileStorageDirectoryQuotaSubjectKindUser, ptr.To(directoryQuotaRuleID), nil, gib, 8000),
							directoryQuotaRule(regionopenapi.FileStorageDirectoryQuotaSubjectKindUser, nil, ptr.To(unknownUser), gib/2, 5000),
						},
					},
				}

				var updated *regionopenapi.FileStorageDirectoryQuotaV2Read

				// The controller and usage monitor write the quota too, so the
				// optimistic lock can answer 409; the API documents it as retryable.
				Eventually(func() error {
					updated, err = regionClient.UpdateFileStorageDirectoryQuota(ctx, storageID, quotaID, update)

					return err
				}).WithTimeout(time.Minute).WithPolling(time.Second).Should(Succeed())

				Expect(updated.Metadata.Id).To(Equal(quotaID))
				Expect(updated.Spec.Path).To(Equal(directoryQuotaPath))
				Expect(updated.Spec.DirectoryLimits).To(Equal(update.Spec.DirectoryLimits))
				Expect(updated.Spec.DefaultUserLimits).To(Equal(update.Spec.DefaultUserLimits))
				Expect(updated.Spec.DefaultGroupLimits).To(BeNil())
				Expect(updated.Spec.Rules).To(Equal(update.Spec.Rules))

				By("waiting for the uid rule to apply and the unknown username to be reported as a rule error")

				quota := eventuallyDirectoryQuotaApplied(storageID, quotaID, update.Spec,
					coreapi.ResourceProvisioningStatusProvisioned, coreapi.ResourceProvisioningStatusError)
				Expect((*quota.Status.Rules)[0].Message).To(BeNil())
				Expect((*quota.Status.Rules)[1].Message).To(HaveValue(Equal("user or group not found")))

				By("deleting the quota and waiting for it to disappear")

				mustDeleteDirectoryQuota(storageID, quotaID)
				deleted = true

				Eventually(func(g Gomega) {
					g.Expect(directoryQuotaListIDs(g, storageID)).To(BeEmpty())
				}).WithTimeout(directoryQuotaTimeout).WithPolling(directoryQuotaPolling).Should(Succeed())
			})
		})
	})
})
