//go:build e2e
// +build e2e

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
	"fmt"
	"path"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/ptr"
)

const (
	manualSnapshotTimeout     = 5 * time.Minute
	manualSnapshotPolling     = 5 * time.Second
	manualSnapshotSSHTimeout  = 10 * time.Second
	manualSnapshotLifetime    = manualSnapshotTimeout + time.Minute
	manualRootProbeFilename   = "e2e-manual-root.txt"
	manualSubdirProbeFilename = "e2e-manual-subdir.txt"
	outsideProbeFilename      = "e2e-outside-subtree.txt"
)

type mountedManualSnapshot struct {
	Resource    *regionopenapi.FileStorageSnapshotV2Read
	SnapshotDir string
	Path        string
	ProbePath   string
	Observer    *api.SnapshotObserver
	visible     bool
	deleted     bool
}

func assertManualSnapshotCapture(mounted *mountedFileStorage, protectedPath string) {
	filename := manualRootProbeFilename
	if protectedPath != "" {
		filename = manualSubdirProbeFilename
	}

	probePath := path.Join(mounted.MountPoint, protectedPath, filename)
	content := "before-" + mounted.Storage.Metadata.Id + "-" + filename
	outsidePath := path.Join(mounted.MountPoint, outsideProbeFilename)
	outsideContent := "outside-" + mounted.Storage.Metadata.Id

	By("writing a probe before taking the manual snapshot")
	runSSHCommandExpectNoError(mounted.SSHClient, "sudo -n mkdir -p -- "+shellQuote(path.Dir(probePath)))
	MustWriteProbeFile(mounted.SSHClient, probePath, content)
	AssertProbeFileContent(mounted.SSHClient, probePath, content)

	if protectedPath != "" {
		MustWriteProbeFile(mounted.SSHClient, outsidePath, outsideContent)
		AssertProbeFileContent(mounted.SSHClient, outsidePath, outsideContent)
	}

	By("creating the manual snapshot and waiting for API readiness and captured content over NFS")

	snapshot := mustCreateMountedManualSnapshot(mounted, protectedPath, filename, content, nil, nil)

	By("changing the live file while the manual snapshot preserves its original contents")

	updatedContent := "after-" + mounted.Storage.Metadata.Id + "-" + filename
	MustWriteProbeFile(mounted.SSHClient, probePath, updatedContent)
	AssertProbeFileContent(mounted.SSHClient, probePath, updatedContent)
	AssertProbeFileContent(mounted.SSHClient, snapshot.ProbePath, content)

	if protectedPath != "" {
		By("confirming the snapshot excludes the existing probe outside the protected subtree")

		entries, err := mountedSnapshotEntries(mounted, snapshot.Path)
		Expect(err).NotTo(HaveOccurred(), "the exact snapshot directory must be readable")
		Expect(entries).NotTo(ContainElement(outsideProbeFilename))
		AssertProbeFileContent(mounted.SSHClient, outsidePath, outsideContent)
	}

	By("explicitly deleting the manual snapshot and waiting for API and NFS absence")
	mustDeleteMountedManualSnapshot(mounted, snapshot)
}

func assertManualSnapshotExpiration(mounted *mountedFileStorage) {
	Expect(config.RegionNamespace).NotTo(BeEmpty(), "TEST_REGION_NAMESPACE is required for direct snapshot CR observations")
	observer, err := api.NewSnapshotObserver(config.RegionNamespace)
	Expect(err).NotTo(HaveOccurred(), "configure read-only Kubernetes access to the same cluster as the Region API")

	By("creating a non-expiring control snapshot with its own captured probe")

	controlFilename := "e2e-expiration-control.txt"
	controlContent := "control-" + mounted.Storage.Metadata.Id
	MustWriteProbeFile(mounted.SSHClient, path.Join(mounted.MountPoint, controlFilename), controlContent)
	control := mustCreateMountedManualSnapshot(mounted, "", controlFilename, controlContent, nil, observer)
	controlCR, err := observer.GetSnapshot(ctx, control.Resource.Metadata.Id)
	Expect(err).NotTo(HaveOccurred(), "the observer must see the API-created control snapshot in the configured cluster and namespace")
	Expect(controlCR.Spec.FileStorageID.String()).To(Equal(mounted.Storage.Metadata.Id))
	Expect(controlCR.Spec.ExpirationTime).To(BeNil())
	Expect(controlCR.UID).NotTo(BeEmpty())

	By("creating a future-expiring snapshot and verifying its captured file before the deadline")

	filename := "e2e-expiring-probe.txt"
	content := "expiring-" + mounted.Storage.Metadata.Id
	MustWriteProbeFile(mounted.SSHClient, path.Join(mounted.MountPoint, filename), content)
	// Leave a full five-minute readiness/visibility budget plus a one-minute
	// observation margin. Expiration is immutable; do not extend it in the test.
	expiration := time.Now().UTC().Add(manualSnapshotLifetime).Truncate(time.Second)
	snapshot := mustCreateMountedManualSnapshot(mounted, "", filename, content, &expiration, observer)
	snapshotCR, err := observer.GetSnapshot(ctx, snapshot.Resource.Metadata.Id)
	Expect(err).NotTo(HaveOccurred())
	Expect(snapshotCR.Spec.FileStorageID.String()).To(Equal(mounted.Storage.Metadata.Id))
	Expect(snapshotCR.Spec.ExpirationTime).NotTo(BeNil())
	Expect(snapshotCR.Spec.ExpirationTime.Time).To(BeTemporally("==", expiration))
	Expect(snapshotCR.UID).NotTo(BeEmpty())
	Expect(snapshotCR.DeletionTimestamp.IsZero()).To(BeTrue())

	By("confirming the expiring snapshot remains available before its deadline")

	remaining := time.Until(expiration) - manualSnapshotPolling
	Expect(remaining).To(BeNumerically(">", 0), "snapshot readiness and NFS content must be observed before expiration")
	Consistently(func(g Gomega) {
		visible, err := regionClient.GetFileStorageSnapshot(ctx, mounted.Storage.Metadata.Id, snapshot.Resource.Metadata.Id)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(visible.Metadata.Id).To(Equal(snapshot.Resource.Metadata.Id))
		cr, err := observer.GetSnapshot(ctx, snapshot.Resource.Metadata.Id)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(cr.UID).To(Equal(snapshotCR.UID))
		g.Expect(cr.DeletionTimestamp.IsZero()).To(BeTrue())
		g.Expect(mountedProbeContent(mounted, snapshot.ProbePath)).To(Equal(content))
	}).WithTimeout(remaining).WithPolling(manualSnapshotPolling).Should(Succeed())

	By("waiting for actual CR removal and NFS disappearance without issuing DELETE")
	// Region hides expired snapshots even if the expirer is disabled. Observe
	// the CR independently; backend expiration by itself is also insufficient.
	mustEventuallyMountedSnapshotGone(mounted, snapshot, time.Until(expiration)+manualSnapshotTimeout)
	snapshot.deleted = true

	By("confirming the non-expiring control's original CR and captured content survive")

	controlRead, err := regionClient.GetFileStorageSnapshot(ctx, mounted.Storage.Metadata.Id, control.Resource.Metadata.Id)
	Expect(err).NotTo(HaveOccurred())
	Expect(controlRead.Metadata.Id).To(Equal(control.Resource.Metadata.Id))
	Expect(controlRead.Spec.ExpirationTime).To(BeNil())

	remainingCR, err := observer.GetSnapshot(ctx, control.Resource.Metadata.Id)
	Expect(err).NotTo(HaveOccurred())
	Expect(remainingCR.UID).To(Equal(controlCR.UID))
	Expect(remainingCR.DeletionTimestamp.IsZero()).To(BeTrue())
	AssertProbeFileContent(mounted.SSHClient, control.ProbePath, controlContent)

	By("explicitly deleting the non-expiring control")
	mustDeleteMountedManualSnapshot(mounted, control)
}

func mustCreateMountedManualSnapshot(mounted *mountedFileStorage, protectedPath, filename, content string, expiration *time.Time, observer *api.SnapshotObserver) *mountedManualSnapshot {
	request := regionopenapi.FileStorageSnapshotV2Create{
		Metadata: coreapi.ResourceWriteMetadata{Name: api.UniqueName("snapshot")},
		Spec:     regionopenapi.FileStorageSnapshotV2CreateSpec{ExpirationTime: expiration},
	}
	if protectedPath != "" {
		request.Spec.ProtectedPath = ptr.To(protectedPath)
	}

	snapshotDir := buildSnapshotDir(path.Join(mounted.MountPoint, protectedPath))
	created, err := regionClient.CreateFileStorageSnapshot(ctx, mounted.Storage.Metadata.Id, request)
	Expect(err).NotTo(HaveOccurred())
	Expect(created).NotTo(BeNil())

	snapshot := &mountedManualSnapshot{
		Resource:    created,
		SnapshotDir: snapshotDir,
		Path:        path.Join(snapshotDir, request.Metadata.Name),
		ProbePath:   path.Join(snapshotDir, request.Metadata.Name, filename),
		Observer:    observer,
	}

	DeferCleanup(func() {
		if !snapshot.deleted {
			mustDeleteMountedManualSnapshot(mounted, snapshot)
		}
	})

	Expect(created.Metadata.Id).NotTo(BeEmpty())
	Expect(created.Metadata.Name).To(Equal(request.Metadata.Name))
	Expect(created.Spec.FileStorageId.String()).To(Equal(mounted.Storage.Metadata.Id))
	Expect(created.Spec.ProtectedPath).To(Equal(request.Spec.ProtectedPath))
	Expect(created.Spec.ExpirationTime).To(Equal(expiration))

	expectedPath := path.Join(mounted.ExportPath, protectedPath)

	Eventually(func(g Gomega) {
		if expiration != nil {
			g.Expect(time.Now()).To(BeTemporally("<", *expiration), "must observe capture before expiration")
		}

		read, err := regionClient.GetFileStorageSnapshot(ctx, mounted.Storage.Metadata.Id, created.Metadata.Id)
		g.Expect(err).NotTo(HaveOccurred())
		snapshot.visible = true
		g.Expect(read.Metadata.Name).To(Equal(request.Metadata.Name))
		g.Expect(read.Spec.FileStorageId).To(Equal(created.Spec.FileStorageId))
		g.Expect(read.Spec.ProtectedPath).To(Equal(request.Spec.ProtectedPath))
		g.Expect(read.Spec.ExpirationTime).To(Equal(expiration))
		g.Expect(read.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
		g.Expect(read.Metadata.HealthStatus).To(Equal(coreapi.ResourceHealthStatusHealthy))
		g.Expect(read.Status.SnapshotTime).NotTo(BeNil())
		g.Expect(read.Status.SnapshotTime.IsZero()).To(BeFalse())
		g.Expect(read.Status.AbsoluteProtectedPath).NotTo(BeNil())
		// Agent accepts VAST's exact resolved path with an optional trailing slash;
		// do not normalize any other bytes of the provider observation.
		g.Expect(*read.Status.AbsoluteProtectedPath).To(BeElementOf(expectedPath, strings.TrimSuffix(expectedPath, "/")+"/"))
		entries, err := mountedSnapshotEntries(mounted, snapshotDir)
		g.Expect(err).NotTo(HaveOccurred(), "snapshot area must be accessible")
		g.Expect(entries).To(ContainElement(request.Metadata.Name))
		g.Expect(mountedProbeContent(mounted, snapshot.ProbePath)).To(Equal(content))
		snapshot.Resource = read
	}).WithTimeout(manualSnapshotTimeout).WithPolling(manualSnapshotPolling).Should(Succeed(), "manual snapshot should be ready with the expected captured file")

	return snapshot
}

func mustDeleteMountedManualSnapshot(mounted *mountedFileStorage, snapshot *mountedManualSnapshot) {
	// A fresh API create may not be readable through Region's cache yet. Establish
	// visibility before accepting an API 404 as cleanup on the fallback path.
	Eventually(func(g Gomega) {
		if !snapshot.visible && snapshot.Observer == nil {
			read, err := regionClient.GetFileStorageSnapshot(ctx, mounted.Storage.Metadata.Id, snapshot.Resource.Metadata.Id)
			g.Expect(err).NotTo(HaveOccurred(), "wait for the accepted create to reach Region's cache before cleanup")
			g.Expect(read.Metadata.Id).To(Equal(snapshot.Resource.Metadata.Id))
			snapshot.visible = true
		}

		err := regionClient.DeleteFileStorageSnapshot(ctx, mounted.Storage.Metadata.Id, snapshot.Resource.Metadata.Id)
		g.Expect(err == nil || errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue(), "delete snapshot: %v", err)
		assertMountedSnapshotGone(g, mounted, snapshot)
	}).WithTimeout(manualSnapshotTimeout).WithPolling(manualSnapshotPolling).Should(Succeed(), "manual snapshot deletion should complete")

	snapshot.deleted = true
}

func mustEventuallyMountedSnapshotGone(mounted *mountedFileStorage, snapshot *mountedManualSnapshot, timeout time.Duration) {
	Eventually(func(g Gomega) {
		g.Expect(time.Now()).To(BeTemporally(">=", *snapshot.Resource.Spec.ExpirationTime))
		assertMountedSnapshotGone(g, mounted, snapshot)
	}).WithTimeout(timeout).WithPolling(manualSnapshotPolling).Should(Succeed(), "expired snapshot CR and NFS directory should be removed within five minutes of expiration")
}

func assertMountedSnapshotGone(g Gomega, mounted *mountedFileStorage, snapshot *mountedManualSnapshot) {
	if snapshot.Observer != nil {
		_, err := snapshot.Observer.GetSnapshot(ctx, snapshot.Resource.Metadata.Id)
		g.Expect(apierrors.IsNotFound(err)).To(BeTrue(), "snapshot CR must actually be removed: %v", err)
	}

	_, err := regionClient.GetFileStorageSnapshot(ctx, mounted.Storage.Metadata.Id, snapshot.Resource.Metadata.Id)
	g.Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue(), "snapshot should no longer be readable: %v", err)
	entries, err := mountedSnapshotEntries(mounted, snapshot.SnapshotDir)
	g.Expect(err).NotTo(HaveOccurred(), "permission, SSH, or NFS errors must not count as snapshot absence")
	g.Expect(entries).NotTo(ContainElement(snapshot.Resource.Metadata.Name))
}

func mountedSnapshotEntries(mounted *mountedFileStorage, directory string) ([]string, error) {
	stdout, stderr, err := runSSHCommandReturnResult(mounted.SSHClient, "sudo -n ls -1A -- "+shellQuote(directory), manualSnapshotSSHTimeout)
	if err != nil {
		return nil, fmt.Errorf("listing snapshot directory %s (stderr: %s): %w", directory, stderr, err)
	}

	if stdout == "" {
		return nil, nil
	}

	return strings.Split(strings.TrimSuffix(stdout, "\n"), "\n"), nil
}

func mountedProbeContent(mounted *mountedFileStorage, filename string) (string, error) {
	stdout, stderr, err := runSSHCommandReturnResult(mounted.SSHClient, "sudo -n cat -- "+shellQuote(filename), manualSnapshotSSHTimeout)
	if err != nil {
		return "", fmt.Errorf("reading snapshot probe %s (stderr: %s): %w", filename, stderr, err)
	}

	return stdout, nil
}
