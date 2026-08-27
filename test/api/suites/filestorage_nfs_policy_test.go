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

//nolint:revive,testpackage,gci // dot imports and package naming standard for Ginkgo, import grouping
package suites

import (
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ssh"

	"k8s.io/utils/ptr"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
)

const (
	// nfsPolicyAtimeIntervalSeconds is the atime update threshold under test. A read
	// advances the server-side atime only when the stored atime is staler than this.
	nfsPolicyAtimeIntervalSeconds = int64(600)

	// nfsPolicyACLProbeUID is an arbitrary numeric principal for setfacl. The storage
	// backend stores and serves numeric entries, so no matching local user is needed.
	nfsPolicyACLProbeUID = 12345

	// nfsPolicyMountOptions pins NFSv3: extended POSIX ACLs are only manageable over
	// v3 (acl enables the NFSACL side protocol; setfacl over v4 always fails), and
	// actimeo=0 disables client attribute caching so stat reflects server-side atime.
	nfsPolicyMountOptions = "vers=3,proto=tcp,sec=sys,hard,acl,actimeo=0,lookupcache=none"

	nfsPolicyPropagationTimeout = 5 * time.Minute
	nfsPolicyPropagationPolling = 15 * time.Second
)

var _ = Describe("File Storage Management", func() {
	Context("When exercising NFS policy options against a mounted filesystem", func() {
		Describe("Given NFSv3 file storage with POSIX ACLs enabled and a 600-second atime interval", func() {
			It("persists the policy fields and enforces setfacl gating and the atime threshold", Label("slow"), func() {
				mounted := EventuallyProvisionMountedFilesystem(mountedFilesystemOptions{
					nfs: &regionopenapi.NFSV2Spec{
						PosixAcl:                   ptr.To(true),
						AtimeUpdateIntervalSeconds: ptr.To(nfsPolicyAtimeIntervalSeconds),
					},
					mountOptions: nfsPolicyMountOptions,
				})
				storageID := mounted.Storage.Metadata.Id

				By("verifying the NFS policy fields survived provisioning")
				provisioned, err := regionClient.GetFileStorage(ctx, storageID)
				Expect(err).NotTo(HaveOccurred())
				expectNFSPolicyValues(provisioned, false, true, nfsPolicyAtimeIntervalSeconds)

				By("verifying the list projection exposes the NFS policy fields")
				expectNFSPolicyValues(mustFindFileStorageInList(storageID), false, true, nfsPolicyAtimeIntervalSeconds)

				By("ensuring the instance has ACL tooling installed")
				mustEnsureACLTools(mounted.SSHClient)

				By("preparing a scratch directory owned by the SSH user")
				caseDir := path.Join(mounted.MountPoint, "nfs-policy-probes")
				runSSHCommandExpectNoError(mounted.SSHClient, fmt.Sprintf("sudo -n install -d -o %s -g %s %s", sshUsername, sshUsername, shellQuote(caseDir)))

				By("verifying setfacl succeeds while POSIX ACLs are enabled")
				aclFile := path.Join(caseDir, "acl-enabled-probe")
				runSSHCommandExpectNoError(mounted.SSHClient, fmt.Sprintf("touch %s && chmod 600 %s", shellQuote(aclFile), shellQuote(aclFile)))
				runSSHCommandExpectNoError(mounted.SSHClient, buildSetfaclCmd(aclFile))
				getfaclOutput := runSSHCommandExpectNoError(mounted.SSHClient, fmt.Sprintf("getfacl -n %s", shellQuote(aclFile)))
				Expect(getfaclOutput).To(ContainSubstring(fmt.Sprintf("user:%d:r--", nfsPolicyACLProbeUID)),
					"named ACL entry should be stored and served")

				By("verifying a read advances atime only when staler than the interval")
				atimeFile := path.Join(caseDir, "atime-probe")
				// 16 MiB forces real READ operations; a backdate beyond the interval is the
				// positive control, an immediate re-read inside the window the negative one.
				runSSHCommandExpectNoError(mounted.SSHClient, fmt.Sprintf("dd if=/dev/urandom of=%s bs=1M count=16 status=none && sync", shellQuote(atimeFile)))
				runSSHCommandExpectNoError(mounted.SSHClient, fmt.Sprintf("touch -a -d '15 minutes ago' %s && sync", shellQuote(atimeFile)))

				staleAtime := remoteFileAtimeEpoch(mounted.SSHClient, atimeFile)
				remoteNow := remoteEpochSeconds(mounted.SSHClient)
				Expect(remoteNow-staleAtime).To(BeNumerically(">", nfsPolicyAtimeIntervalSeconds),
					"backdated atime should be staler than the interval")

				directReadCmd := fmt.Sprintf("dd if=%s of=/dev/null bs=1M iflag=direct status=none", shellQuote(atimeFile))
				runSSHCommandExpectNoError(mounted.SSHClient, directReadCmd)
				refreshedAtime := remoteFileAtimeEpoch(mounted.SSHClient, atimeFile)
				Expect(refreshedAtime).To(BeNumerically(">", staleAtime), "read past the threshold should advance atime")
				Expect(refreshedAtime).To(BeNumerically(">=", remoteNow-60), "advanced atime should be close to now")

				// The 2-second gap makes a wrongly advancing atime visible at whole-second
				// stat resolution.
				runSSHCommandExpectNoError(mounted.SSHClient, "sleep 2 && "+directReadCmd)
				unchangedAtime := remoteFileAtimeEpoch(mounted.SSHClient, atimeFile)
				Expect(unchangedAtime).To(Equal(refreshedAtime), "read within the threshold window should not advance atime")

				By("disabling POSIX ACLs via update, resetting the omitted atime interval")
				// Attachments must be resent: an omitted attachment list detaches the
				// network and would break the live mount.
				update := regionopenapi.StorageV2UpdateRequest{
					Metadata: coreapi.ResourceWriteMetadata{
						Name: mounted.Storage.Metadata.Name,
					},
					Spec: regionopenapi.StorageV2Spec{
						Attachments: &regionopenapi.StorageAttachmentV2Spec{NetworkIds: []string{mounted.NetworkID}},
						SizeGiB:     storageSizeGiB,
						StorageType: regionopenapi.StorageTypeV2Spec{
							NFS: &regionopenapi.NFSV2Spec{PosixAcl: ptr.To(false)},
						},
					},
				}

				updated, err := regionClient.UpdateFileStorage(ctx, storageID, update)
				Expect(err).NotTo(HaveOccurred())
				expectNFSPolicyValues(updated, false, false, 0)

				By("waiting for the disabled POSIX ACL policy to propagate to the filesystem")
				disabledFile := path.Join(caseDir, "acl-disabled-probe")
				runSSHCommandExpectNoError(mounted.SSHClient, fmt.Sprintf("touch %s && chmod 600 %s", shellQuote(disabledFile), shellQuote(disabledFile)))

				Eventually(func() string {
					stdout, stderr, err := runSSHCommandReturnResult(mounted.SSHClient, buildSetfaclCmd(disabledFile), sshCmdTimeout)
					if err == nil {
						GinkgoWriter.Printf("setfacl still succeeds, waiting for policy propagation\nstdout:\n%s\n", stdout)
						return ""
					}

					return stderr
				}).WithTimeout(nfsPolicyPropagationTimeout).
					WithPolling(nfsPolicyPropagationPolling).
					Should(ContainSubstring("Operation not supported"),
						"setfacl should be rejected once POSIX ACL support is disabled")
			})
		})
	})
})

func buildSetfaclCmd(filePath string) string {
	return fmt.Sprintf("setfacl -m u:%d:r-- %s", nfsPolicyACLProbeUID, shellQuote(filePath))
}

func expectNFSPolicyValues(storage *regionopenapi.StorageV2Read, rootSquash, posixACL bool, atimeUpdateIntervalSeconds int64) {
	Expect(storage).NotTo(BeNil())
	Expect(storage.Spec.StorageType.NFS).NotTo(BeNil())
	Expect(storage.Spec.StorageType.NFS.RootSquash).To(Equal(rootSquash))
	// Pointer fields: guard against nil then compare dereferenced values (Equal
	// against a *bool silently fails on the type mismatch).
	Expect(storage.Spec.StorageType.NFS.PosixAcl).NotTo(BeNil())
	Expect(*storage.Spec.StorageType.NFS.PosixAcl).To(Equal(posixACL))
	Expect(storage.Spec.StorageType.NFS.AtimeUpdateIntervalSeconds).NotTo(BeNil())
	Expect(*storage.Spec.StorageType.NFS.AtimeUpdateIntervalSeconds).To(Equal(atimeUpdateIntervalSeconds))
}

func mustFindFileStorageInList(storageID string) *regionopenapi.StorageV2Read {
	list, err := regionClient.ListFileStorage(ctx, config.OrgID, config.ProjectID, config.RegionID)
	Expect(err).NotTo(HaveOccurred())

	for i := range list {
		if list[i].Metadata.Id == storageID {
			return &list[i]
		}
	}

	Fail(fmt.Sprintf("file storage %s not found in list response", storageID))

	return nil
}

// nfsPolicyACLToolsPresentCmd succeeds (exit 0) when the POSIX ACL utilities are installed.
const nfsPolicyACLToolsPresentCmd = "command -v setfacl >/dev/null 2>&1 && command -v getfacl >/dev/null 2>&1"

// mustEnsureACLTools installs the POSIX ACL utilities if not already present.
// The images these tests run on are Debian/Ubuntu, where they ship in the acl package.
func mustEnsureACLTools(client *ssh.Client) {
	if _, _, err := runSSHCommandReturnResult(client, nfsPolicyACLToolsPresentCmd, sshCmdTimeout); err == nil {
		return
	}

	install := "sudo -n apt-get update && sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y acl"
	stdout, stderr, err := runSSHCommandReturnResult(client, install, pkgInstallTimeout)
	Expect(err).NotTo(HaveOccurred(), "installing POSIX ACL utilities (acl)\nstdout:\n%s\nstderr:\n%s", stdout, stderr)

	runSSHCommandExpectNoError(client, nfsPolicyACLToolsPresentCmd)
}

func remoteFileAtimeEpoch(client *ssh.Client, filePath string) int64 {
	stdout := runSSHCommandExpectNoError(client, fmt.Sprintf("stat -c %%X %s", shellQuote(filePath)))

	epoch, err := strconv.ParseInt(strings.TrimSpace(stdout), 10, 64)
	Expect(err).NotTo(HaveOccurred(), "parsing atime epoch from stat output %q", stdout)

	return epoch
}

func remoteEpochSeconds(client *ssh.Client) int64 {
	stdout := runSSHCommandExpectNoError(client, "date +%s")

	epoch, err := strconv.ParseInt(strings.TrimSpace(stdout), 10, 64)
	Expect(err).NotTo(HaveOccurred(), "parsing epoch from date output %q", stdout)

	return epoch
}
