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
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"path"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ssh"

	"k8s.io/utils/ptr"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"
)

const (
	storageSizeGiB            = int64(1)
	sshUsername               = "cloud-user"
	sshConnectTimeout         = 15 * time.Minute
	sshCmdTimeout             = 2 * time.Minute
	pkgInstallTimeout         = 5 * time.Minute
	resourceWatchTimeout      = 20 * time.Minute
	snapshotVisibilityTimeout = 75 * time.Minute
	snapshotFolderName        = ".snapshot"
	snapshotPolicyName        = "e2e-hourly"
	probeFilename             = "e2e-probe.txt"
)

var _ = Describe("File storage snapshot happy flow", func() {
	Context("When mounting file storage from a running instance", func() {
		Describe("Given an OpenStack network, server, and NFS file storage attachment", func() {
			It("captures probe file contents in an hourly scheduled snapshot", Label("slow"), func() {
				policies := buildHourlySnapshotPolicy()
				mounted := EventuallyProvisionMountedFilesystem(&policies)
				probePath := path.Join(mounted.MountPoint, probeFilename)
				probeContent := "probe-" + mounted.Storage.Metadata.Id

				By("writing a probe file to the mounted storage and reading it back")
				MustWriteProbeFile(mounted.SSHClient, probePath, probeContent)
				AssertProbeFileContent(mounted.SSHClient, probePath, probeContent)

				By("waiting for the scheduled hourly snapshot to capture the probe file — no output until it appears, and it can take up to the snapshot interval")
				snapshotDir := buildSnapshotDir(mounted.MountPoint)
				snapshotPath := MustEventuallyFindSnapshottedProbeFile(mounted.SSHClient, snapshotDir, probePath)
				GinkgoWriter.Printf("Found scheduled snapshot containing probe data: %s\n", snapshotPath)
			})
		})
	})
})

type mountedFileStorage struct {
	Storage    *regionopenapi.StorageV2Read
	SSHClient  *ssh.Client
	MountPoint string
}

func mustFindNFSFileStorageClassID() string {
	storageClasses, err := regionClient.ListFileStorageClasses(ctx, config.RegionID)
	Expect(err).NotTo(HaveOccurred(), "failed to list storage classes")

	for _, storageClass := range storageClasses {
		for _, protocol := range storageClass.Spec.Protocols {
			if protocol == regionopenapi.StorageClassProtocolTypeNfsv3 || protocol == regionopenapi.StorageClassProtocolTypeNfsv4 {
				return storageClass.Metadata.Id
			}
		}
	}

	Skip(fmt.Sprintf("no NFS file storage classes allocated to region %s", config.RegionID))

	return ""
}

func EventuallySecurityGroupVisible(securityGroupID string) {
	Eventually(func() error {
		_, err := regionClient.GetSecurityGroup(ctx, securityGroupID)
		return err
	}).WithTimeout(10*time.Second).
		WithPolling(250*time.Millisecond).
		Should(Succeed(), "security group should become visible at the API")
}

func MustCreateSecurityGroup(networkID string) (*regionopenapi.SecurityGroupV2Read, func()) {
	sshPort := 22
	securityGroupRequest := api.NewSecurityGroupPayload(networkID).
		WithRules(regionopenapi.SecurityGroupRuleV2List{
			{
				Direction: regionopenapi.NetworkDirectionIngress,
				Protocol:  regionopenapi.NetworkProtocolTcp,
				Port:      &sshPort,
			},
			{
				Direction: regionopenapi.NetworkDirectionEgress,
				Protocol:  regionopenapi.NetworkProtocolAny,
			},
		}).
		Build()

	securityGroup, err := regionClient.CreateSecurityGroup(ctx, securityGroupRequest)
	Expect(err).NotTo(HaveOccurred(), "failed to create security group fixture")
	Expect(securityGroup).NotTo(BeNil())

	cleanup := func() {
		if err := regionClient.DeleteSecurityGroup(ctx, securityGroup.Metadata.Id); err != nil && !errors.Is(err, coreclient.ErrResourceNotFound) {
			GinkgoWriter.Printf("Warning: cleanup delete security group %s: %v\n", securityGroup.Metadata.Id, err)
		}
	}

	EventuallySecurityGroupVisible(securityGroup.Metadata.Id)

	return securityGroup, cleanup
}

func buildHourlySnapshotPolicy() regionopenapi.StorageSnapshotPolicyListV2Spec {
	return regionopenapi.StorageSnapshotPolicyListV2Spec{
		{
			Name: snapshotPolicyName,
			Schedule: regionopenapi.StorageSnapshotScheduleV2Spec{
				Interval: regionopenapi.StorageSnapshotScheduleIntervalV2Hourly,
			},
			Retention: regionopenapi.StorageSnapshotRetentionV2Spec{Keep: 2},
		},
	}
}

// MustProvisionFileStorage creates NFS file storage attached to networkID, registers
// cleanup immediately, waits for a mountable attachment, and when snapshotPolicies is
// set, waits for the snapshot policy to be provisioned.
func MustProvisionFileStorage(storageClassID, networkID string, snapshotPolicies *regionopenapi.StorageSnapshotPolicyListV2Spec) (*regionopenapi.StorageV2Read, regionopenapi.StorageAttachmentV2Status) {
	request := api.NewFileStoragePayload(config.OrgID, config.ProjectID, config.RegionID, storageClassID, networkID).
		WithSizeGiB(storageSizeGiB).
		WithSnapshotPolicies(snapshotPolicies).
		Build()

	storage, err := regionClient.CreateFileStorage(ctx, request)
	Expect(err).NotTo(HaveOccurred(), "failed to create file storage fixture")
	Expect(storage).NotTo(BeNil())

	cleanup := func() {
		if err := regionClient.DeleteFileStorage(ctx, storage.Metadata.Id); err != nil {
			GinkgoWriter.Printf("Warning: cleanup delete file storage %s: %v\n", storage.Metadata.Id, err)
			return
		}

		api.WaitForFileStorageGone(regionClient, ctx, storage.Metadata.Id)
	}
	DeferCleanup(cleanup)

	var attachment regionopenapi.StorageAttachmentV2Status

	Eventually(func(g Gomega) {
		got, err := regionClient.GetFileStorage(ctx, storage.Metadata.Id)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(got.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
		g.Expect(got.Status.Attachments).NotTo(BeNil())

		foundAttachment := false
		for _, candidate := range *got.Status.Attachments {
			if candidate.NetworkId != networkID {
				continue
			}

			attachment = candidate
			foundAttachment = true
			break
		}

		g.Expect(foundAttachment).To(BeTrue(), "storage attachment for network should be present")
		g.Expect(attachment.MountSource).NotTo(BeNil(), "storage attachment should expose mountSource")
		g.Expect(*attachment.MountSource).NotTo(BeEmpty(), "storage attachment mountSource should be populated")
	}).WithTimeout(resourceWatchTimeout).
		WithPolling(15*time.Second).
		Should(Succeed(), "file storage should become mountable")

	if snapshotPolicies != nil {
		EventuallyProvisionSnapshotPolicy(storage.Metadata.Id)
	}

	return storage, attachment
}

func EventuallyProvisionSnapshotPolicy(storageID string) {
	Eventually(func(g Gomega) {
		storage, err := regionClient.GetFileStorage(ctx, storageID)
		g.Expect(err).NotTo(HaveOccurred())

		foundPolicy := false
		for _, policy := range storage.Status.SnapshotPolicies {
			if policy.Name != snapshotPolicyName {
				continue
			}

			foundPolicy = true
			g.Expect(policy.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
			break
		}

		g.Expect(foundPolicy).To(BeTrue(), "user-managed snapshot policy should be present in status")
	}).WithTimeout(resourceWatchTimeout).
		WithPolling(15*time.Second).
		Should(Succeed(), "file storage snapshot policy should become provisioned")
}

// MustProvisionServer creates a server on the network with the given security group and
// waits until it is running with a public IP for SSH. It returns the server and a cleanup
// func the caller should register (e.g. DeferCleanup(cleanup)).
func MustProvisionServer(networkID, securityGroupID string) (*regionopenapi.ServerV2Read, func()) {
	securityGroups := regionopenapi.ServerV2SecurityGroupIDList{securityGroupID}
	request := api.NewServerPayload(networkID, config.ServerFlavorID, config.ServerImageID).
		WithNetworking(&regionopenapi.ServerV2Networking{
			PublicIP:       ptr.To(true),
			SecurityGroups: &securityGroups,
		}).
		Build()

	created, cleanup := api.MustCreateServer(regionClient, ctx, request)

	var server *regionopenapi.ServerV2Read

	Eventually(func(g Gomega) {
		var err error
		server, err = regionClient.GetServer(ctx, created.Metadata.Id)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(server.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
		g.Expect(server.Status.PowerState).NotTo(BeNil())
		g.Expect(*server.Status.PowerState).To(Equal(regionopenapi.InstanceLifecyclePhaseRunning))
		g.Expect(server.Status.PublicIP).NotTo(BeNil(), "server should have a public IP for SSH")
		g.Expect(*server.Status.PublicIP).NotTo(BeEmpty(), "server public IP should be populated")
	}).WithTimeout(resourceWatchTimeout).
		WithPolling(15*time.Second).
		Should(Succeed(), "server should become running and reachable by public IP")

	return server, cleanup
}

func EventuallyDialSSHConn(ctx context.Context, host, privateKey string) *ssh.Client {
	signer, err := ssh.ParsePrivateKey([]byte(privateKey))
	Expect(err).NotTo(HaveOccurred(), "failed to parse server SSH private key")

	sshConfig := &ssh.ClientConfig{
		User: sshUsername,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // Test-created hosts do not expose host keys through the API.
		Timeout:         10 * time.Second,
	}

	address := net.JoinHostPort(host, "22")
	var client *ssh.Client

	Eventually(func() error {
		var dialErr error
		client, dialErr = ssh.Dial("tcp", address, sshConfig)
		return dialErr
	}).WithContext(ctx).
		WithTimeout(sshConnectTimeout).
		WithPolling(10*time.Second).
		Should(Succeed(), "server should accept SSH connections")

	return client
}

func runSSHCommandReturnResult(client *ssh.Client, command string, timeout time.Duration) (string, string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("creating SSH session: %w", err)
	}

	defer session.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	if err := session.Start(command); err != nil {
		return stdout.String(), stderr.String(), fmt.Errorf("starting remote command %q: %w", command, err)
	}

	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-done:
		return stdout.String(), stderr.String(), err
	case <-timer.C:
		_ = session.Close()
		return stdout.String(), stderr.String(), fmt.Errorf("remote command timed out after %s", timeout)
	}
}

func runSSHCommandExpectNoError(client *ssh.Client, command string) string {
	stdout, stderr, err := runSSHCommandReturnResult(client, command, sshCmdTimeout)
	Expect(err).NotTo(HaveOccurred(), "remote command failed: %s\nstdout:\n%s\nstderr:\n%s", command, stdout, stderr)

	return stdout
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// buildMountCmd mounts the export with plain NFS defaults. The API-provided
// status.attachments[].mountOptions (e.g. remoteports) are provider/multipath
// specific and unsupported by the stock nfs-common client on the test image; the
// mountSource alone mounts fine and is all the snapshot test needs.
func buildMountCmd(mountSource, mountPoint string) string {
	quotedMountSource := shellQuote(mountSource)
	quotedMountPoint := shellQuote(mountPoint)

	return fmt.Sprintf("sudo -n mkdir -p %s && sudo -n mount -t nfs %s %s", quotedMountPoint, quotedMountSource, quotedMountPoint)
}

func buildSnapshotDir(mountPoint string) string {
	snapshotFolder := strings.Trim(config.FileStorageSnapshotDir, "/")
	if snapshotFolder == "" {
		snapshotFolder = snapshotFolderName
	}

	snapshotFolder = path.Clean(snapshotFolder)
	if snapshotFolder == "." || snapshotFolder == ".." || strings.HasPrefix(snapshotFolder, "../") || path.IsAbs(snapshotFolder) {
		Fail(fmt.Sprintf("TEST_FILE_STORAGE_SNAPSHOT_DIR must be a non-empty relative path inside the mount, got %q", config.FileStorageSnapshotDir))
	}

	snapshotDir := path.Join(mountPoint, snapshotFolder)

	return snapshotDir
}

// e2eNFSClientPresentCmd succeeds (exit 0) when an NFS mount helper is installed.
const e2eNFSClientPresentCmd = "command -v mount.nfs >/dev/null 2>&1 || command -v mount.nfs4 >/dev/null 2>&1"

// MustEnsureNFSClient installs the NFS mount helper if it is not already present.
// The images these tests run on are Debian/Ubuntu, where the client ships in nfs-common.
func MustEnsureNFSClient(client *ssh.Client) {
	if _, _, err := runSSHCommandReturnResult(client, e2eNFSClientPresentCmd, sshCmdTimeout); err == nil {
		return
	}

	install := "sudo -n apt-get update && sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y nfs-common"
	stdout, stderr, err := runSSHCommandReturnResult(client, install, pkgInstallTimeout)
	Expect(err).NotTo(HaveOccurred(), "installing NFS client (nfs-common)\nstdout:\n%s\nstderr:\n%s", stdout, stderr)

	runSSHCommandExpectNoError(client, e2eNFSClientPresentCmd)
}

func MustPreflightInstance(client *ssh.Client) {
	runSSHCommandExpectNoError(client, "sudo -n true")
	MustEnsureNFSClient(client)
}

func MustWriteProbeFile(client *ssh.Client, probePath, content string) {
	runSSHCommandExpectNoError(client, fmt.Sprintf("printf %%s %s | sudo -n tee %s >/dev/null", shellQuote(content), shellQuote(probePath)))
}

func AssertProbeFileContent(client *ssh.Client, probePath, content string) {
	runSSHCommandExpectNoError(client, fmt.Sprintf("test \"$(sudo -n cat %s)\" = %s", shellQuote(probePath), shellQuote(content)))
}

func EventuallyProvisionMountedFilesystem(snapshotPolicies *regionopenapi.StorageSnapshotPolicyListV2Spec) *mountedFileStorage {
	api.SkipUnlessOpenStackRegion(regionClient, ctx, config)
	api.SkipUnlessInternalAPIConfigured(regionClient)
	api.SkipUnlessServerFixtureConfigured(config)

	By("selecting an NFS-capable file storage class")
	storageClassID := mustFindNFSFileStorageClassID()

	By("provisioning a network and an SSH-ingress security group")
	networkReq := api.NewNetworkPayload(config.OrgID, config.ProjectID, config.RegionID).Build()
	network, cleanupNetwork := api.MustProvisionNetwork(regionClient, ctx, networkReq)
	DeferCleanup(cleanupNetwork)
	securityGroup, cleanupSecurityGroup := MustCreateSecurityGroup(network.Metadata.Id)
	DeferCleanup(cleanupSecurityGroup)

	By("creating the NFS file storage and waiting for a mountable attachment")
	storage, attachment := MustProvisionFileStorage(storageClassID, network.Metadata.Id, snapshotPolicies)

	By("provisioning a server and waiting for it to run with a public IP")
	server, cleanupServer := MustProvisionServer(network.Metadata.Id, securityGroup.Metadata.Id)
	DeferCleanup(cleanupServer)

	By("retrieving the server's generated SSH key")
	key, err := regionClient.GetServerSSHKey(ctx, server.Metadata.Id)
	Expect(err).NotTo(HaveOccurred(), "failed to retrieve server SSH key")
	Expect(key.PrivateKey).NotTo(BeEmpty(), "server SSH private key should be populated")

	By("opening an SSH connection to the server")
	sshClient := EventuallyDialSSHConn(ctx, *server.Status.PublicIP, key.PrivateKey)
	DeferCleanup(func() {
		if err := sshClient.Close(); err != nil {
			GinkgoWriter.Printf("Warning: cleanup close SSH client for server %s: %v\n", server.Metadata.Id, err)
		}
	})

	By("ensuring the instance has an NFS client installed")
	MustPreflightInstance(sshClient)

	By("mounting the file storage over NFS")
	mountPoint := path.Join("/mnt", string(storage.Metadata.Name))
	mountSource := *attachment.MountSource
	runSSHCommandExpectNoError(sshClient, buildMountCmd(mountSource, mountPoint))
	DeferCleanup(func() {
		runSSHCommandExpectNoError(sshClient, fmt.Sprintf("sudo -n umount %s && sudo -n rmdir %s", shellQuote(mountPoint), shellQuote(mountPoint)))
	})

	return &mountedFileStorage{
		Storage:    storage,
		SSHClient:  sshClient,
		MountPoint: mountPoint,
	}
}

func MustEventuallyFindSnapshottedProbeFile(client *ssh.Client, snapshotDir, probePath string) string {
	var snapshotPath string
	command := fmt.Sprintf(`live=$(sudo -n cat %s) || exit 1
for snapshot in %s/%s-*; do
  [ -d "$snapshot" ] || continue
  snapshot_file="$snapshot/%s"
  [ -f "$snapshot_file" ] || continue
  snapshot_content=$(sudo -n cat "$snapshot_file") || continue
  if [ "$snapshot_content" = "$live" ]; then
    printf '%%s\n' "$snapshot"
    exit 0
  fi
done
exit 1`,
		shellQuote(probePath),
		shellQuote(snapshotDir),
		snapshotPolicyName,
		probeFilename)

	Eventually(func() string {
		stdout, _, err := runSSHCommandReturnResult(client, command, sshCmdTimeout)
		if err != nil {
			return ""
		}

		snapshotPath = strings.TrimSpace(stdout)
		return snapshotPath
	}).WithTimeout(snapshotVisibilityTimeout).
		WithPolling(30*time.Second).
		ShouldNot(BeEmpty(), "scheduled snapshot should contain the live probe file contents")

	return snapshotPath
}
