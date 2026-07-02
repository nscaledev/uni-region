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
	"sort"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ssh"

	"k8s.io/utils/ptr"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	coreutil "github.com/unikorn-cloud/core/pkg/testing/util"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"
)

const (
	e2eStorageSizeGiB            = int64(10)
	e2eSSHUser                   = "cloud-user"
	e2eSSHConnectTimeout         = 15 * time.Minute
	e2eSSHCommandTimeout         = 2 * time.Minute
	e2eCloudInitTimeout          = 10 * time.Minute
	e2eResourceTimeout           = 20 * time.Minute
	e2eSnapshotVisibilityTimeout = 75 * time.Minute
	e2eSnapshotPollingInterval   = 30 * time.Second
	e2eStorageSnapshotDir        = ".snapshot"
	e2eStorageSnapshotPolicyName = "e2e-hourly"
	e2eProbeFileName             = "e2e-probe.txt"
)

// e2eNFSCloudConfig is cloud-init user data that installs the NFS client
// (nfs-utils on the RHEL-family images these tests use) on first boot, so the
// instance can mount the file-storage export over NFS.
const e2eNFSCloudConfig = `#cloud-config
package_update: true
packages:
  - nfs-utils
`

type e2eMountedFileStorage struct {
	Storage    *regionopenapi.StorageV2Read
	SSHClient  *ssh.Client
	MountPoint string
}

func e2eSkipUnlessOpenStackRegion() {
	regions, err := regionClient.ListRegions(ctx, config.OrgID)
	Expect(err).NotTo(HaveOccurred(), "failed to resolve region provider")

	for _, region := range regions {
		if region.Metadata.Id != config.RegionID {
			continue
		}

		if region.Spec.Type != regionopenapi.RegionTypeOpenstack {
			Skip("file-storage mount e2e requires an OpenStack-backed region")
		}

		return
	}

	Skip("file-storage mount e2e requires TEST_REGION_ID to be visible")
}

func e2eSkipUnlessInternalAPIConfigured() {
	if !regionClient.InternalAPIConfigured() {
		Skip("file-storage mount e2e requires local internal API mTLS credentials")
	}
}

func e2eSkipUnlessServerFixtureConfigured() {
	if config.ServerFlavorID == "" || config.ServerImageID == "" {
		Skip("file-storage mount e2e requires TEST_SERVER_FLAVOR_ID and TEST_SERVER_IMAGE_ID")
	}
}

func e2eRequireNFSFileStorageClassID() string {
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

func e2eWaitForNetworkProvisioned(networkID string) {
	Eventually(func() coreapi.ResourceProvisioningStatus {
		network, err := regionClient.GetNetwork(ctx, networkID)
		if err != nil {
			GinkgoWriter.Printf("Error retrieving network %s: %v\n", networkID, err)
			return ""
		}

		return network.Metadata.ProvisioningStatus
	}).WithTimeout(5*time.Minute).
		WithPolling(5*time.Second).
		Should(Equal(coreapi.ResourceProvisioningStatusProvisioned), "network should be provisioned")
}

func e2eWaitForSecurityGroupVisible(securityGroupID string) {
	Eventually(func() error {
		_, err := regionClient.GetSecurityGroup(ctx, securityGroupID)
		return err
	}).WithTimeout(10*time.Second).
		WithPolling(250*time.Millisecond).
		Should(Succeed(), "security group should become visible at the API")
}

func e2eWaitForServerGone(serverID string) {
	Eventually(func() error {
		_, err := regionClient.GetServer(ctx, serverID)
		if errors.Is(err, coreclient.ErrResourceNotFound) {
			return nil
		}
		if err != nil {
			return err
		}

		return fmt.Errorf("server %s still exists", serverID)
	}).WithTimeout(10*time.Minute).
		WithPolling(10*time.Second).
		Should(Succeed(), "server should disappear after deletion")
}

func e2eWaitForFileStorageDeleted(filestorageID string) {
	Eventually(func() error {
		_, err := regionClient.GetFileStorage(ctx, filestorageID)
		if errors.Is(err, coreclient.ErrResourceNotFound) {
			return nil
		}
		if err != nil {
			return err
		}

		return fmt.Errorf("file storage %s still exists", filestorageID)
	}).WithTimeout(10*time.Minute).
		WithPolling(10*time.Second).
		Should(Succeed(), "file storage should be deleted")
}

func e2eCreateNetwork() *regionopenapi.NetworkV2Read {
	network, err := regionClient.CreateNetwork(ctx, api.NewNetworkPayload(config.OrgID, config.ProjectID, config.RegionID).Build())
	Expect(err).NotTo(HaveOccurred(), "failed to create network fixture")
	Expect(network).NotTo(BeNil())

	DeferCleanup(func() {
		if err := regionClient.DeleteNetwork(ctx, network.Metadata.Id); err != nil && !errors.Is(err, coreclient.ErrResourceNotFound) {
			GinkgoWriter.Printf("Warning: cleanup delete network %s: %v\n", network.Metadata.Id, err)
		}
	})

	api.WaitForNetworkVisible(regionClient, ctx, network.Metadata.Id)
	e2eWaitForNetworkProvisioned(network.Metadata.Id)

	return network
}

func e2eCreateSecurityGroup(networkID string) *regionopenapi.SecurityGroupV2Read {
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

	DeferCleanup(func() {
		if err := regionClient.DeleteSecurityGroup(ctx, securityGroup.Metadata.Id); err != nil && !errors.Is(err, coreclient.ErrResourceNotFound) {
			GinkgoWriter.Printf("Warning: cleanup delete security group %s: %v\n", securityGroup.Metadata.Id, err)
		}
	})

	e2eWaitForSecurityGroupVisible(securityGroup.Metadata.Id)

	return securityGroup
}

func e2eHourlySnapshotPolicies() regionopenapi.StorageSnapshotPolicyListV2Spec {
	return regionopenapi.StorageSnapshotPolicyListV2Spec{
		{
			Name: e2eStorageSnapshotPolicyName,
			Schedule: regionopenapi.StorageSnapshotScheduleV2Spec{
				Interval: regionopenapi.StorageSnapshotScheduleIntervalV2Hourly,
			},
			Retention: regionopenapi.StorageSnapshotRetentionV2Spec{Keep: 2},
		},
	}
}

func e2eCreateFileStorage(storageClassID, networkID string, snapshotPolicies *regionopenapi.StorageSnapshotPolicyListV2Spec) *regionopenapi.StorageV2Read {
	storageName := coreutil.GenerateRandomName("test-mount-storage")

	request := regionopenapi.StorageV2CreateRequest{
		Metadata: coreapi.ResourceWriteMetadata{
			Name:        storageName,
			Description: ptr.To("E2E file storage mounted from a server over NFS"),
		},
		Spec: struct {
			Attachments                      *regionopenapi.StorageAttachmentV2Spec         `json:"attachments,omitempty"`
			DefaultSnapshotProtectionEnabled *bool                                          `json:"defaultSnapshotProtectionEnabled,omitempty"`
			OrganizationId                   string                                         `json:"organizationId"`
			ProjectId                        string                                         `json:"projectId"`
			RegionId                         regionopenapi.RegionId                         `json:"regionId"`
			SizeGiB                          int64                                          `json:"sizeGiB"`
			SnapshotPolicies                 *regionopenapi.StorageSnapshotPolicyListV2Spec `json:"snapshotPolicies,omitempty"`
			StorageClassId                   string                                         `json:"storageClassId"`
			StorageType                      regionopenapi.StorageTypeV2Spec                `json:"storageType"`
		}{
			Attachments: &regionopenapi.StorageAttachmentV2Spec{
				NetworkIds: []string{networkID},
			},
			DefaultSnapshotProtectionEnabled: ptr.To(false),
			OrganizationId:                   config.OrgID,
			ProjectId:                        config.ProjectID,
			RegionId:                         regionids.MustParseRegionID(config.RegionID),
			SizeGiB:                          e2eStorageSizeGiB,
			SnapshotPolicies:                 snapshotPolicies,
			StorageClassId:                   storageClassID,
			StorageType: regionopenapi.StorageTypeV2Spec{
				NFS: &regionopenapi.NFSV2Spec{},
			},
		},
	}

	storage, err := regionClient.CreateFileStorage(ctx, request)
	Expect(err).NotTo(HaveOccurred(), "failed to create file storage fixture")
	Expect(storage).NotTo(BeNil())

	DeferCleanup(func() {
		if err := regionClient.DeleteFileStorage(ctx, storage.Metadata.Id); err != nil {
			GinkgoWriter.Printf("Warning: cleanup delete file storage %s: %v\n", storage.Metadata.Id, err)
			return
		}

		e2eWaitForFileStorageDeleted(storage.Metadata.Id)
	})

	return storage
}

func e2eWaitForFileStorageMount(storageID, networkID string) regionopenapi.StorageAttachmentV2Status {
	var attachment regionopenapi.StorageAttachmentV2Status

	Eventually(func(g Gomega) {
		storage, err := regionClient.GetFileStorage(ctx, storageID)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(storage.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
		g.Expect(storage.Status.Attachments).NotTo(BeNil())

		foundAttachment := false
		for _, candidate := range *storage.Status.Attachments {
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
	}).WithTimeout(e2eResourceTimeout).
		WithPolling(15*time.Second).
		Should(Succeed(), "file storage should become mountable")

	return attachment
}

func e2eWaitForSnapshotPolicyProvisioned(storageID string) {
	Eventually(func(g Gomega) {
		storage, err := regionClient.GetFileStorage(ctx, storageID)
		g.Expect(err).NotTo(HaveOccurred())

		foundPolicy := false
		for _, policy := range storage.Status.SnapshotPolicies {
			if policy.Name != e2eStorageSnapshotPolicyName {
				continue
			}

			foundPolicy = true
			g.Expect(policy.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
			break
		}

		g.Expect(foundPolicy).To(BeTrue(), "user-managed snapshot policy should be present in status")
	}).WithTimeout(e2eResourceTimeout).
		WithPolling(15*time.Second).
		Should(Succeed(), "file storage snapshot policy should become provisioned")
}

func e2eCreateServer(networkID, securityGroupID string) *regionopenapi.ServerV2Read {
	securityGroups := regionopenapi.ServerV2SecurityGroupIDList{securityGroupID}
	request := api.NewServerPayload(networkID, config.ServerFlavorID, config.ServerImageID).
		WithNetworking(&regionopenapi.ServerV2Networking{
			PublicIP:       ptr.To(true),
			SecurityGroups: &securityGroups,
		}).
		WithUserData([]byte(e2eNFSCloudConfig)).
		Build()

	server, err := regionClient.CreateServer(ctx, request)
	Expect(err).NotTo(HaveOccurred(), "failed to create server fixture")
	Expect(server).NotTo(BeNil())

	DeferCleanup(func() {
		err := regionClient.DeleteServer(ctx, server.Metadata.Id)
		if errors.Is(err, coreclient.ErrResourceNotFound) {
			return
		}
		if err != nil {
			GinkgoWriter.Printf("Warning: cleanup delete server %s: %v\n", server.Metadata.Id, err)
			return
		}

		e2eWaitForServerGone(server.Metadata.Id)
	})

	return server
}

func e2eWaitForServerReady(serverID string) *regionopenapi.ServerV2Read {
	var server *regionopenapi.ServerV2Read

	Eventually(func(g Gomega) {
		var err error
		server, err = regionClient.GetServer(ctx, serverID)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(server.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
		g.Expect(server.Status.PowerState).NotTo(BeNil())
		g.Expect(*server.Status.PowerState).To(Equal(regionopenapi.InstanceLifecyclePhaseRunning))
		g.Expect(server.Status.PublicIP).NotTo(BeNil(), "server should have a public IP for SSH")
		g.Expect(*server.Status.PublicIP).NotTo(BeEmpty(), "server public IP should be populated")
	}).WithTimeout(e2eResourceTimeout).
		WithPolling(15*time.Second).
		Should(Succeed(), "server should become running and reachable by public IP")

	return server
}

func e2eDialSSH(ctx context.Context, host, privateKey string) *ssh.Client {
	signer, err := ssh.ParsePrivateKey([]byte(privateKey))
	Expect(err).NotTo(HaveOccurred(), "failed to parse server SSH private key")

	sshConfig := &ssh.ClientConfig{
		User: e2eSSHUser,
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
		WithTimeout(e2eSSHConnectTimeout).
		WithPolling(10*time.Second).
		Should(Succeed(), "server should accept SSH connections")

	return client
}

func e2eRunSSHCommandResult(client *ssh.Client, command string, timeout time.Duration) (string, string, error) {
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

func e2eRunSSHCommand(client *ssh.Client, command string) string {
	stdout, stderr, err := e2eRunSSHCommandResult(client, command, e2eSSHCommandTimeout)
	Expect(err).NotTo(HaveOccurred(), "remote command failed: %s\nstdout:\n%s\nstderr:\n%s", command, stdout, stderr)

	return stdout
}

func e2eShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// e2eMountOptions derives the NFS mount options from the storage attachment
// reported by the Region API (status.attachments[].mountOptions), which is the
// authoritative source for how the export must be mounted (e.g. remoteports).
func e2eMountOptions(attachment regionopenapi.StorageAttachmentV2Status) string {
	if attachment.MountOptions == nil || len(*attachment.MountOptions) == 0 {
		return ""
	}

	options := make([]string, 0, len(*attachment.MountOptions))
	for key, value := range *attachment.MountOptions {
		options = append(options, fmt.Sprintf("%s=%s", key, value))
	}
	sort.Strings(options)

	return strings.Join(options, ",")
}

func e2eMountCommand(mountSource, mountPoint, options string) string {
	quotedMountSource := e2eShellQuote(mountSource)
	quotedMountPoint := e2eShellQuote(mountPoint)

	if options == "" {
		return fmt.Sprintf("sudo -n mkdir -p %s && sudo -n mount -t nfs %s %s", quotedMountPoint, quotedMountSource, quotedMountPoint)
	}

	return fmt.Sprintf("sudo -n mkdir -p %s && sudo -n mount -t nfs -o %s %s %s", quotedMountPoint, e2eShellQuote(options), quotedMountSource, quotedMountPoint)
}

func e2eSnapshotDir() string {
	snapshotDir := strings.Trim(config.FileStorageSnapshotDir, "/")
	if snapshotDir == "" {
		snapshotDir = e2eStorageSnapshotDir
	}

	snapshotDir = path.Clean(snapshotDir)
	if snapshotDir == "." || snapshotDir == ".." || strings.HasPrefix(snapshotDir, "../") || path.IsAbs(snapshotDir) {
		Fail(fmt.Sprintf("TEST_FILE_STORAGE_SNAPSHOT_DIR must be a non-empty relative path inside the mount, got %q", config.FileStorageSnapshotDir))
	}

	return snapshotDir
}

// e2eWaitForNFSClient polls until the NFS client binary appears. SSH can become
// available before cloud-init (see e2eNFSCloudConfig) finishes installing nfs-utils,
// so we wait for the binary rather than asserting its presence immediately.
func e2eWaitForNFSClient(client *ssh.Client) {
	Eventually(func() error {
		_, _, err := e2eRunSSHCommandResult(client,
			"command -v mount.nfs >/dev/null 2>&1 || command -v mount.nfs4 >/dev/null 2>&1",
			e2eSSHCommandTimeout)
		return err
	}).WithTimeout(e2eCloudInitTimeout).
		WithPolling(15*time.Second).
		Should(Succeed(), "cloud-init should install the NFS client (nfs-utils) before mounting")
}

func e2ePreflightInstance(client *ssh.Client) {
	e2eRunSSHCommand(client, "sudo -n true")
	e2eWaitForNFSClient(client)
}

func e2eWriteProbeFile(client *ssh.Client, probePath, content string) {
	e2eRunSSHCommand(client, fmt.Sprintf("printf %%s %s | sudo -n tee %s >/dev/null", e2eShellQuote(content), e2eShellQuote(probePath)))
}

func e2eAssertProbeFile(client *ssh.Client, probePath, content string) {
	e2eRunSSHCommand(client, fmt.Sprintf("test \"$(sudo -n cat %s)\" = %s", e2eShellQuote(probePath), e2eShellQuote(content)))
}

func e2eProvisionMountedFileStorage(snapshotPolicies *regionopenapi.StorageSnapshotPolicyListV2Spec) *e2eMountedFileStorage {
	e2eSkipUnlessOpenStackRegion()
	e2eSkipUnlessInternalAPIConfigured()
	e2eSkipUnlessServerFixtureConfigured()

	storageClassID := e2eRequireNFSFileStorageClassID()
	network := e2eCreateNetwork()
	securityGroup := e2eCreateSecurityGroup(network.Metadata.Id)
	storage := e2eCreateFileStorage(storageClassID, network.Metadata.Id, snapshotPolicies)
	attachment := e2eWaitForFileStorageMount(storage.Metadata.Id, network.Metadata.Id)
	if snapshotPolicies != nil {
		e2eWaitForSnapshotPolicyProvisioned(storage.Metadata.Id)
	}

	server := e2eCreateServer(network.Metadata.Id, securityGroup.Metadata.Id)
	server = e2eWaitForServerReady(server.Metadata.Id)

	key, err := regionClient.GetServerSSHKey(ctx, server.Metadata.Id)
	Expect(err).NotTo(HaveOccurred(), "failed to retrieve server SSH key")
	Expect(key.PrivateKey).NotTo(BeEmpty(), "server SSH private key should be populated")

	sshClient := e2eDialSSH(ctx, *server.Status.PublicIP, key.PrivateKey)
	DeferCleanup(func() {
		if err := sshClient.Close(); err != nil {
			GinkgoWriter.Printf("Warning: cleanup close SSH client for server %s: %v\n", server.Metadata.Id, err)
		}
	})

	e2ePreflightInstance(sshClient)

	mountPoint := path.Join("/mnt", string(storage.Metadata.Name))
	mountSource := *attachment.MountSource
	mountOptions := e2eMountOptions(attachment)
	e2eRunSSHCommand(sshClient, e2eMountCommand(mountSource, mountPoint, mountOptions))
	DeferCleanup(func() {
		e2eRunSSHCommand(sshClient, fmt.Sprintf("sudo -n umount %s && sudo -n rmdir %s", e2eShellQuote(mountPoint), e2eShellQuote(mountPoint)))
	})

	return &e2eMountedFileStorage{
		Storage:    storage,
		SSHClient:  sshClient,
		MountPoint: mountPoint,
	}
}

func e2eFindSnapshotContainingProbeCommand(snapshotDir, probePath string) string {
	return fmt.Sprintf(`live=$(sudo -n cat %s) || exit 1
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
		e2eShellQuote(probePath),
		e2eShellQuote(snapshotDir),
		e2eStorageSnapshotPolicyName,
		e2eProbeFileName)
}

func e2eWaitForSnapshotContainingProbe(client *ssh.Client, snapshotDir, probePath string) string {
	var snapshotPath string
	command := e2eFindSnapshotContainingProbeCommand(snapshotDir, probePath)

	Eventually(func() string {
		stdout, _, err := e2eRunSSHCommandResult(client, command, e2eSSHCommandTimeout)
		if err != nil {
			return ""
		}

		snapshotPath = strings.TrimSpace(stdout)
		return snapshotPath
	}).WithTimeout(e2eSnapshotVisibilityTimeout).
		WithPolling(e2eSnapshotPollingInterval).
		ShouldNot(BeEmpty(), "scheduled snapshot should contain the live probe file contents")

	return snapshotPath
}

var _ = Describe("File Storage NFS E2E", func() {
	Context("When mounting file storage from a running instance", func() {
		Describe("Given an OpenStack network, server, and NFS file storage attachment", func() {
			It("mounts the filesystem over SSH and reads/writes a probe file", func() {
				mounted := e2eProvisionMountedFileStorage(nil)
				probePath := path.Join(mounted.MountPoint, e2eProbeFileName)
				probeContent := "fast-" + mounted.Storage.Metadata.Id

				e2eWriteProbeFile(mounted.SSHClient, probePath, probeContent)
				e2eAssertProbeFile(mounted.SSHClient, probePath, probeContent)
			})

			It("captures probe file contents in an hourly scheduled snapshot", Label("nightly"), func() {
				policies := e2eHourlySnapshotPolicies()
				mounted := e2eProvisionMountedFileStorage(&policies)
				probePath := path.Join(mounted.MountPoint, e2eProbeFileName)
				probeContent := "nightly-" + mounted.Storage.Metadata.Id

				e2eWriteProbeFile(mounted.SSHClient, probePath, probeContent)
				e2eAssertProbeFile(mounted.SSHClient, probePath, probeContent)

				snapshotDir := path.Join(mounted.MountPoint, e2eSnapshotDir())
				snapshotPath := e2eWaitForSnapshotContainingProbe(mounted.SSHClient, snapshotDir, probePath)
				GinkgoWriter.Printf("Found scheduled snapshot containing probe data: %s\n", snapshotPath)
			})
		})
	})
})
