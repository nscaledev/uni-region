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

//nolint:revive,testpackage,gci // Ginkgo conventions
package suites

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/google/uuid"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionopenapi "github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"
)

func mustProvisionServerWithMarker(marker string) *regionopenapi.ServerV2Read {
	GinkgoHelper()
	network := api.MustResolveSharedNetwork(regionClient, ctx)
	builder := api.NewServerPayload(network.Metadata.Id, config.ServerFlavorID, config.ServerImageID).
		WithUserData(markerUserData(marker))

	if config.ServerInfrastructureRef != "" {
		builder.WithInfrastructureRef(config.ServerInfrastructureRef).WithSSHInjection(regionopenapi.SshInjectionNone)
	}
	created, cleanup := api.MustCreateServer(regionClient, ctx, builder.Build())
	DeferCleanup(cleanup)
	server := EventuallyServerProvisioned(created.Metadata.Id)
	Expect(server.Status.PrivateIP).NotTo(BeNil())
	eventuallyConsoleContains(server.Metadata.Id, marker)
	return server
}

func markerUserData(marker string) []byte {
	return []byte(fmt.Sprintf("#cloud-config\nfinal_message: %s\n", marker))
}

func eventuallyConsoleContains(serverID, marker string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		output, err := regionClient.GetServerConsoleOutput(ctx, serverID)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output.Contents).To(ContainSubstring(marker))
	}).WithTimeout(rebuildWatchTimeout).WithPolling(rebuildPollInterval).Should(Succeed())
}

func expectServerIdentityAndAddresses(got, original *regionopenapi.ServerV2Read) {
	GinkgoHelper()
	Expect(got.Metadata.Id).To(Equal(original.Metadata.Id))
	Expect(got.Metadata.Name).To(Equal(original.Metadata.Name))
	Expect(got.Status.NetworkId).To(Equal(original.Status.NetworkId))
	Expect(got.Status.PrivateIP).To(Equal(original.Status.PrivateIP))
	Expect(got.Status.PublicIP).To(Equal(original.Status.PublicIP))
}

func eventuallyServerUserData(serverID string, userData *[]byte) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		got, err := regionClient.GetServer(ctx, serverID)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(got.Spec.UserData).To(Equal(userData))
	}).WithTimeout(5 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())
}

var _ = Describe("Server user data", func() {
	BeforeEach(func() {
		api.SkipUnlessOpenStackRegion(regionClient, ctx, config)
		api.SkipUnlessInternalAPIConfigured(regionClient)
		api.SkipUnlessServerFixtureConfigured(config)
	})

	Context("When changing a provisioned v2 server's user data", func() {
		Describe("Given user-data rebuilds are enabled", func() {
			It("applies the new user data in place", Label("slow"), func() {
				if !config.ServerUserDataRebuild {
					Skip("requires TEST_SERVER_USER_DATA_REBUILD=true matching serverController.userDataRebuild")
				}
				server := mustProvisionServerWithMarker(uuid.NewString())
				marker := uuid.NewString()
				userData := markerUserData(marker)
				update := api.ServerUpdateFromRead(server).Build()
				update.Spec.UserData = &userData

				updated, err := regionClient.UpdateServer(ctx, server.Metadata.Id, update)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated.Spec.UserData).To(Equal(&userData))
				Expect(updated.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioning))
				eventuallyServerUserData(server.Metadata.Id, &userData)
				EventuallyServerProvisioning(server.Metadata.Id)
				settled := EventuallyServerProvisioned(server.Metadata.Id)
				expectServerIdentityAndAddresses(settled, server)
				eventuallyConsoleContains(server.Metadata.Id, marker)
			})
		})

		Describe("Given user-data rebuilds are disabled", func() {
			It("stores the new user data without applying it to the guest", Label("slow"), func() {
				if config.ServerUserDataRebuild {
					Skip("requires TEST_SERVER_USER_DATA_REBUILD=false matching serverController.userDataRebuild")
				}
				originalMarker, newMarker := uuid.NewString(), uuid.NewString()
				server := mustProvisionServerWithMarker(originalMarker)
				userData := markerUserData(newMarker)
				update := api.ServerUpdateFromRead(server).Build()
				update.Spec.UserData = &userData

				updated, err := regionClient.UpdateServer(ctx, server.Metadata.Id, update)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated.Spec.UserData).To(Equal(&userData))
				eventuallyServerUserData(server.Metadata.Id, &userData)
				settled := EventuallyServerProvisioned(server.Metadata.Id)
				expectServerIdentityAndAddresses(settled, server)

				// Observe several reconciliation intervals; this is a bounded no-rebuild check.
				Consistently(func(g Gomega) {
					got, err := regionClient.GetServer(ctx, server.Metadata.Id)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(got.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioned))
					output, err := regionClient.GetServerConsoleOutput(ctx, server.Metadata.Id)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(output.Contents).To(ContainSubstring(originalMarker))
					g.Expect(output.Contents).NotTo(ContainSubstring(newMarker))
				}).WithTimeout(2 * time.Minute).WithPolling(rebuildProvisioningPoll).Should(Succeed())
			})
		})
	})

	Context("When omitting user data from a v2 update", func() {
		Describe("Given a provisioned server booted with user data", func() {
			It("clears the stored user data and rebuilds in place when enabled", Label("slow"), func() {
				server := mustProvisionServerWithMarker(uuid.NewString())
				update := api.ServerUpdateFromRead(server).Build()
				update.Spec.UserData = nil

				updated, err := regionClient.UpdateServer(ctx, server.Metadata.Id, update)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated.Spec.UserData).To(BeNil())
				if config.ServerUserDataRebuild {
					Expect(updated.Metadata.ProvisioningStatus).To(Equal(coreapi.ResourceProvisioningStatusProvisioning))
					EventuallyServerProvisioning(server.Metadata.Id)
				}
				eventuallyServerUserData(server.Metadata.Id, nil)
				settled := EventuallyServerProvisioned(server.Metadata.Id)
				expectServerIdentityAndAddresses(settled, server)
				Expect(settled.Spec.UserData).To(BeNil())
				// Console output has no boot boundary: absence could mean truncation or
				// cloud-init has not finished, so it cannot prove the new boot cleared data.
			})
		})
	})
})
