//go:build cloudinit

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

package server_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	serverprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/server"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// These tests run real cloud-init in the image built from testdata/cloudinit
// (make test-cloud-init). See the README's "Cloud-init tests" section.

func cloudInitImage(t *testing.T) string {
	t.Helper()

	image := os.Getenv("CLOUDINIT_TEST_IMAGE")
	if image == "" {
		image = "unikorn-region-cloudinit-test"
	}

	if err := exec.CommandContext(t.Context(), "docker", "image", "inspect", image).Run(); err != nil {
		// A skip in CI would hide a regression.
		if os.Getenv("CI") != "" {
			t.Fatalf("cloud-init test image %s is required in CI: %v", image, err)
		}

		t.Skipf("cloud-init test image %s not available: %v", image, err)
	}

	return image
}

func docker(t *testing.T, stdin []byte, args ...string) []byte {
	t.Helper()

	var stdout, stderr bytes.Buffer

	cmd := exec.CommandContext(t.Context(), "docker", args...)
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	require.NoError(t, cmd.Run(), "docker %s: %s", strings.Join(args, " "), stderr.String())

	return stdout.Bytes()
}

// harness runs testdata/cloudinit/harness.py in the image.
func harness(t *testing.T, mode string, stdin []byte, out any) {
	t.Helper()

	stdout := docker(t, stdin, "run", "--rm", "-i", cloudInitImage(t), "ci-harness", mode)
	require.NoError(t, json.Unmarshal(stdout, out), string(stdout))
}

type harnessPart struct {
	Type      string  `json:"type"`
	Handled   bool    `json:"handled"`
	FileName  *string `json:"filename"`
	MergeType *string `json:"mergeType"`
	Payload   []byte  `json:"payload"`
}

type harnessParts struct {
	Parts    []harnessPart `json:"parts"`
	Warnings []string      `json:"warnings"`
}

func cloudInitParts(t *testing.T, userData []byte) harnessParts {
	t.Helper()

	var result harnessParts

	harness(t, "parts", userData, &result)

	return result
}

// container is one machine; each boot runs cloud-init's stages in it.
type container struct {
	t  *testing.T
	id string
}

func newContainer(t *testing.T, userData []byte) *container {
	t.Helper()

	id := strings.TrimSpace(string(docker(t, nil, "run", "-d", "--rm", cloudInitImage(t), "sleep", "infinity")))

	t.Cleanup(func() {
		// t.Context is cancelled before cleanup runs.
		_ = exec.Command("docker", "rm", "-f", id).Run()
	})

	c := &container{t: t, id: id}
	c.exec(userData, "sh", "-c", "mkdir -p /tmp/ci/seed && cat > /tmp/ci/seed/user-data")

	return c
}

func (c *container) exec(stdin []byte, args ...string) []byte {
	c.t.Helper()

	return docker(c.t, stdin, append([]string{"exec", "-i", c.id}, args...)...)
}

type bootFile struct {
	Mode   string `json:"mode"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
	SHA256 string `json:"sha256"`
}

type bootResult struct {
	Files   map[string]bootFile `json:"files"`
	Markers []string            `json:"markers"`
	Boots   int                 `json:"boots"`
	Shim    []string            `json:"shim"`
	SSHD    string              `json:"sshd"`
	Status  struct {
		Errors            []any          `json:"errors"`
		RecoverableErrors map[string]any `json:"recoverable_errors"` //nolint:tagliatelle // cloud-init's field name.
	} `json:"status"`
	Warnings     []string `json:"warnings"`
	FailedStages []string `json:"failedStages"`
}

// boot runs every cloud-init stage, then reports what the boot left behind.
func (c *container) boot(instanceID string, reboot bool) *bootResult {
	c.t.Helper()

	args := []string{"ci-boot"}
	if reboot {
		args = append(args, "--reboot")
	}

	c.exec(nil, append(args, instanceID)...)

	var result bootResult

	require.NoError(c.t, json.Unmarshal(c.exec(nil, "ci-collect"), &result))

	return &result
}

func (c *container) read(path string) string {
	c.t.Helper()

	return string(c.exec(nil, "cat", path))
}

// augmentedUserData is what the provisioner sends for a server with an SSH CA.
func augmentedUserData(t *testing.T, userData []byte) []byte {
	t.Helper()

	resource := testSSHCertificateAuthority()
	server := testServer(withTestSSHCertificateAuthority(resource))
	server.Spec.UserData = userData

	options, err := serverprovisioner.ServerCreateOptionsForTest(t.Context(), server, testClient(t, []client.Object{resource}))
	require.NoError(t, err)

	return options.UserData
}
