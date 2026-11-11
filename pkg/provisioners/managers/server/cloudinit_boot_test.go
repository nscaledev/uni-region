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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	caKeysPath   = "/etc/ssh/trusted-user-ca-keys.pub"
	caConfigPath = "/etc/ssh/sshd_config.d/90-unikorn-trusted-user-ca.conf"
)

// marker is a shell command recording that it ran, in order.
func marker(name string) string {
	return "mkdir -p /opt/marker; echo " + name + " >> /opt/marker/order"
}

func multipartUserData(parts ...string) string {
	var b strings.Builder

	b.WriteString("Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\nMIME-Version: 1.0\r\n\r\n")

	for _, part := range parts {
		b.WriteString("--BOUNDARY\r\n" + part + "\r\n")
	}

	b.WriteString("--BOUNDARY--\r\n")

	return b.String()
}

type bootCase struct {
	name     string
	userData string
	// markers and files are the customer outcome without an SSH CA: the
	// positive control, so two equally broken boots cannot pass.
	markers []string
	files   map[string]string
	// customerCA is set where the customer overrides TrustedUserCAKeys,
	// which they may (see the README).
	customerCA string
	// customerErrors is set where cloud-init reports problems with the
	// customer's own user-data, in both boots.
	customerErrors bool
}

func bootCases() []bootCase {
	return []bootCase{
		{
			// INST-1542.
			name:     "CloudConfig",
			userData: "#cloud-config\nruncmd:\n- [sh, -c, '" + marker("runcmd") + "']\nwrite_files:\n- path: /opt/customer/file\n  content: customer\n",
			markers:  []string{"runcmd"},
			files:    map[string]string{"/opt/customer/file": "customer"},
		},
		{
			name:           "NullKeys",
			userData:       "#cloud-config\nruncmd:\nwrite_files:\n",
			customerErrors: true,
		},
		{
			name:     "RunCmdStrings",
			userData: "#cloud-config\nruncmd:\n- '" + marker("first") + "'\n- '" + marker("second") + "'\n",
			markers:  []string{"first", "second"},
		},
		{
			name:           "EmptyCloudConfig",
			userData:       "#cloud-config\n",
			customerErrors: true,
		},
		{
			name:           "InvalidYAML",
			userData:       "#cloud-config\nruncmd: [\n",
			customerErrors: true,
		},
		{
			name:     "Jinja",
			userData: "## template: jinja\n#cloud-config\nruncmd:\n- [sh, -c, '" + marker("jinja-{{ v1.instance_id }}") + "']\nwrite_files:\n- path: /opt/customer/iid\n  content: '{{ v1.instance_id }}'\n",
			markers:  []string{"jinja-i-1"},
			files:    map[string]string{"/opt/customer/iid": "i-1"},
		},
		{
			name:     "CloudConfigArchive",
			userData: "#cloud-config-archive\n- type: text/cloud-config\n  content: |\n    #cloud-config\n    write_files:\n    - path: /opt/customer/file\n      content: archive\n- type: text/x-shellscript\n  content: |\n    #!/bin/sh\n    " + marker("archive") + "\n",
			markers:  []string{"archive"},
			files:    map[string]string{"/opt/customer/file": "archive"},
		},
		{
			name:     "ShellScript",
			userData: "#!/bin/sh\n" + marker("script") + "\n",
			markers:  []string{"script"},
		},
		{
			name: "Multipart",
			userData: multipartUserData(
				"Content-Type: text/cloud-config\r\n\r\n#cloud-config\nruncmd:\n- [sh, -c, '"+marker("runcmd")+"']\n",
				"Content-Type: text/x-shellscript\r\n\r\n#!/bin/sh\n"+marker("script")+"\n",
				"Content-Type: text/x-shellscript; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n#!/bin/sh\nprintf 'caf=C3=A9' > /opt/customer-qp\n",
			),
			// Scripts run in filename order: part-002 before runcmd.
			markers: []string{"script", "runcmd"},
			files:   map[string]string{"/opt/customer-qp": "café"},
		},
		{
			// A customer script named runcmd is overwritten by their own
			// runcmd: their clash, and it must stay the same with a CA.
			name: "PartNamedRunCmd",
			userData: multipartUserData(
				"Content-Type: text/cloud-config\r\n\r\n#cloud-config\nruncmd:\n- [sh, -c, '"+marker("runcmd")+"']\n",
				"Content-Type: text/x-shellscript\r\nContent-Disposition: attachment; filename=\"runcmd\"\r\n\r\n#!/bin/sh\n"+marker("named")+"\n",
			),
			markers: []string{"runcmd"},
		},
		{
			name:       "CustomerTrustedUserCAKeys",
			userData:   "#cloud-config\nwrite_files:\n- path: /etc/ssh/sshd_config.d/10-customer.conf\n  content: TrustedUserCAKeys /etc/ssh/customer-ca.pub\n",
			files:      map[string]string{"/etc/ssh/sshd_config.d/10-customer.conf": "TrustedUserCAKeys /etc/ssh/customer-ca.pub"},
			customerCA: "/etc/ssh/customer-ca.pub",
		},
		{
			name:     "NonASCII",
			userData: "#cloud-config\nruncmd:\n- [sh, -c, '" + marker("runcmd") + "']\nwrite_files:\n- path: /opt/customer/file\n  content: café €\n",
			markers:  []string{"runcmd"},
			files:    map[string]string{"/opt/customer/file": "café €"},
		},
		{
			name: "Empty",
		},
		{
			name:     "SentinelVariant",
			userData: "\n#Cloud-Config\nruncmd:\n- [sh, -c, '" + marker("runcmd") + "']\n",
			markers:  []string{"runcmd"},
		},
	}
}

// TestBootCustomerOutcomeUnchanged boots each input with and without an SSH
// CA: the customer's outcome must be identical, and the CA must take effect.
func TestBootCustomerOutcomeUnchanged(t *testing.T) {
	t.Parallel()

	for _, test := range bootCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rawContainer := newContainer(t, []byte(test.userData))
			raw := rawContainer.boot("i-1", false)

			// Positive control.
			require.Equal(t, test.markers, nilIfEmpty(raw.Markers))

			for path, content := range test.files {
				require.Equal(t, content, rawContainer.read(path), path)
			}

			if !test.customerErrors {
				require.Empty(t, raw.Warnings)
				require.Empty(t, raw.Status.Errors)
				require.Empty(t, raw.FailedStages)
			}

			managedContainer := newContainer(t, augmentedUserData(t, []byte(test.userData)))
			managed := managedContainer.boot("i-1", false)

			// Customer outcome unchanged.
			require.Equal(t, raw.Markers, managed.Markers)
			require.Equal(t, raw.Status, managed.Status)
			require.Equal(t, raw.FailedStages, managed.FailedStages)
			require.Equal(t, normaliseWarnings(raw.Warnings), normaliseWarnings(managed.Warnings))

			managedFiles := managed.Files
			delete(managedFiles, caKeysPath)
			delete(managedFiles, caConfigPath)
			require.Equal(t, raw.Files, managedFiles)

			// CA in effect.
			require.Equal(t, testSSHCertificateAuthority().Spec.PublicKey+"\n", managedContainer.read(caKeysPath))
			require.Equal(t, "TrustedUserCAKeys "+caKeysPath+"\n", managedContainer.read(caConfigPath))
			require.Equal(t, "644 0:0\n644 0:0\n", string(managedContainer.exec(nil, "stat", "-c", "%a %u:%g", caKeysPath, caConfigPath)))

			expectedCA := caKeysPath
			if test.customerCA != "" {
				expectedCA = test.customerCA
			}

			require.Equal(t, expectedCA, managed.SSHD)

			// Reloaded once, after both files exist.
			require.Equal(t, []string{"systemctl reload sshd +" + caKeysPath + " +" + caConfigPath}, reloads(managed.Shim))
		})
	}
}

// TestBootManagedConfigRunsOncePerInstance encodes the owner's rule: once
// applied, operators may remove the CA and it never comes back on reboot. A
// rebuild reimages the disk, which is a first boot again. A new instance-id
// (e.g. a server made from a snapshot) applies it afresh.
func TestBootManagedConfigRunsOncePerInstance(t *testing.T) {
	t.Parallel()

	userData := "#cloud-config\nbootcmd:\n- [sh, -c, 'mkdir -p /opt/marker; echo boot >> /opt/marker/boots']\n"

	c := newContainer(t, augmentedUserData(t, []byte(userData)))

	first := c.boot("i-1", false)
	require.Empty(t, first.FailedStages)
	require.Empty(t, first.Warnings)
	require.Equal(t, 1, first.Boots)
	require.Equal(t, caKeysPath, first.SSHD)

	c.exec(nil, "rm", caKeysPath, caConfigPath)

	reboot := c.boot("i-1", true)
	require.Equal(t, 2, reboot.Boots, "positive control: the reboot ran")
	require.NotContains(t, reboot.Files, caKeysPath)
	require.NotContains(t, reboot.Files, caConfigPath)
	require.Empty(t, reloads(reboot.Shim))
	require.Equal(t, "none", reboot.SSHD)

	newInstance := c.boot("i-2", true)
	require.Equal(t, 3, newInstance.Boots)
	require.Contains(t, newInstance.Files, caKeysPath)
	require.Equal(t, caKeysPath, newInstance.SSHD)
	require.Len(t, reloads(newInstance.Shim), 1)
}

// TestBootManagedConfigRunsBeforeCustomerScripts: scripts_user is marked done
// before it runs, so a customer script that reboots (here, kills cloud-init)
// must not stop the CA landing.
func TestBootManagedConfigRunsBeforeCustomerScripts(t *testing.T) {
	t.Parallel()

	userData := "#!/bin/sh\nkill -9 $PPID\n"

	c := newContainer(t, augmentedUserData(t, []byte(userData)))

	first := c.boot("i-1", false)
	require.Equal(t, []string{"modules --mode final"}, first.FailedStages, "positive control: cloud-init was killed")

	reboot := c.boot("i-1", true)
	require.Equal(t, caKeysPath, reboot.SSHD)
}

func reloads(shim []string) []string {
	var out []string

	for _, line := range shim {
		if strings.Contains(line, "ssh") {
			out = append(out, line)
		}
	}

	return out
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}

	return s
}

// normaliseWarnings drops the log prefix (timestamps, pids) so warnings from
// two boots compare.
func normaliseWarnings(warnings []string) []string {
	out := make([]string, 0, len(warnings))

	for _, warning := range warnings {
		if _, message, ok := strings.Cut(warning, "]: "); ok {
			warning = message
		}

		out = append(out, warning)
	}

	return out
}
