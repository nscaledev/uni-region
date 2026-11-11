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
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	serverprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/server"
)

const partHandler = "#part-handler\ndef list_types():\n    return ['text/x-mine']\n\ndef handle_part(data, ctype, filename, payload):\n    pass\n"

// detectionPayloads builds every first-line variant cloud-init must agree
// with us on, from cloud-init's own prefix table.
func detectionPayloads(t *testing.T) []string {
	t.Helper()

	var prefixes map[string]string

	harness(t, "prefixes", nil, &prefixes)

	leads := []string{"", "\n", "\r\n", "\n\n\n", "  ", "\t", "\x1c", "\uFEFF"}
	payloads := []string{}

	for prefix := range prefixes {
		for _, lead := range leads {
			payloads = append(payloads,
				lead+prefix+"\nbody\n",
				lead+strings.ToUpper(prefix)+"\r\nbody\r\n",
			)
		}
	}

	// Near misses and non-cloud-init payloads.
	payloads = append(payloads,
		"echo hello\n",
		"{\"ignition\": {\"version\": \"3.4.0\"}}\n",
		" \n\t\n",
		"cloud-config\n",
		"# cloud-config\n",
		"#\u0130nclude\nhttps://example.com\n",
		"#cloud-boothoo\u212a\n#!/bin/sh\n",
		"#cloud-config\n\xff\xfe\n",
		"\xff#cloud-config\n",
	)

	slices.Sort(payloads)

	return slices.Compact(payloads)
}

// TestPrefixTableMatchesCloudInit: a stale entry in ours would accept what
// cloud-init leaves unhandled.
func TestPrefixTableMatchesCloudInit(t *testing.T) {
	t.Parallel()

	var prefixes map[string]string

	harness(t, "prefixes", nil, &prefixes)
	require.Equal(t, prefixes, serverprovisioner.CloudInitPrefixesForTest())
}

// TestDetectionMatchesCloudInit: we accept exactly what cloud-init detects,
// except part-handler and payloads that are not UTF-8, rejected by policy.
func TestDetectionMatchesCloudInit(t *testing.T) {
	t.Parallel()

	payloads := detectionPayloads(t)

	encoded := make([][]byte, len(payloads))
	for i, payload := range payloads {
		encoded[i] = []byte(payload)
	}

	stdin, err := json.Marshal(encoded)
	require.NoError(t, err)

	var detected []*string

	harness(t, "detect", stdin, &detected)
	require.Len(t, detected, len(payloads))

	for i, payload := range payloads {
		t.Run(strings.ToValidUTF8(payload, "?"), func(t *testing.T) {
			t.Parallel()

			err := serverprovisioner.ValidateUserData([]byte(payload))

			switch {
			case !utf8.ValidString(payload):
				require.ErrorContains(t, err, "UTF-8")
			case detected[i] == nil:
				require.ErrorContains(t, err, "unsupported userData format", "cloud-init would not handle this")
			case *detected[i] == "text/part-handler":
				require.ErrorContains(t, err, "part-handler")
			default:
				require.NoError(t, err, "cloud-init detects %s", *detected[i])

				require.Equal(t, *detected[i], serverprovisioner.DetectContentTypeForTest([]byte(payload)))
			}
		})
	}
}

func gzipped(t *testing.T, data string) string {
	t.Helper()

	var b bytes.Buffer

	w := gzip.NewWriter(&b)
	_, err := w.Write([]byte(data))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	return b.String()
}

// TestPartHandlerRejected covers a part-handler used openly. Buried ones
// (gzip, base64, nested, archive) are known gaps (see the README).
func TestPartHandlerRejected(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"Single":         partHandler,
		"Declared":       multipartUserData("Content-Type: text/part-handler\r\n\r\ndef list_types():\n    return []\n"),
		"AsPlain":        multipartUserData("Content-Type: text/plain\r\n\r\n" + partHandler),
		"AsShellScript":  multipartUserData("Content-Type: text/x-shellscript\r\n\r\n" + partHandler),
		"Malformed":      multipartUserData("Content-Type: Text/Part-Handler; ;x\r\n\r\ndef list_types():\n    return []\n"),
		"SinglePartMIME": "MIME-Version: 1.0\r\nContent-Type: text/part-handler\r\n\r\ndef list_types():\n    return []\n",
	}

	for name, userData := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Positive control: cloud-init sees a part-handler.
			require.Equal(t, "text/part-handler", cloudInitParts(t, []byte(userData)).Parts[0].Type)

			require.ErrorContains(t, serverprovisioner.ValidateUserData([]byte(userData)), "part-handler")
			require.ErrorContains(t, serverprovisioner.ValidateManagedUserData([]byte(userData)), "part-handler")
		})
	}
}

// TestDeclaredTypeNotSniffed: cloud-init reads a part-handler prefix only in
// the parts it sniffs, so a body under any other declared type is accepted.
func TestDeclaredTypeNotSniffed(t *testing.T) {
	t.Parallel()

	userData := multipartUserData("Content-Type: text/x-shellscript-per-boot\r\n\r\n" + partHandler)

	require.Equal(t, "text/x-shellscript-per-boot", cloudInitParts(t, []byte(userData)).Parts[0].Type)
	require.NoError(t, serverprovisioner.ValidateUserData([]byte(userData)))
	require.NoError(t, serverprovisioner.ValidateManagedUserData([]byte(userData)))
}

// TestProvisionerPassesStoredPartHandlerThrough: rejection is at the API only,
// so existing servers whose stored user-data has a part-handler still
// reconcile.
func TestProvisionerPassesStoredPartHandlerThrough(t *testing.T) {
	t.Parallel()

	parts := cloudInitParts(t, augmentedUserData(t, []byte(partHandler))).Parts
	require.Equal(t, "text/part-handler", parts[0].Type)
	require.Equal(t, partHandler, string(parts[0].Payload))
}

// passThroughInputs are customer payloads whose parts must reach cloud-init
// unchanged when we add ours.
func passThroughInputs(t *testing.T) map[string]string {
	t.Helper()

	cases := map[string]string{
		"QuotedPrintable": multipartUserData("Content-Type: text/x-shellscript; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n#!/bin/sh\nprintf 'caf=E9 and a long line that is soft broken by=\r\n the encoder'\n"),
		"Base64":          multipartUserData("Content-Type: text/x-shellscript\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte("#!/bin/sh\necho hello\n"))),
		"GzipPart":        multipartUserData("Content-Type: application/gzip\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte(gzipped(t, "#!/bin/sh\necho hello\n")))),
		"Nested":          multipartUserData("Content-Type: multipart/mixed; boundary=\"INNER\"\r\n\r\n--INNER\r\nContent-Type: text/cloud-config\r\n\r\n#cloud-config\nruncmd: [[a]]\n\r\n--INNER--\r\n"),
		"MergeType":       multipartUserData("Content-Type: text/cloud-config\r\nMerge-Type: list(append)+dict(recurse_array)+str()\r\nContent-Disposition: attachment; filename=\"mine\"\r\n\r\n#cloud-config\nruncmd: [[a]]\n"),
		"Jinja":           "## template: jinja\n#cloud-config\nhostname: {{ v1.local_hostname }}\n",
		"Archive":         "#cloud-config-archive\n- type: text/cloud-config\n  content: |\n    #cloud-config\n    runcmd: [[a]]\n",
		"MixedCase":       "\n\n#Cloud-Config\nruncmd: [[a]]\n",
		"Jsonp":           multipartUserData("Content-Type: text/cloud-config\r\n\r\n#cloud-config\nruncmd: [[a]]\n", "Content-Type: text/cloud-config-jsonp\r\n\r\n#cloud-config-jsonp\n[{\"op\": \"add\", \"path\": \"/runcmd/-\", \"value\": [\"b\"]}]\n"),
		"Boothook":        "#cloud-boothook\n#!/bin/sh\necho hello\n",
		"NonASCII":        "#cloud-config\nwrite_files:\n- path: /opt/x\n  content: café €\n",
		"Whitespace":      "#!/bin/sh\r\necho 'trailing'   \r\n\techo " + strings.Repeat("long line with spaces =", 20) + " \n\n",
		"BlankThenMIME":   "\n#!/bin/sh\necho MIME-Version: 1\n",
		"MentionsMIME":    "#cloud-config\nwrite_files:\n- path: /opt/x\n  content: 'MIME-Version: 1.0'\n",
		"PerBoot":         multipartUserData("Content-Type: text/x-shellscript-per-boot\r\n\r\n#!/bin/sh\necho hello\n"),
	}

	return cases
}

// TestCustomerPartsReachCloudInitUnchanged: every part cloud-init hands to a
// handler without a CA, it hands over identically with one, plus ours.
func TestCustomerPartsReachCloudInitUnchanged(t *testing.T) {
	t.Parallel()

	for name, userData := range passThroughInputs(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.NoError(t, serverprovisioner.ValidateManagedUserData([]byte(userData)))

			raw := cloudInitParts(t, []byte(userData))
			managed := cloudInitParts(t, augmentedUserData(t, []byte(userData)))

			require.Empty(t, raw.Warnings, "positive control")
			require.Empty(t, managed.Warnings)

			for _, part := range append(slices.Clone(raw.Parts), managed.Parts...) {
				require.True(t, part.Handled, "no cloud-init handler for %s", part.Type)
			}

			require.Len(t, managed.Parts, len(raw.Parts)+1)
			require.Equal(t, raw.Parts, managed.Parts[:len(raw.Parts)])

			ours := managed.Parts[len(raw.Parts)]
			require.Equal(t, "text/x-shellscript", ours.Type)
			require.NotNil(t, ours.FileName)
			require.Equal(t, "00-unikorn-ssh-certificate-authority", *ours.FileName)
		})
	}
}

// TestAcceptedUserDataIsHandled: anything the API accepts without a CA,
// cloud-init handles when sent unmodified.
func TestAcceptedUserDataIsHandled(t *testing.T) {
	t.Parallel()

	inputs := passThroughInputs(t)
	inputs["Gzip"] = gzipped(t, "#cloud-config\nruncmd: [[a]]\n")

	for name, userData := range inputs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.NoError(t, serverprovisioner.ValidateUserData([]byte(userData)))

			result := cloudInitParts(t, []byte(userData))
			require.Empty(t, result.Warnings)

			for _, part := range result.Parts {
				require.True(t, part.Handled, "no cloud-init handler for %s", part.Type)
			}
		})
	}
}

// TestMIMEAsCloudInitReadsIt: cloud-init reads user-data as MIME only if it
// has "mime-version:" in its first 4096 bytes, however it starts.
func TestMIMEAsCloudInitReadsIt(t *testing.T) {
	t.Parallel()

	t.Run("MultipartWithoutMIMEVersion", func(t *testing.T) {
		t.Parallel()

		userData := strings.Replace(multipartUserData("Content-Type: text/x-shellscript\r\n\r\n#!/bin/sh\necho hello\n"), "MIME-Version: 1.0\r\n", "", 1)

		require.False(t, cloudInitParts(t, []byte(userData)).Parts[0].Handled, "positive control: cloud-init ignores it")
		require.ErrorContains(t, serverprovisioner.ValidateUserData([]byte(userData)), "unsupported userData format")
	})

	t.Run("MarkerWithColon", func(t *testing.T) {
		t.Parallel()

		userData := "#cloud-config:x\nContent-Type: text/part-handler\nMIME-Version: 1.0\n\ndef list_types():\n    return []\n"

		require.Equal(t, "text/part-handler", cloudInitParts(t, []byte(userData)).Parts[0].Type, "positive control")
		require.ErrorContains(t, serverprovisioner.ValidateUserData([]byte(userData)), "part-handler")
	})

	t.Run("StoredUnparsable", func(t *testing.T) {
		t.Parallel()

		// Rejected at the API, but a stored copy must still reconcile.
		userData := " #cloud-config\nwrite_files:\n- path: /x\n  content: 'MIME-Version: 1.0'\n"

		require.Error(t, serverprovisioner.ValidateManagedUserData([]byte(userData)))

		parts := cloudInitParts(t, augmentedUserData(t, []byte(userData))).Parts
		require.Equal(t, "00-unikorn-ssh-certificate-authority", *parts[len(parts)-1].FileName)
	})

	t.Run("SinglePart", func(t *testing.T) {
		t.Parallel()

		userData := "MIME-Version: 1.0\r\nContent-Type: text/x-shellscript\r\n\r\n#!/bin/sh\necho hello\n"

		require.NoError(t, serverprovisioner.ValidateManagedUserData([]byte(userData)))

		raw := cloudInitParts(t, []byte(userData))
		managed := cloudInitParts(t, augmentedUserData(t, []byte(userData)))

		require.Len(t, managed.Parts, 2)
		require.Equal(t, raw.Parts, managed.Parts[:1])
	})
}
