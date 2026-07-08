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
	"testing"

	"github.com/stretchr/testify/require"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	serverprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/server"
)

func TestValidateUserDataAcceptsSupportedPayloads(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		userData []byte
	}{
		{
			name:     "Empty",
			userData: nil,
		},
		{
			name:     "CloudConfig",
			userData: []byte("#cloud-config\nusers: []\n"),
		},
		{
			name:     "ShellScript",
			userData: []byte("#!/bin/sh\necho hello\n"),
		},
		{
			name:     "JinjaTemplate",
			userData: []byte("## template: jinja\n#cloud-config\nhostname: {{ ds.meta_data.hostname }}\n"),
		},
		{
			name:     "IncludeURL",
			userData: []byte("#include\nhttps://example.com/user-data\n"),
		},
		{
			name:     "CloudBoothook",
			userData: []byte("#cloud-boothook\n#!/bin/sh\necho hello\n"),
		},
		{
			name:     "CloudConfigArchive",
			userData: []byte("#cloud-config-archive\n- type: text/cloud-config\n  content: |\n    users: []\n"),
		},
		{
			name:     "PartHandler",
			userData: []byte("#part-handler\ndef list_types():\n    return [\"text/plain\"]\n"),
		},
		{
			name:     "CRLFLineEndings",
			userData: []byte("#cloud-config\r\nusers: []\r\n"),
		},
		{
			name:     "Multipart",
			userData: []byte("Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\nMIME-Version: 1.0\r\n\r\n--BOUNDARY\r\nContent-Type: text/x-shellscript\r\n\r\n#!/bin/sh\necho hello\r\n--BOUNDARY--\r\n"),
		},
		{
			// Multipart detection must not depend on header order: MIME allows any
			// header first, and cloud-init accepts this payload.
			name:     "MultipartMIMEVersionFirst",
			userData: []byte("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\r\n--BOUNDARY\r\nContent-Type: text/x-shellscript\r\n\r\n#!/bin/sh\necho hello\r\n--BOUNDARY--\r\n"),
		},
		{
			// Gzip payloads are passed to the platform unmodified when no managed
			// augmentation occurs, so they are accepted here.
			name:     "Gzip",
			userData: []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			require.NoError(t, serverprovisioner.ValidateUserData(test.userData))
		})
	}
}

func TestValidateUserDataRejectsMalformedPayloads(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		userData []byte
		contains string
	}{
		{
			name:     "PlainTextWithoutSentinel",
			userData: []byte("echo hello"),
			contains: "unsupported userData format",
		},
		{
			name:     "MultipartMissingBoundary",
			userData: []byte("Content-Type: multipart/mixed\r\nMIME-Version: 1.0\r\n\r\nbody\r\n"),
			contains: "boundary missing",
		},
		{
			name:     "MultipartMalformedHeaders",
			userData: []byte("Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\nnot a valid header\n\n--BOUNDARY--\n"),
			contains: "unable to parse multipart userData",
		},
		{
			name:     "MultipartTruncatedPart",
			userData: []byte("Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\nMIME-Version: 1.0\r\n\r\n--BOUNDARY\r\nContent-Type: text/x-shellscript\r\n\r\n#!/bin/sh\r\n"),
			contains: "multipart userData",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := serverprovisioner.ValidateUserData(test.userData)

			require.Error(t, err)
			require.ErrorContains(t, err, test.contains)
		})
	}
}

func TestValidateUserDataUnsupportedFormatMessageIsContextNeutral(t *testing.T) {
	t.Parallel()

	err := serverprovisioner.ValidateUserData([]byte("echo hello"))

	require.Error(t, err)
	require.ErrorContains(t, err, "unsupported userData format")
	// The unrecognized-format error surfaces on paths with no managed
	// augmentation involved, so it must not blame augmentation.
	require.NotContains(t, err.Error(), "managed cloud-init augmentation")
}

func TestValidateManagedUserDataRejectsGzip(t *testing.T) {
	t.Parallel()

	err := serverprovisioner.ValidateManagedUserData([]byte{0x1f, 0x8b, 0x08, 0x00})

	require.Error(t, err)
	require.ErrorContains(t, err, "gzip userData cannot be combined with managed cloud-init augmentation")
}

func TestUserDataErrorCarriesStructuredReason(t *testing.T) {
	t.Parallel()

	err := serverprovisioner.ValidateUserData([]byte("echo hello"))

	require.Error(t, err)

	// The reason must be recoverable structurally, not by string surgery.
	udErr := &serverprovisioner.UserDataError{}
	require.ErrorAs(t, err, &udErr)
	require.Contains(t, udErr.Reason, "unsupported userData format")
	require.NotContains(t, udErr.Reason, "consistency error")

	// Provisioner-side classification must keep seeing the sentinel.
	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}
