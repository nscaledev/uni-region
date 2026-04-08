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
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"testing"

	"github.com/stretchr/testify/require"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	serverprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/server"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func testSSHCertificateAuthority() *regionv1.SSHCertificateAuthority {
	return &regionv1.SSHCertificateAuthority{
		ObjectMeta: metav1.ObjectMeta{
			Name:      string(uuid.NewUUID()),
			Namespace: "default",
		},
		Spec: regionv1.SSHCertificateAuthoritySpec{
			PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMI0BxP3V7j7iB5nV5d8zWwM9W4a8W2R7x5gNBy3M2Q7 test-ca",
		},
	}
}

func testServer(opts ...func(*regionv1.Server)) *regionv1.Server {
	server := &regionv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Name:      string(uuid.NewUUID()),
			Namespace: "default",
		},
	}

	for _, opt := range opts {
		opt(server)
	}

	return server
}

func withTestSSHCertificateAuthority(resource *regionv1.SSHCertificateAuthority) func(*regionv1.Server) {
	return func(server *regionv1.Server) {
		server.Spec.SSHCertificateAuthorityID = ptr.To(resource.Name)
		server.Namespace = resource.Namespace
	}
}

func testClient(t *testing.T, objects []client.Object) client.Client {
	t.Helper()

	scheme, err := coreclient.NewScheme(regionv1.AddToScheme)
	require.NoError(t, err)

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func parseTestMultipartUserData(t *testing.T, userData []byte) []struct {
	ContentType string
	Content     []byte
} {
	t.Helper()

	message, err := mail.ReadMessage(bytes.NewReader(userData))
	require.NoError(t, err)

	_, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	require.NoError(t, err)

	reader := multipart.NewReader(message.Body, params["boundary"])
	parts := []struct {
		ContentType string
		Content     []byte
	}{}

	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}

		require.NoError(t, err)

		content, err := io.ReadAll(part)
		require.NoError(t, err)

		parts = append(parts, struct {
			ContentType string
			Content     []byte
		}{
			ContentType: part.Header.Get("Content-Type"),
			Content:     content,
		})
	}

	return parts
}

func TestServerCreateOptions(t *testing.T) {
	t.Parallel()

	t.Run("WithoutSSHCertificateAuthority", func(t *testing.T) {
		t.Parallel()

		cli := testClient(t, nil)

		options, err := serverprovisioner.ServerCreateOptionsForTest(t.Context(), testServer(), cli)
		require.NoError(t, err)
		require.NotNil(t, options)
		require.Empty(t, options.UserData)
	})

	t.Run("WithSSHCertificateAuthorityAndNoUserData", func(t *testing.T) {
		t.Parallel()

		resource := testSSHCertificateAuthority()
		cli := testClient(t, []client.Object{resource})

		options, err := serverprovisioner.ServerCreateOptionsForTest(t.Context(), testServer(withTestSSHCertificateAuthority(resource)), cli)
		require.NoError(t, err)
		require.Contains(t, string(options.UserData), "#cloud-config")
		require.Contains(t, string(options.UserData), "write_files:")
		require.Contains(t, string(options.UserData), "runcmd:")
		require.NotContains(t, string(options.UserData), "WriteFiles:")
		require.NotContains(t, string(options.UserData), "RunCmd:")
		require.Contains(t, string(options.UserData), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMI0BxP3V7j7iB5nV5d8zWwM9W4a8W2R7x5gNBy3M2Q7")
		require.Contains(t, string(options.UserData), "test-ca")
		require.Contains(t, string(options.UserData), "TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pub")
	})

	t.Run("WithSSHCertificateAuthorityAndCloudConfigUserData", func(t *testing.T) {
		t.Parallel()

		resource := testSSHCertificateAuthority()
		server := testServer(withTestSSHCertificateAuthority(resource))
		server.Spec.UserData = []byte("#cloud-config\nusers: []\n")
		cli := testClient(t, []client.Object{resource})

		options, err := serverprovisioner.ServerCreateOptionsForTest(t.Context(), server, cli)
		require.NoError(t, err)

		parts := parseTestMultipartUserData(t, options.UserData)
		require.Len(t, parts, 2)
		require.Equal(t, "text/cloud-config", parts[0].ContentType)
		require.Equal(t, string(server.Spec.UserData), string(parts[0].Content))
		require.Equal(t, "text/cloud-config", parts[1].ContentType)
		require.Contains(t, string(parts[1].Content), "test-ca")
	})

	t.Run("WithSSHCertificateAuthorityAndMultipartUserData", func(t *testing.T) {
		t.Parallel()

		resource := testSSHCertificateAuthority()
		server := testServer(withTestSSHCertificateAuthority(resource))
		server.Spec.UserData = []byte("Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\nMIME-Version: 1.0\r\n\r\n--BOUNDARY\r\nContent-Type: text/x-shellscript\r\n\r\n#!/bin/sh\necho hello\r\n--BOUNDARY--\r\n")
		cli := testClient(t, []client.Object{resource})

		options, err := serverprovisioner.ServerCreateOptionsForTest(t.Context(), server, cli)
		require.NoError(t, err)

		parts := parseTestMultipartUserData(t, options.UserData)
		require.Len(t, parts, 2)
		require.Equal(t, "text/x-shellscript", parts[0].ContentType)
		require.Contains(t, string(parts[0].Content), "#!/bin/sh")
		require.Equal(t, "text/cloud-config", parts[1].ContentType)
		require.Contains(t, string(parts[1].Content), "test-ca")
	})
}
