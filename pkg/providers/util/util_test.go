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

package util_test

import (
	"crypto/ed25519"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/unikorn-cloud/region/pkg/providers/util"
)

func TestGenerateSSHKeyPairReturnsValidEd25519PublicKey(t *testing.T) {
	t.Parallel()

	publicKey, _, err := util.GenerateSSHKeyPair()
	require.NoError(t, err)
	require.NotEmpty(t, publicKey)

	require.True(t, strings.HasPrefix(string(publicKey), "ssh-ed25519 "),
		"public key must be an OpenSSH ed25519 authorized_keys line")

	parsed, _, _, rest, err := ssh.ParseAuthorizedKey(publicKey)
	require.NoError(t, err, "public key must parse as an authorized_keys entry")
	require.Empty(t, rest, "authorized_keys line must not contain trailing data")
	require.Equal(t, ssh.KeyAlgoED25519, parsed.Type())
}

func TestGenerateSSHKeyPairReturnsValidPEMPrivateKey(t *testing.T) {
	t.Parallel()

	_, privateKey, err := util.GenerateSSHKeyPair()
	require.NoError(t, err)
	require.NotEmpty(t, privateKey)

	block, rest := pem.Decode(privateKey)
	require.NotNil(t, block, "private key must be a valid PEM block")
	require.Equal(t, "OPENSSH PRIVATE KEY", block.Type)
	require.Empty(t, rest, "private key PEM must not contain trailing data")
}

func TestGenerateSSHKeyPairKeysRoundTrip(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := util.GenerateSSHKeyPair()
	require.NoError(t, err)

	signer, err := ssh.ParsePrivateKey(privateKey)
	require.NoError(t, err, "private key must parse back into a signer")

	derived := ssh.MarshalAuthorizedKey(signer.PublicKey())
	require.Equal(t, string(publicKey), string(derived),
		"public key derived from the private key must match the returned public key")
}

func TestGenerateSSHKeyPairProducesUniqueKeys(t *testing.T) {
	t.Parallel()

	firstPub, firstPriv, err := util.GenerateSSHKeyPair()
	require.NoError(t, err)

	secondPub, secondPriv, err := util.GenerateSSHKeyPair()
	require.NoError(t, err)

	require.NotEqual(t, string(firstPub), string(secondPub),
		"ephemeral keypairs must not repeat public keys across calls")
	require.NotEqual(t, string(firstPriv), string(secondPriv),
		"ephemeral keypairs must not repeat private keys across calls")
}

func TestGenerateSSHKeyPairPrivateKeyIsEd25519(t *testing.T) {
	t.Parallel()

	_, privateKey, err := util.GenerateSSHKeyPair()
	require.NoError(t, err)

	raw, err := ssh.ParseRawPrivateKey(privateKey)
	require.NoError(t, err)
	require.IsType(t, &ed25519.PrivateKey{}, raw)
}
