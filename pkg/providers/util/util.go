/*
Copyright 2024-2025 the Unikorn Authors.
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

package util

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

// GenerateSSHKeyPair creates an ephemeral SSH keypair, returning the
// public and private keys in SSH fingerprint and PEM formats respectively.
func GenerateSSHKeyPair() ([]byte, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	block, err := ssh.MarshalPrivateKey(priv, "unikorn ephemeral ed25519 key")
	if err != nil {
		return nil, nil, err
	}

	privateKey := pem.EncodeToMemory(block)

	publicKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}

	return ssh.MarshalAuthorizedKey(publicKey), privateKey, nil
}
