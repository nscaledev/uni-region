# pkg/providers/util

## Intention

`pkg/providers/util` is a narrow provider-support package for generating the
ephemeral SSH keypair currently used as a break-glass access path during
OpenStack identity provisioning.

It is not a general SSH helper library. Its current job is to create an
Ed25519 keypair, return the public key in OpenSSH authorized-key format, return
the private key in PEM form, and hand both back to the OpenStack provider flow
that installs the public key cloud-side and persists the private key for later
download or use by higher-order services.

That makes this package a transitional convenience helper rather than a durable
architectural primitive. The long-term direction is toward SSH certificate
flows where the service does not handle user private keying material at all.

## Invariants And Guard Rails

- This package exists for one specific workflow: generating the ephemeral SSH
  keypair used by the OpenStack identity bootstrap path.
- `GenerateSSHKeyPair()` generates Ed25519 keys. The algorithm is not currently
  configurable.
- The returned public key is encoded in OpenSSH authorized-key format.
- The returned private key is PEM-encoded OpenSSH private key material.
- The package should not grow into a generic SSH abstraction layer unless there
  is a concrete second use case that justifies it.

## Caveats

- The helper is described as ephemeral, but the private key is still persisted
  in provider-backed identity state today so it can be downloaded or consumed
  later. That means the exposure model is still materially different from a
  pure certificate-based approach.
- This is primarily a break-glass convenience path, not the preferred
  long-term trust model.
- The package name undersells its sensitivity: it is generating access
  credentials, not performing low-stakes generic utility work.
- If server access moves fully to SSH certificate authority flows, this package
  may become unnecessary for at least some current provisioning paths.

## TODO

- Remove or reduce service handling of private SSH key material as certificate
  based login flows replace break-glass key download.
- Re-evaluate whether this package should exist at all once SSH certificate
  flows are the normal path.

## Cross-Package Context

- [../internal/openstack](../internal/openstack/README.md) consumes this helper
  while provisioning OpenStack identities
- [../../apis/unikorn/v1alpha1](../../apis/unikorn/v1alpha1/README.md) defines
  the persisted `OpenstackIdentity` fields that currently store the generated
  key metadata and private key
- [../../openapi](../../openapi/README.md) exposes the current read-side API
  shape through which higher-order services can still receive this bootstrap
  material
