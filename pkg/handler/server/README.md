# Server

## Purpose

`pkg/handler/server` handles compute-server lifecycle.

It contains both deprecated `v1` paths and the preferred `v2` model, but the
package is worth documenting separately because server handling is richer than
basic CRUD:

- create/update/delete
- power operations
- console access
- snapshot creation
- stronger validation of referenced resources

In `v2`, server context is primarily inferred from the selected network and
related dependencies rather than from nested path scope.

## Distinctive Behaviour

- `v1` servers are nested more explicitly under identity paths
- `v2` servers are network-linked resources with direct ID-based access
- create/update validate referenced image existence through the provider layer
- create/update can validate and bind an SSH certificate authority; update can
  move the control-plane reference to a replacement CA without treating the
  original CA as permanently locked to the Server record
- snapshot creation bridges server lifecycle into image provenance semantics
- snapshot creation is also a cross-resource permission bridge: the caller must
  already be able to see the server and also be allowed to create images in the
  owning organization
- the package exposes operational verbs:
  - start
  - stop
  - soft reboot
  - hard reboot
  - console output/session
- server-name uniqueness is enforced per network to avoid aliasing cloud-side
  host identity

## Invariants And Guard Rails

- `v2` is the intended model; `v1` is compatibility surface only.
- direct `v2` object access is gated to resources labeled with
  `ResourceAPIVersionLabel=2`.
- A `Server v2` is owned by its network for cascading deletion.
- User data and SSH certificate authority combinations are validated together to
  avoid unsupported managed-userdata states.
- Omitting `sshCertificateAuthorityId` on update preserves the current CA for
  backwards compatibility; providing a different value validates and stores that
  replacement.
- Power-operation errors are translated carefully from provider conflict/not-found
  states into user-facing API semantics.

## Caveats

- This package is partly CRUD handler and partly operational façade over the
  provider compute API.
- Snapshot behaviour is coupled to image provenance and ownership semantics, so
  server is not fully self-contained as a lifecycle concept.
- Some semantics, such as managed user-data validation for SSH CA use, are
  important but narrow enough that they should stay local to this package.

## TODO

- Delete the deprecated `v1` handler surface once migration is complete.

## Cross-Package Context

- [../network](../network/README.md) documents the parent linkage model for
  `v2` servers
- [../sshcertificateauthority](../sshcertificateauthority/README.md) documents
  the referenced SSH CA resource model
- [../image](../image/README.md) documents the image-side semantics that
  snapshot creation feeds into
