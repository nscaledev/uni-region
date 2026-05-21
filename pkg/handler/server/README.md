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
- create/update can validate and bind an SSH certificate authority
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
  host identity; the Kubernetes resource name is derived deterministically from
  `(networkID, serverName)` so a duplicate create collides at the Kubernetes
  layer and is rejected with HTTP 409 without a read-before-write; uniqueness
  is anchored to the name at creation time (the actual VM hostname, which
  OpenStack does not change) rather than to the mutable display label, so
  renaming a server does not free its original hostname slot

## Invariants And Guard Rails

- `v2` is the intended model; `v1` is compatibility surface only.
- direct `v2` object access is gated to resources labeled with
  `ResourceAPIVersionLabel=2`.
- A `Server v2` is owned by its network for cascading deletion.
- User data and SSH certificate authority combinations are validated together to
  avoid unsupported managed-userdata states.
- Power-operation errors are translated carefully from provider conflict/not-found
  states into user-facing API semantics.
- The Kubernetes resource name for a `v2` server is a deterministic UUID v5
  derived from `(networkID, serverName)` where `serverName` is the name
  supplied at creation time. Renaming a server via update does not change
  the Kubernetes resource name, so the original hostname slot remains
  permanently occupied — consistent with OpenStack not changing a VM's
  hostname after boot.
- Servers provisioned before this mechanism was introduced have random-UUID
  names and are not covered by it; deduplication applies only to resources
  created after deployment.

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
