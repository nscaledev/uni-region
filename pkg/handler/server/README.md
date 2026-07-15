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
- create accepts an explicit SSH injection mode: `ca`, `identityKeypair`, or
  `none`. Omitted values preserve the legacy contract: requests with
  `sshCertificateAuthorityId` resolve to `ca`, all other requests resolve to
  `identityKeypair`. Pinned servers cannot use `identityKeypair` because it is
  scoped to the tenant credentials and is not valid for the privileged
  pinned-create path
- create/update reject references that escape the server's scope, enforced at the
  API edge with HTTP 422. The RBAC read check that fetches a reference only proves
  the caller may see it — a caller authorized across several tenancies could
  otherwise attach a resource from another tenancy — so an explicit scope check is
  applied on top:
  - a referenced security group must belong to the same **network** as the server.
    A network belongs to exactly one identity (one underlying OpenStack project),
    which belongs to one organization and project, so same-network is the natural
    granularity that closes the cross-tenancy hole and matches what OpenStack itself
    permits. The owning network is exposed identically in region (the `NetworkLabel`)
    and in the read model the compute service consumes (`status.networkId`), so the
    same rule is enforced uniformly across both services.
  - a referenced SSH certificate authority (which is not network-scoped) must share
    the server's organization and project.
- create can carry an `infrastructureRef` that pins initial placement to a
  provider-specific physical host; reads expose the value in status so callers
  can verify the placement request that was persisted
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
  layer and is rejected with HTTP 409 without a read-before-write
- server names are immutable after creation; update requests that supply a
  different name are rejected with HTTP 422
- changing a v2 server's `imageId` is a destructive in-place Nova rebuild. It
  recreates the root disk and destroys its contents while retaining the server
  UUID, ports, fixed and floating IP relationships, attached data volumes,
  flavor, metadata, and placement. Flavor changes remain unsupported and are
  rejected with HTTP 422.
- `POST /api/v2/servers/{serverID}/rebuild/retry` re-arms the same desired image
  only after an accepted Region-issued rebuild has failed. It does not select a
  new image, move the server, or recover a failed compute host.

## Invariants And Guard Rails

- `v2` is the intended model; `v1` is compatibility surface only.
- direct `v2` object access is gated to resources labeled with
  `ResourceAPIVersionLabel=2`.
- A `Server v2` is owned by its network for cascading deletion.
- User data is validated at create time against the server provisioner's
  cloud-init parser, so malformed payloads are rejected with HTTP 422 instead of
  failing mid-provision (when managed augmentation parses them) or silently
  inside the guest at boot. With an SSH certificate authority the payload must
  additionally support managed cloud-init augmentation (which excludes gzip);
  without one, gzip payloads are accepted and passed through unmodified.
- `GET /api/v2/servers/{serverID}/sshkey` only returns the identity private key
  for servers where Region requested `identityKeypair` SSH injection during
  create. It returns not found for `ca` and `none` servers.
- Power-operation errors are translated carefully from provider conflict/not-found
  states into user-facing API semantics.
- `infrastructureRef` is create-time placement input. Updates preserve the
  existing value and the CRD marks it immutable, because moving an existing
  server to a different physical host is not an in-place server update.
- The Kubernetes resource name for a `v2` server is a deterministic UUID v5
  derived from `(networkID, serverName)` at creation time, making the name
  immutable for the lifetime of the resource — consistent with OpenStack not
  changing a VM's hostname after boot.
- Servers provisioned before this mechanism was introduced have random-UUID
  names and are not covered by it; deduplication applies only to resources
  created after deployment.
- Image rebuild automatically submits at most one Nova-accepted action for a
  target image and rebuild generation. A failed accepted action requires an
  explicit retry, another image update, or server replacement.

## Caveats

- This package is partly CRUD handler and partly operational façade over the
  provider compute API.
- Snapshot behaviour is coupled to image provenance and ownership semantics, so
  server is not fully self-contained as a lifecycle concept.
- Some semantics, such as user-data validation, are important but narrow enough
  that they should stay local to this package; the parser itself is owned by the
  server provisioner so the boundary check and provisioning behaviour cannot
  drift apart.

## TODO

- Delete the deprecated `v1` handler surface once migration is complete.

## Cross-Package Context

- [../network](../network/README.md) documents the parent linkage model for
  `v2` servers
- [../sshcertificateauthority](../sshcertificateauthority/README.md) documents
  the referenced SSH CA resource model
- [../securitygroup](../securitygroup/README.md) documents the referenced
  security group resource model
- [../image](../image/README.md) documents the image-side semantics that
  snapshot creation feeds into
