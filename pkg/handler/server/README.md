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
- create/update validate the requested image through the provider layer under a
  single shared contract: the image must exist and be visible, be Ready, and be
  architecture/disk/virtualization compatible with the requested flavor. The
  two paths differ only in how a flavor the region no longer offers is treated:
  create rejects it with HTTP 422 (a create cannot proceed on retired
  hardware), while update tolerates it — the flavor is immutable and already in
  use by that exact server, so a retired flavor must not block an image update
  (e.g. a security-patch rebuild); the flavor-dependent compatibility checks
  are skipped because the flavor's metadata is unavailable, and Nova remains
  the backstop for a truly incompatible rebuild. An image reporting an
  unrecognized virtualization type fails closed with HTTP 422 — an unknown
  value is evidence of version skew or bad provider metadata, and the gate
  fronts a destructive root-disk rebuild. Absent metadata fails open on both
  axes: images lacking the virtualization property (out-of-band Glance
  uploads, images predating the label) or an architecture are not rejected,
  because absence of evidence is not evidence of incompatibility
- create/update can validate and bind an SSH certificate authority
- v2 reads project stored per-Volume attachment state only for the Server's
  current desired Volume set (attachment progress, optional provider device, and
  a safe message). This is status only; handlers do not claim Volumes or call
  providers in this slice.
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
- create can carry immutable `providerCreateGates`; reads expose only
  `status.remainingProviderCreateGates`, while the stored Kubernetes object
  retains per-gate status details for operators
- internal service callers can satisfy an existing provider-create gate through
  `POST /api/v2/servers/{serverID}/provider-create-gates`, which records the
  authenticated service actor, reason, and message on the status subresource
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
- a v2 update replaces the persisted `userData` wholesale — an omitted field
  clears the stored value. The value is never applied to the running guest; it
  is consumed by the next recreate. A rebuild (image change) re-runs the
  create-time user data, not the updated value — applying updated user data on
  rebuild is deferred until Nova's microversion 2.57 `user_data` field is wired
  through the client library
- the image is immutable through the v1 API: a v1 update carrying a different
  `imageId` succeeds but preserves the stored image (the rest of the update
  still applies). The `imageId` on a v1 update is ignored entirely and not
  validated — the value is discarded, so even one referencing a since-deleted
  image does not fail the update. The destructive rebuild contract below is
  exposed — and its compatibility validation enforced — only by v2, so v1 must
  never let the stored image drift from the running server. This preserves v1's
  historical accept-and-ignore behaviour for image changes, now enforced at the
  API boundary instead of falling out of the old create-only image handling in
  the provider.
- changing a v2 server's `imageId` is a destructive in-place Nova rebuild. It
  recreates the root disk and destroys its contents while retaining the server
  UUID, ports, fixed and floating IP relationships, attached data volumes,
  flavor, metadata, and placement. Flavor changes remain unsupported and are
  rejected with HTTP 422. An accepted rebuild destroys the previous root disk
  contents even if the rebuild subsequently fails, so failure recovery is
  choosing another image or replacing the server — never data restoration.
- while a rebuild is pending or in flight the v2 read reports
  `provisioningStatus=provisioning`, with one bounded exception: between an
  accepted v2 update and the first reconcile pass it triggers — one watch
  dispatch, typically sub-second, not a poll period — a read still reports
  `provisioned`, because the status is derived purely from the `Available`
  condition and only the reconciler rewrites that condition. This is deliberate:
  the read path performs no masking of its own (that machinery was removed with
  the rebuild marker). Once the reconciler runs it yields while an image change
  is outstanding, and core maps a yield to `Available=Provisioning`.
  `provisioned` means settled — which the sole consumer, uni-compute's instance
  settlement gate, relies on — and the target image is not realized until the
  rebuild converges. A rebuild
  that fails leaves the server `ERROR`, which surfaces as the server's phase, so the
  failure stays visible. See the provider's rebuild handling in
  [../../providers/internal/openstack/README.md](../../providers/internal/openstack/README.md).

## Invariants And Guard Rails

- `v2` is the intended model; `v1` is compatibility surface only.
- direct `v2` object access is gated to resources labeled with
  `ResourceAPIVersionLabel=2`.
- A `Server v2` is owned by its network for cascading deletion.
- User data is validated at create time, and at update time whenever the
  persisted value would change, against the server provisioner's cloud-init
  parser, so malformed payloads are rejected with HTTP 422 instead of failing
  mid-provision (when managed augmentation parses them) or silently inside the
  guest at boot. With an SSH certificate authority (on update, the server's
  current one — updates preserve the CA chosen at create) the payload must
  additionally support managed cloud-init augmentation (which excludes gzip);
  without one, gzip payloads are accepted and passed through unmodified.
  Unchanged user-data is never re-validated, so legacy servers whose stored
  payloads predate validation keep working when a client PUTs the same bytes
  back.
- `GET /api/v2/servers/{serverID}/sshkey` only returns the identity private key
  for servers where Region requested `identityKeypair` SSH injection during
  create. It returns not found for `ca` and `none` servers.
- Power-operation errors are translated carefully from provider conflict/not-found
  states into user-facing API semantics.
- `infrastructureRef` is create-time placement input. Updates preserve the
  existing value and the CRD marks it immutable, because moving an existing
  server to a different physical host is not an in-place server update.
- `providerCreateGates` is create-time coordination input. Updates preserve the
  existing gate list and the CRD marks it immutable; only Region writes the
  derived status entries.
- The provider-create gate action has its own
  `region:servers:v2/provider-create-gates` permission. It also requires normal
  server read access because callers must not satisfy gates on servers they
  cannot see.
- The Kubernetes resource name for a `v2` server is a deterministic UUID v5
  derived from `(networkID, serverName)` at creation time, making the name
  immutable for the lifetime of the resource — consistent with OpenStack not
  changing a VM's hostname after boot.
- Servers provisioned before this mechanism was introduced have random-UUID
  names and are not covered by it; deduplication applies only to resources
  created after deployment.
- Image rebuild submits at most one Nova-accepted action per target image. A rebuild that fails
  leaves the server on the desired image in `ERROR`; there is no automatic retry, and
  recovery is another image update or server replacement.

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
