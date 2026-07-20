# pkg/providers/internal/openstack

## Intention

`pkg/providers/internal/openstack` is the real cloud provider implementation
for OpenStack-backed regions.

It does not merely wrap the OpenStack SDK. It is the package that translates
the region service's storage model, tenancy model, metadata conventions, and
lifecycle rules into concrete OpenStack operations across identity, compute,
image, network, security group, load balancer, quota, and block storage
surfaces.

The most important philosophy in this package is the trust and scoping model:

- region-level `manager` authority is used only to provision and manage users
  and projects inside a managed Keystone domain
- once that scaffolding exists, most OpenStack operations deliberately context
  switch into the specific project provisioned for one Unikorn identity
- that OpenStack project then becomes the practical mapping, isolation, and
  accounting boundary between Unikorn resources and real cloud resources

That model is what makes it realistic for multiple regions or deployments to
share one underlying cloud while still limiting blast radius. It is also what
makes backchannel accounting and billing integration plausible, because the
project scope becomes the place where cloud resource usage can be tied back to a
specific Unikorn identity and its descendants.

The most important architectural rule is that this package prefers deterministic
lookup against OpenStack over maintaining broad mirrored OpenStack state in
Kubernetes. In older designs, dedicated `Openstack*` CRDs were used to persist
more provider-side state locally. That drifted from reality and introduced race
conditions. The current direction is:

- service-native CRDs remain the primary control objects
- OpenStack remains the source of truth for cloud-side resources where they can
  be re-found deterministically
- only the provider state that still cannot be reconstructed safely or
  sufficiently remains persisted locally, most notably `OpenstackIdentity`

This package therefore owns the mapping between:

- region-native CRDs and OpenStack resources
- service labels, tags, and metadata conventions
- per-identity delegated cloud credentials
- compensating local mechanisms where OpenStack is not sufficient on its own,
  such as image caching and provider-network VLAN allocation

## Links

- [../../../apis/unikorn/v1alpha1](../../../apis/unikorn/v1alpha1/README.md)
- [../../types](../../types/README.md)
- [../allocation/vlan](../allocation/vlan/README.md)
- [./ADMIN.md](./ADMIN.md)

`pkg/apis/unikorn/v1alpha1` defines the service-native resources and the
remaining persisted provider-state records this package consumes. `pkg/providers/types`
defines the provider-neutral contract this package implements. `pkg/providers/allocation/vlan`
covers the local VLAN allocator used when provider networks need segmentation IDs.
`ADMIN.md` keeps the human operator setup guidance for preparing an OpenStack
region.

## OpenStack Region Registration

An OpenStack-backed region should be registered with `hack/openstack/configure`
and `hack/openstack/register-region`, rather than by hand-creating the Keystone
domain, project, user, Kubernetes Secret, and `Region` manifest. That flow keeps
operator setup aligned with this package's scoping model: region-level provider
credentials are used to manage provider-domain scaffolding and discover region
inventory, while workload operations still context-switch into per-identity
OpenStack projects.

The full operator procedure lives in [./ADMIN.md](./ADMIN.md).

## Invariants And Guard Rails

- This package implements the full `types.Provider` contract for OpenStack
  regions.
- Provider construction has an explicit bootstrap/runtime split:
  - bootstrap uses uncached Kubernetes reads to assemble OpenStack service
    clients before controller-manager caches exist
  - runtime operation switches back to the normal Kubernetes client and refreshes
    derived OpenStack client state when region configuration or credentials
    change
- OpenStack access is intentionally scoped through different credential modes:
  - region-level service credentials bootstrap privileged service clients and
    managed-domain scaffolding
  - per-identity credentials are used for most project-scoped operations
  - some operations deliberately bind privileged credentials to a service
    principal's project when manager-level powers are required
  - pinned server creation is one of those privileged project-scoped operations:
    it still targets the identity project, but uses region-level credentials so
    Nova policy can authorise the requested destination
  - pinned server creation can also enable a transient
    `openstack.compute.placementPreflight` check. When enabled, the provider
    asks OpenStack Placement whether the pinned resource provider has available
    inventory for the flavor's positive custom `resources:*` extra spec and
    any `trait:*` extra specs, unioned with configured `requiredTraits`.
    Required flavor traits are sent as positive Placement `required` entries;
    forbidden flavor traits are sent as `!TRAIT` entries. Empty trait inputs
    mean no trait filter. A miss yields and lets the controller retry.
- SSH injection is a create-time server decision. OpenStack receives the
  identity key name only for the resolved `identityKeypair` mode; `ca` and
  `none` omit Nova `key_name`. Image rebuild omits both `key_name` and
  `user_data`, so Nova preserves the stored keypair and create-time user data
  (including the managed SSH-CA cloud-init baked in at create) and rebuilt guests
  stay create-equivalent. Updated user data therefore takes effect on server
  replacement, not rebuild — Nova accepts `user_data` on rebuild from
  microversion 2.57, deferred until gophercloud's `RebuildOpts` carries the field.
- A desired server image change is reconciled with Nova rebuild only once the
  server has booted at least once, decided from Nova's `launched_at`
  (`OS-SRV-USG:launched_at`) read fresh on the same `GetServer` — never from the
  monitor-stamped `status.launchedAt`/`status.provisionedAt` latches, which are
  observations and must not authorize the gate (observation is stimulus, never
  authorization; keying off them silently dropped image changes whenever the
  monitor had not yet recorded the first `ACTIVE`, and the clean-completing
  reconcile then let the API misreport the change as settled). Before first boot
  the desired image is a create parameter, not a rebuild target, so a pending
  image change on a server Nova reports with a zero `launched_at` defers: the
  reconcile yields, leaving the resource visibly `provisioning` and re-checking
  every 10s until first boot, then subsequent passes arm and submit the rebuild. A
  never-booted server Nova reports in `ERROR` is likewise deferred here — the
  reconcile pass yields silently without writing a health stamp (the monitor
  owns observed state) — and absorbed by the bounded provider-create
  delete-and-retry flow, which recreates it from the already-updated spec
  image. That retry adoption keys off the `Healthy=Errored` stamp the
  monitor's poll writes, so it takes effect at worst one poll later. This
  assumes the cloud exposes
  `OS-SRV-USG:launched_at` — the same signal the health monitor mirrors and the
  create-retry guard keys off. Deliberately not a goal: recreating a
  never-booted server rather than waiting for it to boot (e.g. a queued
  baremetal deploy, where recreate would skip a wasted provision) is a future
  optimization, rejected for now to avoid a third delete/recreate site and the
  known name-collision race.
- Rebuild intent is write-ahead. The marker is `Status.Rebuild`, a two-field
  struct: `TargetImageID` (the image this intent converges toward) and `State`
  (a forward-only enum `Initiated` < `Rebuilding` < `Succeeded` == `Failed`,
  the terminals being peers that never retreat and never flip
  terminal-to-terminal — first observation wins). Arming (recording the target
  at `Initiated`) and submitting to Nova happen in separate reconcile passes,
  with the yield between them acting as the durable commit point, so the
  marker is persisted — and read back on a later pass — before Nova can be
  asked to destroy the root disk. The marker records the one fact fresh
  observation cannot reconstruct: whether Region recently asked for a
  destructive rebuild.

  Ownership is split. Only the reconciler creates, replaces, or clears the
  marker, and only the reconciler parks; the monitor's poll only rank-advances
  `State` from observed evidence, never creating, clearing, or retargeting it
  (observation is stimulus, never authorization — the reconciler's settlement
  pass always re-decides from its own fresh `GetServer`). The forward-only
  rank check (`advanceRebuildState`) makes every advance monotone, so a late
  or duplicate observation, or two writers racing the same edge, can never
  retreat a state or flip a terminal. The one exception is the reconciler's
  park, which assigns `Failed` directly and may overwrite a `Succeeded`
  stamped moments before an `ERROR` arrived — a stale success left standing
  would otherwise re-fire the settlement wake forever on a parked server.

  Attribution ties a Nova observation to *this* rebuild by the image ref, not
  by spec match. Nova flips the ref to the target atomically with `task_state`
  at accept, and this protocol never submits when the fresh ref already equals
  the target, so a standing marker observed with `ref == target` always means
  an accepted rebuild toward it (ours, or a fail-closed-equivalent foreign
  same-image one). Activity is read from `OS-EXT-STS:task_state`, which is
  non-empty for the whole rebuild window and empty at rest (the `REBUILD`
  status is folded in defensively, since Nova projects it only from an active
  rebuild task). Convergence is therefore the conjunction `ref == target ∧
  stable non-error status ∧ task_state empty`: the ref flips at accept but
  `task_state` stays non-empty until the rebuild settles, so that conjunction
  is never observable while a rebuild is in flight, and it uniquely
  characterises completion. Both the monitor's `Succeeded` stamp and the
  reconciler's marker clear gate on it. This is what closes the accept-to-
  settle lag window: a stopped or errored server can display a stable
  `SHUTOFF`/`ERROR` throughout its rebuild, so a converged-looking status
  alone is not evidence of completion — `task_state` is the authoritative
  activity signal, and settlement is state-based rather than
  health-reason-based (`SHUTOFF` settles like any other stable status).

  The monitor (`advanceServerRebuildState`) advances: with `ref == target`,
  `ERROR` → `Failed`, an active task → `Rebuilding`, otherwise quiescent →
  `Succeeded`; with a readable off-target ref and the marker already durably
  `>= Rebuilding`, an `ERROR` or a quiesced task → `Failed` (supersession — an
  accepted rebuild whose ref has moved off the target can no longer converge);
  with an unreadable ref, only durable acceptance plus `ERROR` → `Failed`. An
  `Initiated` marker observed with `ref != target` advances nothing: an
  unattributed advance would falsely satisfy the submission gate and either
  wedge the rebuild or drive a second Nova accept.

  The reconciler's pass (`reconcileServerImage`) follows a fixed order. It
  replaces a marker whose target differs from the desired image (the re-arm
  recovery, allowed even over a parked `Failed` — a different image is the
  designed recovery), then classifies a park, then yields on an unreadable
  ref, then converges or submits. Park classification runs *before* the
  unreadable-ref yield so an attributable `ERROR` with an unverifiable ref
  parks rather than yielding forever. On a converged read with the marker
  present and the task empty, the pass clears the marker and yields so the
  requeued pass confirms the clear by read-back (marker absent → settled;
  marker still present → the write dropped → clear and yield again). A
  converged read with an active task and a non-terminal marker records the
  acceptance (`Rebuilding`) and completes the pass, because a future monitor
  rank-advance to a terminal is still guaranteed to wake the settlement pass;
  but a *terminal* marker can never rank-advance again, so a pass observing one
  it cannot yet settle yields rather than clean-completing, carrying liveness
  through its own requeue.

  The park is two-phase (`reconcileServerRebuildPark`). A deciding pass stamps
  `Failed` (by direct assignment) and yields; the terminal `UserActionRequired`
  return — which core turns into `Available=Errored`, the "parked" signal — is
  issued only by a pass that reads `Failed` back durable. The common case
  satisfies this on the first pass, because the monitor's own `Failed` stamp is
  the usual wake. A dropped pre-park stamp is recovered by read-back: the
  requeued pass re-enters the same branch (the evidence persists) and stamps
  again until a pass reads it back and parks. The park records the fresh-read
  health and retains the marker; the only re-arm is a different desired image
  or server replacement. Failure recovery is never data restoration.

  The submission (`submitServerRebuild`) is the single destructive step, gated
  on an `Initiated` marker read back durable plus a quiescent server, and it
  submits at most one accepted action per standing target image. On Nova's 2xx
  it advances to `Rebuilding` and writes a fixed accepted stamp (`Phase=Building`,
  `Healthy=False/Provisioning`, matching the monitor's `REBUILD` mapping so the
  two writers agree) — it never derives the stamp from the rebuild HTTP response
  body, whose server representation can still read `ACTIVE` for the
  pre-destruction server and would falsely stamp the just-accepted destructive
  rebuild as running. A Nova `409 Conflict` is pre-acceptance and yields
  silently, leaving the marker at `Initiated`.

  Pre-acceptance situations yield silently — a log line and the yield, nothing
  else — because no action was taken: the arming pass; a fresh read whose image
  ref is missing or unparseable (every server this provider creates is
  image-booted, so convergence cannot be checked and the pass must not report
  success over a dropped image change); a foreign or blocking op holding the
  task busy while the marker is still `Initiated`; and the Nova `409` at
  submission. A generic Nova `ERROR` under an unmoved-ref `Initiated` marker is
  intent without acceptance — unrelated, never a rebuild park (the remediation
  submit owns it) — and a marker-less `ERROR` never becomes a rebuild request.
  The reconciler writes `Phase`/`Healthy` only when it acts (a rebuild is
  accepted) or decides (a park); while it waits, the health monitor owns the
  observed state and the core-owned provisioning status on yield keeps the
  pending change user-visible. Because the reconciler no longer watches the
  rebuild converge tick by tick, a post-success ambiguity window — during which
  an unrelated Nova `ERROR` is indistinguishable from a failed rebuild and is
  treated as one — widens from a single reconcile requeue to at most one or two
  monitor poll cycles. This fails closed: recovery is selecting an image again
  or replacing the server, never data restoration.
- Nova rebuild retains the server UUID, network ports and IP relationships,
  attached data volumes, flavor, metadata, and placement, but recreates the
  root disk. It stays on the same compute host; evacuation is a separate
  operator workflow.
- `OpenstackIdentity` is the remaining persisted provider-state anchor. It
  currently stores the secret-bearing user/project/application-credential and
  bootstrap state needed to operate on behalf of a region `Identity`.
- The package relies heavily on deterministic naming and metadata conventions to
  re-find cloud-side resources. This is a convention-heavy contract, not magic:
  - identity-scoped resources use fixed generated names
  - network lookups rely on deterministic names
  - server metadata is written deliberately as both a control-plane lookup aid
    and an in-guest linkage surface exposed through the metadata service
  - legacy camelCase server metadata keys remain frozen for backwards
    compatibility while newer namespaced keys provide the upgrade path
- Flavor export is a hybrid model: OpenStack discovers the flavor inventory, but
  region configuration can enrich or override user-facing flavor metadata such
  as architecture, baremetal status, and GPU semantics. The baremetal flag is
  also operationally meaningful for live lifecycle (`Active` condition) reporting:
  a Nova `BUILD` server with a baremetal flavor is disambiguated through Ironic so the API
  can distinguish `Queued` (waiting on hardware) from `Building` (provider
  actively deploying).
- VolumeClass configuration follows the same inventory pattern for block
  storage. Region configuration under
  `openstack.blockStorage.volumeClasses.selector.ids` is a strict allowlist:
  only Cinder volume type IDs explicitly listed there are eligible for export.
  Missing `volumeClasses` configuration, a missing selector, or nil/empty IDs
  exports no VolumeClasses. Selected classes can be enriched with user-facing
  metadata such as media, maximum performance caps, and encryption signals. The
  provider discovers Cinder volume types and converts the selected/enriched
  result into provider-neutral `VolumeClass` values. Maximum performance
  metadata records caps rather than guaranteed reservations. `VolumeClass` is
  Region-scoped inventory configuration, not a project-owned resource or
  lifecycle object. The block-storage service client is cached with the other
  OpenStack service clients so Cinder volume-type inventory cache survives
  repeated provider calls and is refreshed only when Region configuration or
  credentials change. Production Region CRs must contain their curated IDs
  before this fail-closed behavior is rolled out.
- Image handling is a first-class contract surface here:
  - OpenStack image properties are validated against a schema
  - public images can additionally be signature-verified
  - image properties are translated into provider-neutral OS, package, GPU,
    ownership, virtualization, and tag metadata
  - an optional refresh-ahead cache exists because raw image API latency is too
    expensive to expose directly to every caller
- Quota and role behaviour are not purely discovered from OpenStack defaults.
  The package assumes and applies a managed-role model, including default role
  names such as `manager`, `member`, and `load-balancer_member`, unless region
  configuration overrides parts of that behaviour.
- Network, security group, and server resources are re-found in OpenStack by
  deterministic lookup rather than relying on mirrored `OpenstackNetwork`,
  `OpenstackSecurityGroup`, or `OpenstackServer` CRDs as authoritative state.
- Baremetal server progress uses Ironic as an additional provider truth source
  only while Nova reports `BUILD` for a flavor marked baremetal in region
  configuration. The result feeds `setServerActive`, which sets the `Active`
  condition to `Queued` (pre-deploy Ironic states: not yet picked up, cleaning,
  inspecting, etc.) or `Building` (Ironic actively deploying — including the
  post-deploy `Error` state and the transient `*Fail` states, on the principle
  that the node is still in the build pipeline as far as the platform is concerned
  and the failure signal belongs on the `Healthy` condition rather than on the
  `Active` condition. The node lifecycle eventually terminates via delete;
  splitting "in the pipeline" from "in the pipeline but unhappy" across both the
  `Active` and `Healthy` conditions would just duplicate one concept across two
  axes). Provisioning status itself is a separate axis (the `Available` condition),
  provisioner-owned and the monitor never writes it; `setServerActive`
  does, however, latch the monitor-owned `status.provisionedAt` field from Nova
  `launched_at` the first time a server is seen booted (write-once, never
  cleared, independent of live power state), which the controller's bounded
  provider-create delete-and-retry guard relies on (so a server that has booted
  is never destroyed and recreated). The image-rebuild gate does not read this
  latch: it authorizes from Nova `launched_at` read fresh each pass. Alongside it, `setServerMACAddress` records the other monitor-owned
  field, `status.macAddress`, from the Nova response once the server is `ACTIVE`
  (the port MAC rides inline in `addresses`, reused from the same `GetServer` — no
  extra call). ACTIVE is required because baremetal Ironic rebinds the port to the
  real NIC MAC asynchronously; the value is only ever written, never cleared. The lookup is
  filtered by `instance_uuid`. Because Ironic node ownership and visibility
  are provider infrastructure concerns rather than tenant workload operations,
  this lookup uses the Region top-level provider credentials scoped to the
  service principal's project, matching the package's other privileged client
  patterns. Deployments must grant those credentials enough Ironic policy
  visibility to list/detail nodes by instance UUID, for example through a
  narrow `bm-mapper`-style role or equivalent admin, service, or system-reader
  policy that permits `baremetal:node:list_all`/node-detail visibility. If the
  privileged client cannot be created or Ironic rejects or fails the lookup,
  the monitor logs the failure and falls back to the VM default `Building`
  `Active` state so API responses still see a coherent live signal rather than
  failing the monitor path.
- Some OpenStack list APIs are not safe to treat as exact lookup, notably
  server, network, and Octavia load-balancer `name` filters:
  - `name` filters behave like prefix or regular-expression matches rather than
    strict equality
  - this package therefore re-checks exact names after listing to avoid aliasing
    and false matches
- Provider networks that require VLAN segmentation use the local VLAN allocator
  because OpenStack does not allocate those IDs for us.

## Octavia Load Balancers

OpenStack load balancers are reconciled through Octavia in the service
principal's project. The region `LoadBalancer` CRD is still the desired-state
root, while Octavia remains the cloud-side source of truth for the realized
topology.

The provider reconciles the full topology:

- the Octavia load balancer and VIP
- listeners, pools, members, and optional health monitors
- the optional public floating IP attached to the Octavia-owned VIP port

Cloud-side lookup uses deterministic names:

- load balancer: `lb-{loadBalancer}`
- listener: `lb-{loadBalancer}-{listener}-listener`
- pool: `lb-{loadBalancer}-{listener}-pool`
- health monitor: `lb-{loadBalancer}-{listener}-monitor`

Those names are not just cosmetic. They are the linkage contract that lets the
provider re-find and converge existing Octavia resources without mirrored
provider-state CRDs. Octavia list filters are fuzzy in the same way as other
OpenStack name filters, so the client always post-filters returned resources by
exact name and treats duplicate exact matches as consistency errors.

Octavia provisioning status controls the reconcile outcome:

- `ACTIVE` allows the provider to continue reconciling the next part of the
  topology
- `PENDING_CREATE`, `PENDING_UPDATE`, and `PENDING_DELETE` yield the controller
  so the next pass can observe settled state
- any other state is treated as a consistency error because the provider cannot
  safely infer a valid next action

Mutable topology is converged in place where Octavia permits it:

- listener allowed CIDRs
- listener default-pool linkage
- TCP listener idle timeouts
- pool members
- health-monitor thresholds
- orphaned listeners, pools, and monitors whose deterministic names are no
  longer implied by the current spec

Other fields are intentionally blocked before they reach this provider. The
handler keeps existing listener protocol and port immutable, and it blocks
`proxyProtocolV2` drift for an existing listener name because that changes the
derived Octavia pool protocol, which Octavia does not allow to be updated in
place.

There are a few Octavia-specific constraints worth preserving:

- UDP listeners do not support idle timeouts or Proxy Protocol v2.
- UDP health checks use Octavia's UDP connect monitor type.
- TCP pools use Octavia `PROXYV2` only when `proxyProtocolV2` is enabled; the
  load-balancer client pins microversion `2.22` so that protocol is available.
- Floating IP cleanup runs before cascade-deleting the load balancer because the
  cascade removes the VIP port that otherwise anchors the floating IP lookup.

## Caveats

- This package is the convergence point of a large amount of platform policy,
  provider behaviour, and historical baggage. Its size reflects real behaviour,
  not just poor code hygiene.
- Deterministic lookup is the preferred direction, but the package still lives
  in a mixed world:
  - some cloud-side state is derived live from OpenStack
  - some transitional compatibility fields still exist in repo-native CRDs
  - `OpenstackIdentity` still persists state that the service would ideally stop
    owning over time
- Deterministic lookup is cleaner than mirrored CRDs, but it is still sensitive
  to convention drift. Renaming generated resources, changing metadata keys, or
  casually altering project-scoping assumptions can break the linkage between
  Unikorn resources, what OpenStack stores, and what users can see from inside
  provisioned servers.
- `OpenstackIdentity` should not be treated as permanently special. Its current
  survival is largely driven by implicit side effects and secret-bearing
  service-owned state that the architecture should work to remove:
  - ephemeral SSH key generation and download
  - implicit server-group creation
  - persisted service-principal/user/project/application-credential data
- Exposing application credentials to higher layers is current operational
  reality, not the desired end state. The package's scoping model helps contain
  blast radius today, while the wider platform works toward removing that
  exposure entirely.
- If the wider API moves toward explicit SSH certificate authority use, explicit
  server-group resources, and less implicit provider-side identity scaffolding,
  deleting `OpenstackIdentity` becomes more realistic.
- Image metadata translation is powerful but fragile. This package currently
  depends on OpenStack image properties carrying a large amount of semantic
  information correctly.
- Image query, get, create, delete, and snapshot flows are tightly coupled to
  the image cache path. When caching is disabled, large parts of the higher
  image contract are effectively unavailable rather than merely slower.
- The image query layer still contains its own comment admitting that some logic
  now operates on generic types and probably should not live here long term.
- Some older assumptions still leak through in status fields and helper paths,
  especially where compatibility with older API or storage shapes is still being
  carried.
- Rebuild settlement rests on two environmental facts about the target cloud,
  both worth an integration assertion rather than assumption. First, that Nova
  flips the image ref to the target *atomically* with setting `task_state` at
  accept: if a cloud made the ref visible before `task_state`, a poll could see
  the converged ref with an empty task inside the rebuild window and stamp a
  premature `Succeeded` — the accept-to-settle lag window this design closes by
  gating settlement on `task_state` emptiness would silently reopen. Second,
  that `OS-EXT-STS:task_state` is actually visible to the region service
  principal (its exposure is policy-gated, and an unexposed field decodes
  indistinguishably from "at rest"); without that visibility the same premature
  clear returns. A kind/devstack assertion that a just-accepted rebuild's GET
  shows a non-empty `task_state` covers both.

## TODO

- Delete the remaining mirror-state OpenStack CRD usage paths entirely:
  `OpenstackNetwork`, `OpenstackSecurityGroup`, and `OpenstackServer` should not
  survive as authoritative provider-state patterns.
- Continue shrinking the reasons `OpenstackIdentity` must exist:
  - remove service-handled private SSH key material in favour of explicit SSH
    certificate trust
  - stop relying on implicit server-group provisioning
  - move toward explicit API shapes where reconstructable state does not need to
    be persisted here
- Revisit image-query and image-metadata logic that now operates on
  provider-neutral types but still lives in this package because of historical
  coupling.
- Remove remaining compatibility writes and reads that depend on transitional
  CRD status shapes as those fields disappear from the wider system.

## Cross-Package Context

- [../../types](../../types/README.md) defines the neutral provider contract and
  intermediate types this package must satisfy
- [../../../apis/unikorn/v1alpha1](../../../apis/unikorn/v1alpha1/README.md)
  defines the service-native control objects and the remaining persisted
  provider-state records this package consumes
- [../../../handler](../../../handler/README.md) and specific handler packages
  depend on this package to make region API operations real against OpenStack
- [../allocation/vlan](../allocation/vlan/README.md) exists because this
  package needs a compensating local allocator for provider-network VLAN IDs
