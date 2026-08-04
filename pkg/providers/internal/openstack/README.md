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
- [../../allocation/vlan](../../allocation/vlan/README.md)
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
  every 10s until first boot, after which a pass submits the rebuild once the
  server is quiescent. A
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
- `reconcileServerImage` decides entirely from the fresh `GetServer` on the same
  pass.

  Nova commits the image ref and `task_state` together. `nova/compute/api.py` sets
  `task_state = REBUILDING` and `image_ref = image_href` on one object and saves them
  with `expected_task_state=[None]` — a database compare-and-swap — *before*
  `_record_action_start` and before the RPC cast to the compute node, all inside the
  synchronous request. Three consequences the pass rests on: there is no interleaving
  in which a reader sees the new ref without an active rebuild task; the state is
  durable before the client receives its 202; and two concurrent rebuilds cannot both
  commit, the loser raising `UnexpectedTaskStateError`. Nova's own state check
  (`check_instance_state`, whose default requires `task_state` NULL) refuses a rebuild
  against a rebuilding server with a 409 before that. All of this is decided in Nova's
  API layer above the driver, so it holds for Ironic exactly as for libvirt.

  The pass order, deciding only from the fresh read:

  | | Condition | Action |
  |---|---|---|
  | R1 | `Spec.Image == nil` | **park** |
  | R2 | image ref unreadable | **park** |
  | R3 | ref == desired, rebuild task active | yield |
  | R3′ | ref == desired, `ERROR`, launched | **park** |
  | R3″ | ref == desired, otherwise | done |
  | R4 | ref != desired, `launched_at` zero | yield |
  | R4′ | ref != desired, any task active | yield |
  | R4″ | ref != desired, quiescent | **submit** |

  R2 exists because every server this provider creates is image-booted, so an absent,
  empty or unparseable ref is abnormal: the pass must not report success over an image
  change it cannot verify. The park is re-derived per pass, so a later readable ref
  un-parks it without any spec change.

  `serverRebuildInFlight` tests Nova's own `rebuild_states` family
  (`rebuilding`, `rebuild_block_device_mapping`, `rebuild_spawning` — matched by the
  `rebuild` prefix, so a substate a newer Nova adds still reads as in flight rather
  than as settled over a disk being rewritten — plus the `REBUILD` status projected
  from the same family), because on a converged ref the question is specifically
  whether *a rebuild* is running — an unrelated task such as a user's reboot must not
  be reported as one. `serverTaskActive` tests any task at all, because before
  submitting the question is only whether Nova would accept, and it refuses while any
  task holds the server.

  R3′ parks a quiesced `ERROR` on the desired ref as user-action-required
  (`provisioners.UserActionRequired`, so `provisioningStatus=error` with an
  actionable, cause-neutral message that advertises the spec-edit remedy),
  mirroring create-retry's exhausted-attempts park. The
  ref moves at *accept*, not on a successful write, so this state means the spec
  image was never realized and must not read as `provisioned` (INST-1235: measured
  on kolla 2025.1, a failed rebuild deploy settles exactly here within seconds on
  both the sushy and fake-controllable fixtures). The park does not claim to
  attribute the `ERROR` to the rebuild — an unrelated host failure after a
  successful rebuild presents identically — but under either cause the spec is
  unrealized, so `error` is the honest report on the provisioning axis; the
  monitor's health axis carries the ambient view on its own cadence. Deferring the
  report to the monitor instead was measured to lose short-lived failures
  entirely: the reconciler settles in one 10s yield cycle while the monitor
  samples at one-minute cadence. Never-launched servers are excluded from the
  park (an `ERROR` before first boot is a failed create, owned by the
  provisioner's bounded retry machinery).

  A parked server has no requeue, so it un-parks on exactly two paths. The user
  edits the spec — the remedy the message advertises — and the generation-change
  wake resumes reconciliation, monitor-independent. Or the provider recovers
  without a spec change, in which case the un-park rides the monitor's
  `status.observed` write firing the observed wake: the park is re-derived per
  pass, so the woken pass walks to R3″ and reads `provisioned` again (the same
  measured path as a foreign recovery, below — within one monitor period).

  The provisioning axis reports *spec-realization*, not attribution. A
  rebuild-class operation this provider did not submit — `nova evacuate` is
  implemented as a rebuild, presenting `task_state=rebuilding` with the ref
  already on the spec image — therefore reads exactly as ours when a pass runs.
  Measured behaviour: an in-flight foreign rebuild does not move the
  provisioning axis at all (a foreign operation generates no reconciler wake —
  no spec change, no observed change — so R3 never runs; only the monitor's
  phase and health axes read `Rebuilding`/`Unknown` for one poll cycle), a
  *failed* foreign rebuild parks via the observed-errored wake within one
  monitor period, and a foreign recovery un-parks the same way. A foreign
  rebuild onto a *different* image — succeeded or failed — is auto-reverted:
  the ref flip changes `observed.image`, the wake fires, and R4″ resubmits
  toward the spec image (measured: ~20s from the foreign act to the corrective
  rebuild). The park is therefore scoped precisely to failures on the
  *converged* ref, where the spec image itself is implicated; divergent-ref
  failures are reconverged instead. Operational consequence: operators must
  change the spec, never act through Nova — a Nova-side image change is undone
  within seconds. This is deliberate. During any rebuild-shaped operation the
  server is not serving its spec — a rebuild is rewriting the root disk, while an
  evacuation on shared storage rebuilds the instance on another host without
  touching it — so `provisioning` is honest; after a failed one the spec image is
  not running. Both reports are true regardless of who initiated the operation, and
  no destructive row can fire on a foreign operation (R4″ requires a diverged
  ref, which a foreign rebuild does not present). The park is re-derived per
  pass, not latched: when a foreign recovery returns the server to `ACTIVE` on
  the converged ref, the next pass walks to R3″ and the server reads
  `provisioned` again. What this costs is attribution in the *messages* — a
  failed evacuation reports the same cause-neutral park message as a failed
  rebuild — which is the price of having no persisted intent to consult, and
  why the message names neither.

  R4 defers to the create-retry path rather than duplicating it, and Nova enforces the
  same precondition itself (`must_have_launched`).

  R4″ is the single destructive step. The submission (`submitServerRebuild`) writes a
  fixed accepted stamp on a 2xx (`Active` `Rebuilding`, `Healthy` `Unknown`, matching
  the monitor's `REBUILD` mapping so the two writers agree rather than churn) and never
  derives it from the rebuild response body, whose 202 can still describe the
  pre-destruction server as `ACTIVE` and would stamp a just-accepted destructive
  rebuild as running. Acceptance *yields* rather than completing: Nova now has a
  destructive operation in flight, and completing would map to
  `Available=Provisioned` and report a server whose root disk is being rewritten as
  settled. A `409` is pre-acceptance — the server is untouched — so it
  also yields, silently, for a short retry.

  Nova's accept gate refuses an unresolvable or non-`active` image, an image
  whose `min_ram`/`min_disk` exceeds the flavor, non-bootable image properties, a
  locked or wrongly-stated instance, and quota — all *before* writing any state.
  `status.observed` structurally cannot carry the rejection, so the body stays
  in the log and never reaches the API surface. A synchronous HTTP 400 parks
  the server as user-action-required (a spec edit resumes it) only when the
  body carries Nova's image-not-found signature ("Cannot find image for
  rebuild") — the one refusal that provably cannot self-heal. Nova 400s are
  not homogeneous: a *deactivated* image (`ImageNotActive`) is also a 400, but
  an operator reactivating it bumps no generation and moves no observed field,
  so parking it would strand the server; it retries instead and converges on
  the pass after reactivation. Every other 400 — and a reworded or stripped
  body — likewise surfaces as the pass's error and retries, failing safe
  toward the retry loop rather than toward a wrong park. An HTTP 409 yields
  awaiting quiescence, and every other rejection class surfaces as the pass's
  error and retries on the yield interval.

  The reconciler writes `Active`/`Healthy` when it acts and re-asserts the
  accepted stamp while a rebuild it submitted is still in flight (R3); on every other
  waiting row it writes nothing and the monitor owns observed state.
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
  - Cinder volumes use `volume-{Region Volume UUID}` inside the service
    principal's project; create, delete, attach, and detach rediscover that
    exact name
  - server metadata is written deliberately as both a control-plane lookup aid
    and an in-guest linkage surface exposed through the metadata service
  - legacy camelCase server metadata keys remain frozen for backwards
    compatibility while newer namespaced keys provide the upgrade path
- Cinder Volume create/delete is a project-scoped lifecycle slice:
  - the Region Volume controller resolves the full cloud provider and drives
    its Volume capability after the service-principal Identity is ready
  - the native Region `Volume` CRD supplies the requested size and
    `VolumeClassID`, which becomes the Cinder volume type
  - create lists by the stable generated name and exact-matches the result
    before submitting a create, so controller retries adopt an existing volume
    rather than duplicating it
  - an accepted Cinder create is partial progress rather than success: the
    provider yields after submission and on subsequent rediscovery until the
    volume reports `available`; all unrecognized non-error states also yield so
    an unfamiliar provider state cannot be mistaken for convergence
  - a Cinder status beginning with `error` returns a typed terminal
    `Available=False`, `Reason=Errored` result with the user-safe message
    `provider volume entered an error state`; provider IDs, scheduler failures,
    host details, and other raw Cinder diagnostics remain operator-only
  - user tags are translated with the package's normal namespaced metadata
    convention; namespaced system linkage keys are written last so user input
    cannot override identity, organization, project, region, network, or Volume
    IDs; Volume metadata does not emit the legacy camelCase compatibility keys
    retained by older resource types
  - delete uses the same rediscovery path, treats a missing Cinder volume as
    success, yields after Cinder accepts an asynchronous delete until a later
    rediscovery confirms absence, and treats an absent or not-yet-project-backed
    `OpenstackIdentity` as proof that no provider volume could have been
    created; this lets controller deletion delegate unconditionally before
    releasing any Identity allocation
  - general observed size/status mapping and VolumeClass inventory are outside
    this lifecycle slice; the narrow status classification above exists only to
    determine create convergence, while Nova attach/detach is the separate
    server-owned provider slice described below
- Flavor export is a hybrid model: OpenStack discovers the flavor inventory, but
  region configuration can enrich or override user-facing flavor metadata such
  as architecture, baremetal status, and GPU semantics. Architecture resolves
  from per-flavor `cpu.architecture`, then `openstack.defaultArchitecture`,
  then the legacy `x86_64` fallback for objects that bypass CRD defaulting. The
  baremetal flag is
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
  metadata such as optional minimum/maximum capacity bounds, a
  `supportedFlavors` selector, media, maximum performance caps, and encryption
  signals. Omitted selectors and omitted or empty selector IDs mean unrestricted
  compatibility; the provider resolves this operator-authored selector to the
  neutral Flavor ID allowlist and does not infer it from Cinder volume types.
  Capacity bounds are
  operator-authored positive whole GiB values; either may be omitted, and when
  both are present the maximum must be at least the minimum. The provider
  discovers Cinder volume types and combines them with this Region-authored
  metadata into provider-neutral `VolumeClass` values. It does not discover
  capacity bounds from Cinder. Maximum performance metadata records caps rather
  than guaranteed reservations. `VolumeClass` is Region-scoped inventory
  configuration, not a project-owned resource or lifecycle object. The
  block-storage service client is cached with the other OpenStack service
  clients so Cinder volume-type inventory cache survives repeated provider
  calls and is refreshed only when Region configuration or credentials change.
  Production Region CRs must contain their curated IDs before this fail-closed
  behavior is rolled out.
- Existing-volume server attachments are a separate, project-scoped write path
  from Region-scoped `VolumeClass` inventory. The provider creates ephemeral
  compute and block-storage clients from the service principal, rediscovers the
  Nova server and detailed Cinder volume, and uses Cinder's attachment rows as
  the normal-path observation before calling Nova's volume-attachment
  create/delete API. Cinder volume lifecycle observation is not part of this
  slice. The Cinder name filter is treated as fuzzy and is post-filtered against
  the exact stable name `volume-{Volume.Name}`; duplicate exact matches fail
  closed with `ErrConsistency`. Only the optional guest device name crosses the
  provider-neutral boundary; Nova and Cinder IDs and Gophercloud objects remain
  internal.

  Attachment behavior is deliberately asymmetric:
  - attach requires both the server and volume; either missing resource maps to
    `ErrResourceNotFound`
  - a Cinder attachment already present on the requested server is successful
    and returns its observed device without a Nova read
  - an attachment to any other server maps to `ErrConflict`; Region does not
    support multi-attach even when the Cinder volume is multiattach-capable
  - when Cinder reports no attachment, attach calls Nova create directly; a
    create `409 Conflict` is followed by one Nova attachment read so concurrent
    creation of the same desired attachment becomes success, while an
    unresolved conflict maps to `ErrConflict`
  - detach calls Nova delete only when Cinder reports an attachment to the
    requested server; a missing server, volume, requested-server attachment, or
    Nova delete `404` is success because detached state already holds, including
    when the volume remains attached only to another server
  - a Nova delete `409 Conflict` maps to `ErrConflict`; other provider failures
    are preserved
  - detach also no-ops when the backing OpenStack identity was never realized,
    matching the provider's other teardown contracts

  Attachment intent and observed rows remain on `Server.Spec.Volumes` and
  `Server.Status.Volumes`; this provider slice does not mirror attachments into
  `Volume.Status`, claim volumes, or reconcile server controllers.
- Image handling is a first-class contract surface here:
  - OpenStack image properties are validated against a schema
  - public images can additionally be signature-verified
  - image properties are translated into provider-neutral OS, package, GPU,
    ownership, virtualization, and tag metadata
  - an explicit Glance `architecture` property wins; otherwise image conversion
    uses `openstack.defaultArchitecture`, with the same defensive legacy
    `x86_64` fallback as flavor conversion
  - an optional refresh-ahead cache exists because raw image API latency is too
    expensive to expose directly to every caller
- Quota and role behaviour are not purely discovered from OpenStack defaults.
  The package assumes and applies a managed-role model, including default role
  names such as `manager`, `member`, and `load-balancer_member`, unless region
  configuration overrides parts of that behaviour.
- Network, security group, server, and Volume resources are re-found in OpenStack by
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
  real NIC MAC asynchronously; the value is only ever written, never cleared.
  `GetServer` resolves by name, which forces a list, and **the list response can omit
  `fault` entirely** on Nova up to 2025.2, so a listed errored server carries no
  fault detail. `GetServer` itself does not compensate: the fault is operator log
  detail, not part of the returned server, so it is fetched by a dedicated by-ID
  read exactly once, on the observed transition into the errored state, and
  written to the observation log — status records only the neutral
  `observed.errored` marker. Best-effort: a failed fetch logs the transition
  without the detail rather than failing anything, because the fault is an
  enrichment and not the reason for the read; healthy servers, and servers
  already known to be errored, never pay the extra call.
  `setServerObservedStatus` records the monitor's `status.observed` region from the
  `GetServer` response: `generation` unconditionally, the image via `openstackServerImageID`
  (an unreadable ref preserves the previous value rather than clearing it), and
  the neutral `errored` marker when Nova reports `ERROR`. The marker is gated on
  `Status == "ERROR"` and not on `Fault` being populated, because Nova leaves a
  stale `fault` on a recovered server, so keying off the struct would report a
  cleared failure forever. The logged detail is the fault's code, message, and
  created timestamp; `fault.details` is excluded as an admin-only stack trace,
  and nothing from the fault reaches projected status. The Ironic lookup is
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
  server, network, Cinder volume, and Octavia load-balancer `name` filters:
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
- Rebuild rests on one environmental fact about the target cloud: that
  `OS-EXT-STS:task_state` is actually visible to the region service principal. Its
  exposure is policy-gated, and an unexposed field decodes indistinguishably from "at
  rest" — so without it a foreign operation would not be seen to hold
  the server, and Nova's 409 becomes the only guard. It was visible
  to a project-scoped admin credential on a kolla 2025.1 all-in-one.

  `OS-SRV-USG:launched_at` is likewise policy-gated and is now load-bearing for
  the image-row decisions — the before-first-boot deferral and the
  never-launched exclusion on the failed-rebuild park — so a cloud hiding it
  breaks those rows the same way a hidden `task_state` breaks the in-flight
  tests.

  Measured on the **libvirt** driver — the first GET after accept, at 260 ms
  with 1 s polling, already showed the target ref together with
  `task_state='rebuilding'`. The failure side is atomic the same way: an
  asynchronous failure moved `REBUILD`→`ERROR` and cleared `task_state` within a single
  observation, so a failed rebuild never presents as a settled one.

  The same contract holds on the **Ironic** driver (measured on sushy-tools
  virtual metal): the ref and `task_state` flip together at accept, the rebuild
  task states stay visible through the whole redeploy, and a failed redeploy
  settles `ERROR` with the ref **still on the target** — it never reverts, which
  is what keeps a failed rebuild from re-satisfying the submission row. The node
  lands in `deploy failed`, and a rebuild toward another image recovers both
  server and node without operator action.

  - **Do not raise the compute client microversion past 2.92.** From 2.93 Nova
    sets `reimage_boot_volume` on every rebuild and the Ironic driver refuses the
    flag outright — volume-backed or not — so every baremetal rebuild fails. An
    upstream defect, unfixed as of 2025.1
    (https://bugs.launchpad.net/nova/+bug/2127017). The client pins 2.90.
  - Ironic node reads require a *system-scoped* credential — project-scoped admin
    lists nodes but 404s on node detail — so `task_state` visibility has an Ironic
    sibling that needs its own credential arrangement.
- A rebuild toward a nonexistent image is rejected *synchronously* (HTTP 400,
  "Cannot find image for rebuild") and touches nothing: the server stays on its
  image, no wipe, no `ERROR`. Nova resolves the image before mutating anything,
  so a bad image ID can never produce a converged-looking ref on a broken server.
  The controller parks only this signature ("Cannot find image for rebuild",
  matched in the 400 response body) as user-action-required, since a deleted
  image can never be re-resolved and the remedy is a spec edit. Other rebuild
  400s retry: notably `ImageNotActive` from a *deactivated* Glance image,
  which an operator can clear with an image reactivation that bumps no
  generation and moves no observed field — a park there would have no recovery
  path. An HTTP 409 yields awaiting quiescence, and every other rejection
  class retries. A valid image Nova can resolve but qemu cannot use
  (measured with a truncated qcow2, which Glance accepts as `active`) behaves
  the opposite way: accepted, ref flipped, then an asynchronous failure to
  `ERROR`. Its fault carries `code: 400` despite the request having been
  accepted, so a 4xx in a recorded provider error does not imply the request
  was rejected.

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
- [../../allocation/vlan](../../allocation/vlan/README.md) exists because this
  package needs a compensating local allocator for provider-network VLAN IDs
