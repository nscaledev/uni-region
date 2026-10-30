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
    mean no trait filter. A miss is a recheck: the host is not moving, so the next poll looks again.
  - a miss splits the same way the image rows do: the host, resource class and
    required traits go to the log, and the condition gets wording we choose.
    None of that detail is on the API — the resource class and flavor traits are
    Nova extra specs and `requiredTraits` is region config — so it would be
    provider vocabulary on a surface the caller cannot act on. The wait is
    a typed `Recheck(DependencyNotReady)`, because a pinned host is a dependency and is not
    the user's own server.
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
  stamped `status.launchedAt`/`status.provisionedAt` latches, which are
  observations and must not authorize the gate (observation is stimulus, never
  authorization; keying off them silently dropped image changes whenever the
  latch had not yet been set, and the clean-completing reconcile then let the
  API misreport the change as settled). Before first boot
  the desired image is a create parameter, not a rebuild target, so a pending
  image change on a server Nova reports with a zero `launched_at` defers: the
  reconcile yields, leaving the resource visibly `provisioning` and re-checking
  every 10s until first boot, after which a pass submits the rebuild once the
  server is quiescent. A
  never-booted server Nova reports in `ERROR` is likewise deferred here (the
  yield is named on the `Available` condition) and absorbed by the bounded
  provider-create delete-and-retry flow, which recreates it from the
  already-updated spec image. That retry adoption keys off the errored lifecycle
  stamp, which the pass now projects itself, so it takes effect on the next pass
  rather than at worst one poll later. This
  assumes the cloud exposes
  `OS-SRV-USG:launched_at` — the same signal the projection mirrors and the
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
  | R1 | `Spec.Image == nil` | user action required |
  | R2 | image ref unreadable | **recheck** |
  | R3 | ref == desired, rebuild task active | yield |
  | R3′ | ref == desired, `ERROR`, launched | **recheck** |
  | R3″ | ref == desired, otherwise | done |
  | R4 | ref != desired, `launched_at` zero | yield |
  | R4′ | ref != desired, any task active | yield |
  | R4″ | ref != desired, quiescent | **submit**, or recheck if the image is gone |

  Every yielding row returns `provisioners.Yield` with a `Provisioning` reason
  and a message naming the wait, so the row a server is waiting on is readable
  from its `Available` condition. That matters because the rows are not
  equivalent — R3 is our own rebuild, R4 is a server that has never booted, R4′ is
  someone else's operation — and a bare `ErrYield` renders them identical: the
  manager only lifts a reason and message off a typed `provisioners.Error`, so a
  bare sentinel leaves the generic default with no message at all. Provider
  vocabulary (Nova status, `task_state`) stays in the log line; the condition
  gets only user-safe wording.

  The reason stays `Provisioning` here, and only the message varies. `reason` is
  API surface — it projects to `provisioningStatusDetail.reason` and callers
  script against it — so it has to describe the wait accurately. None of these
  rows is a `DependencyNotReady`: that means a dependency exists but is not yet
  provisioned, whereas every row above is waiting on the user's own server to
  finish something. Naming them `DependencyNotReady` would send a user looking
  through their networks and security groups for a fault that is not there. The
  provider-create gate is the one wait in the server path that does use
  `DependencyNotReady`, because another service genuinely satisfies it.

  R2 exists because every server this provider creates is image-booted, so an absent,
  empty or unparseable ref is abnormal: the pass must not report success over an image
  change it cannot verify. It is a recheck, so a later readable ref clears it at
  the next poll without any spec change.

  `serverRebuildInFlight` tests Nova's own `rebuild_states` family
  (`rebuilding`, `rebuild_block_device_mapping`, `rebuild_spawning` — matched by the
  `rebuild` prefix, so a substate a newer Nova adds still reads as in flight rather
  than as settled over a disk being rewritten — plus the `REBUILD` status projected
  from the same family), because on a converged ref the question is specifically
  whether *a rebuild* is running — an unrelated task such as a user's reboot must not
  be reported as one. `serverTaskActive` tests any task at all, because before
  submitting the question is only whether Nova would accept, and it refuses while any
  task holds the server.

  R3′ reports a quiesced `ERROR` on the desired ref with `provisioners.Recheck`,
  so `provisioningStatus=error` with an actionable, cause-neutral message, and
  is looked at again at the next poll. The
  ref moves at *accept*, not on a successful write, so this state means the spec
  image was never realized and must not read as `provisioned` (measured on kolla
  2025.1: a failed rebuild deploy settles exactly here within seconds on both the
  sushy and fake-controllable fixtures). The report does not claim to
  attribute the `ERROR` to the rebuild — an unrelated host failure after a
  successful rebuild presents identically — but under either cause the spec is
  unrealized, so `error` is the honest report for provisioning. The same
  pass projects the lifecycle and health conditions from the same read.
  Never-launched servers are excluded (an `ERROR` before first boot is a failed
  create, owned by the provisioner's bounded retry machinery).

  **R2 and R3′ are rechecks.** Both are states the provider can leave on its
  own — an operator resets the server, a host comes back. A recheck is looked at
  again at the poll slot, not on the 10s yield timeout, so a fleet hit by one
  fault costs one pass per server per period. A server deleted out of band needs none of this: the next pass's own
  `GetServer` finds it not-found and routes to the create path, which is also why
  `UpdateServerState` still surfaces `ErrResourceNotFound` rather than swallowing
  it — the create-retry provisioner's confirmed-gone gate depends on it.

  The provisioning condition reports *spec-realization*, not attribution. A
  rebuild-class operation this provider did not submit — `nova evacuate` is
  implemented as a rebuild, presenting `task_state=rebuilding` with the ref
  already on the spec image — therefore reads exactly as ours on the next poll:
  R3 reports `provisioning` while it runs, R3′ reports a failed one and rechecks
  it, and a recovery clears it at the poll after. A foreign rebuild onto a
  *different* image — succeeded or failed — is auto-reverted: the next poll reads
  the flipped ref and R4″ resubmits toward the spec image (up to one period
  later). The error report is therefore scoped
  precisely to failures on the *converged* ref, where the spec image itself is
  implicated; divergent-ref failures are reconverged instead. Operational
  consequence: operators must change the spec, never act through Nova — the region is
  the control plane, so a Nova-side image change is undone within a period, as a
  deleted VM is recreated. This is deliberate. During
  any rebuild-shaped operation the server is not serving its spec — a rebuild is
  rewriting the root disk, while an evacuation on shared storage rebuilds the
  instance on another host without touching it — so `provisioning` is honest;
  after a failed one the spec image is not running. Both reports are true
  regardless of who initiated the operation, and no destructive row can fire on a
  foreign operation (R4″ requires a diverged ref, which a foreign rebuild does not
  present). Nothing is latched: when a foreign recovery returns the server to
  `ACTIVE` on the converged ref, the next pass walks to R3″ and the server reads
  `provisioned` again. What this costs is attribution in the *messages* — a failed
  evacuation reports the same cause-neutral message as a failed rebuild — which is
  the price of having no persisted intent to consult, and why the message names
  neither.

  R4 defers to the create-retry path rather than duplicating it, and Nova enforces the
  same precondition itself (`must_have_launched`).

  R4″ is the single destructive step. The submission (`submitServerRebuild`) writes a
  fixed accepted stamp on a 2xx (`Active` `Rebuilding`, `Healthy` `Unknown`, matching
  the projection's `REBUILD` mapping) and never
  derives it from the rebuild response body, whose 202 can still describe the
  pre-destruction server as `ACTIVE` and would stamp a just-accepted destructive
  rebuild as running. Acceptance *yields* rather than completing: Nova now has a
  destructive operation in flight, and completing would map to
  `Available=Provisioned` and report a server whose root disk is being rewritten as
  settled. Every submit is logged at Info ("submitting server rebuild"), because it
  wipes the disk and may start with no spec edit. A `409` is pre-acceptance — the
  server is untouched — so it is a `Recheck(Provisioning)`, looked at again at the
  next poll. A deleted image costs one rejected rebuild request a poll until it
  comes back or the spec names another: the controllers run without the image
  cache, so there is nothing cheaper to ask.

  Nova's accept gate refuses an unresolvable or non-`active` image, an image
  whose `min_ram`/`min_disk` exceeds the flavor, non-bootable image properties, a
  locked or wrongly-stated instance, and quota — all *before* writing any state.
  The body stays in the log and never reaches the API surface. A synchronous HTTP
  400 is `Recheck(Errored, "the requested image is not available at the provider;
  it will be applied when it is, or select a different image")` only when the
  body carries Nova's image-not-found signature ("Cannot find image for
  rebuild"). It is not user-action-required: if the image comes back, the next poll
  rebuilds with no spec edit. Nova 400s are not homogeneous: a *deactivated*
  image (`ImageNotActive`) is also a 400, and is not matched. Every other 400 —
  and a reworded or stripped body — surfaces as the pass's error, failing safe
  toward the error path rather than toward a wrong wait. An HTTP 409 is a
  recheck, and every other rejection class surfaces as the pass's error.

  The reconciler projects `Active`/`Healthy` on every row from the read it
  decided on (see Server Observation) and re-asserts the accepted stamp while a
  rebuild it submitted is still in flight (R3).
- Nova rebuild retains the server UUID, network ports and IP relationships,
  attached data volumes, flavor, metadata, and placement, but recreates the
  root disk. It stays on the same compute host; evacuation is a separate
  operator workflow.
- Server delete is held while Nova reports the server as `BUILD` with
  `task_state` `spawning`, or `REBUILD` with `rebuild_spawning`. Ironic has no
  teardown transition from `deploying`; Nova's Ironic driver asks for one
  anyway, is refused, abandons the build and clears the instance's host, so the
  node finishes deploying with no instance and a later delete never reaches
  Ironic ([Nova bug 1477490](https://bugs.launchpad.net/nova/+bug/1477490)).
  Nova claims the Ironic node only once the task state is `spawning`; a build
  still queued in nova-compute (`scheduling`, `networking`,
  `block_device_mapping`) aborts cleanly on delete without reaching Ironic, so
  its delete is requested at once. Other states, including `deleting`, retry
  DELETE so failed synchronous cleanup on a down compute host can recover;
  Nova suppresses duplicate asynchronous deletions.
  The hold is read from one `GetServer`, so a delete can land in
  the instant after Nova saves `spawning`; that window is one API round trip.
  A held pass sets the Server's `DeletionHeld` condition True with the Nova
  state in its message, so its transition time is when the hold began, and logs
  at Info on every pass so a live controller is distinguishable from a wedged
  one. False with reason `Released` means the build hold ended, irrespective
  of later cleanup success; never-held servers have no `DeletionHeld` condition.
- Accepted Nova DELETE, including a concurrent-delete 404, yields until a fresh
  lookup confirms absence. Only then are the floating IP and port deleted, in
  that order. After the port is absent, another Nova lookup must confirm absence
  before deletion succeeds. A create discovered during network cleanup yields;
  later reconciles delete matching instances through the same path, including
  separate instances from retried creates. Failed lookups retain ownership.
  Neutron DELETE 404 is idempotent success; other provider errors retain cleanup
  ownership. This assumes the shared project list (see
  [Kept Lists](#kept-lists)) is complete, which it is for
  instances visible before its walk began; one that first becomes visible mid-walk
  can be missed, so the final lookup's window is one walk rather than one request.
  An absence is only ever answered from a list opened after the lookup began,
  so after the port delete, never from a kept list.
  It also assumes Nova keeps instances discoverable until network
  teardown finishes. It requires `[api] list_records_by_skipping_down_cells = False`
  on every Nova API replica and `reclaim_instance_interval = 0` on API and
  compute services. Credential retention depends on the existing Server
  ownership and reference chain. The final lookup catches creates that became
  visible during network cleanup; it does not recover instances after the
  Region Server is gone or establish a general fence for later Region creates
  or rebuilds.
- `OpenstackIdentity` is the remaining persisted provider-state anchor. It
  currently stores the secret-bearing user/project/application-credential and
  bootstrap state needed to operate on behalf of a region `Identity`.
- The package relies heavily on deterministic naming and metadata conventions to
  re-find cloud-side resources. This is a convention-heavy contract, not magic:
  - identity-scoped resources use fixed generated names
  - network lookups rely on deterministic names
  - Cinder volumes use `volume-{Region Volume UUID}` inside the service
    principal's project; create, delete, observation, attach, and detach
    rediscover that exact name
  - server metadata is written deliberately as both a control-plane lookup aid
    and an in-guest linkage surface exposed through the metadata service
  - legacy camelCase server metadata keys remain frozen for backwards
    compatibility while newer namespaced keys provide the upgrade path
- Cinder Volume create/delete and observation are project-scoped lifecycle
  operations:
  - the Region Volume controller resolves the full cloud provider and drives
    its Volume capability after the service-principal Identity is ready
  - the native Region `Volume` CRD supplies the requested size and
    `VolumeClassID`, which becomes the Cinder volume type
  - create lists by the stable generated name and exact-matches the result
    before submitting a create, so controller retries adopt an existing volume
    rather than duplicating it
  - a successful rediscovery stamps `VolumeStatus.ProvisionedAt` once; if a
    later lookup confirms the backing volume is gone, the provider refuses to
    recreate it under the same Region Volume ID
  - an accepted Cinder create is partial progress rather than success: the
    provider yields after submission and on subsequent rediscovery until the
    volume reports `available`; all unrecognized non-error states also yield so
    an unfamiliar provider state cannot be mistaken for convergence
  - a Cinder status beginning with `error` returns a typed recheck,
    `Available=False`, `Reason=Errored`, with the user-safe message
    `the provider reports the volume in an error state`; provider IDs,
    scheduler failures, host details, and other raw Cinder diagnostics remain
    operator-only
  - `CreateVolume` and `AttachVolume` return a failure to reach the cloud
    untyped, so the volume controller's `WithTransient` keeps the condition, as
    for servers
  - an attach Nova refuses with a 409 and no attachment is a yield while a task
    holds the server and a recheck otherwise; a volume attached to another
    server is a recheck
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
  - observation creates an ephemeral Cinder client in the identity's project,
    exact-matches the stable name `volume-{Region Volume UUID}` after Cinder's
    fuzzy name filter, and fails closed on duplicate exact matches
  - observation uses the exact stable name and identity-scoped project lookup
    to establish the backing resource. Cinder metadata is not revalidated during
    observation, so mutable provider metadata drift does not block status updates
  - Cinder's whole-GiB capacity becomes a binary `resource.Quantity` by
    multiplying by one GiB. Negative capacity or a value that cannot be
    represented in bytes as an `int64` is `ErrConsistency`, not a neutral
    observation. Cinder lifecycle values map directly to the neutral Healthy
    condition: recognized operational states are healthy, deleting and error
    states are degraded, and empty or unrecognized values are unknown.
  - no exact match returns `ErrResourceNotFound`, while Cinder request,
    decoding, and client-construction failures remain errors. A recognized
    Cinder error lifecycle and an unknown lifecycle are successful observations,
    not Go errors.
  - `reconcileVolume` projects observed size and health onto the supplied Region
    Volume without exposing Cinder or Gophercloud types. It returns provider read
    errors so the caller can preserve the last observed status. It does not
    introduce a mirrored provider-state CRD. The Volume controller owns the
    durable `ProvisionedAt` marker, create/delete intent, and generic
    `Available` provisioning condition.
    VolumeClass inventory and Nova
    attach/detach remain separate capabilities
- Flavor export is a hybrid model: OpenStack discovers the flavor inventory, but
  region configuration can enrich or override user-facing flavor metadata such
  as architecture, baremetal status, and GPU semantics. Only public flavors
  with UUID IDs are exported, because Region's FlavorID request and CRD
  contracts are UUID-backed; configured selectors further restrict that set.
  Architecture resolves
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
  signals. Omitted selectors and omitted or empty selector IDs make the class
  ineligible for Server attachment; the provider resolves this operator-authored
  selector to the neutral Flavor ID allowlist and does not infer it from Cinder
  volume types.
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
  create/delete API. Cinder volume lifecycle observation is a separate
  capability from this attachment slice. The Cinder name filter is treated as
  fuzzy and post-filtered against the exact stable name
  `volume-{Volume.Name}`; duplicate
  exact matches fail closed with `ErrConsistency`. Only the optional guest
  device name crosses the provider-neutral boundary; Nova and Cinder IDs and
  Gophercloud objects remain internal.

  Attachment behavior is deliberately asymmetric:
  - attach requires both the server and volume; either missing resource maps to
    `ErrResourceNotFound`
  - a Cinder attachment already present on the requested server is successful
    only when Cinder reports the Volume `in-use`; it returns that row's observed
    device without a Nova read. `reserved`, `attaching`, and other transitional
    states yield for another observation; `error*` states return a terminal
    provider error
  - an attachment to any other server maps to `ErrConflict`; Region does not
    support multi-attach even when the Cinder volume is multiattach-capable
  - when Cinder reports no attachment, attach requests Nova only after Cinder
    observes the Volume `available`; transitional states yield. It yields after
    Nova acceptance. A create `409 Conflict` is followed by one Nova attachment
    read so a concurrent desired request yields for Cinder `in-use`; an
    unresolved conflict maps to `ErrConflict`
  - detach resolves Nova and checks it directly, so an empty Cinder attachment
    list cannot hide the claimed Nova attachment. Per-Volume finalizers block
    Server deletion until attachments are removed, so deleting and live Servers
    use the same active Nova detach path. A Cinder attachment row is a fallback
    only when its Server ID matches the resolved claimed Nova Server. Foreign or
    unowned rows are never detached; they conflict or yield until provider state
    converges
  - an accepted Nova delete yields immediately because detach is asynchronous.
    A later reconcile succeeds only when Nova no longer reports the claimed
    attachment and Cinder reports no attachment with status `available`; a
    missing backing Volume is idempotent success
  - a Nova delete `400 Bad Request` yields while the provider attachment state
    converges; the claim is retained and Region does not reset Cinder state. A
    `409 Conflict` maps to `ErrConflict`; other provider failures are preserved
  - detach also no-ops when the backing OpenStack identity was never realized,
    matching the provider's other teardown contracts

  Region owns these resources through its API. Detach does not attempt
  administrative repair of foreign attachments, multiattach, or resources
  changed directly through Kubernetes or OpenStack.

  Attachment intent and observed rows remain on `Server.Spec.Volumes` and
  `Server.Status.Volumes`; this provider slice does not mirror attachments into
  `Volume.Status`, claim volumes, or reconcile server controllers. Those
  belong to the volume provisioner
  ([../../../provisioners/managers/volume](../../../provisioners/managers/volume/README.md)),
  which populates `Volume.Status.AttachedAt` and owns claim release.
- Image handling is a first-class contract surface here:
  - only Glance images with `public` visibility are listed unless
    `openstack.image.includeCommunity` is set. That option is for development
    environments only and must never be enabled in production. With it set,
    `community` images are listed too, except any carrying an organization ID:
    uni-region only publishes organization images as public, so such an image
    is forged or was demoted by its owner
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
  dimensions). Provisioning status itself is separate (the `Available` condition),
  provisioner-owned and the projection never writes it; `setServerActive`
  does, however, latch `status.provisionedAt` from Nova
  `launched_at` the first time a server is seen booted (write-once, never
  cleared, independent of live power state), which the controller's bounded
  provider-create delete-and-retry guard relies on (so a server that has booted
  is never destroyed and recreated). The image-rebuild gate does not read this
  latch: it authorizes from Nova `launched_at` read fresh each pass. Alongside it, `setServerMACAddress` records
  `status.macAddress` from the Nova response once the server is `ACTIVE`
  (the port MAC rides inline in `addresses`, reused from the same `GetServer` — no
  extra call). ACTIVE is required because baremetal Ironic rebinds the port to the
  real NIC MAC asynchronously; the value is only ever written, never cleared.
  `GetServer` resolves by name, which forces a list, and **the list response can omit
  `fault` entirely** on Nova up to 2025.2, so a listed errored server carries no
  fault detail. `GetServer` itself does not compensate: the fault is operator log
  detail, not part of the returned server, so it is fetched by a dedicated by-ID
  read exactly once, on the observed transition into the errored state, and
  written to the log — status records no fault detail. Best-effort: a failed fetch logs the transition
  without the detail rather than failing anything, because the fault is an
  enrichment and not the reason for the read; healthy servers, and servers
  already known to be errored, never pay the extra call.
  The error edge is gated on `Status == "ERROR"` and not on `Fault` being
  populated, because Nova leaves a stale `fault` on a recovered server, so keying
  off the struct would report a cleared failure forever. The logged detail is the fault's code, message, and
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
  the pass logs the failure and falls back to the VM default `Building`
  `Active` state so API responses still see a coherent live signal rather than
  failing the pass.
- Some OpenStack list APIs are not safe to treat as exact lookup, notably
  server, network, Cinder volume, and Octavia load-balancer `name` filters:
  - `name` filters behave like prefix or regular-expression matches rather than
    strict equality
  - this package therefore re-checks exact names after listing to avoid aliasing
    and false matches
- Server port reconciliation compares the security groups and allowed address
  pairs returned by Neutron with the desired values as unordered sets before
  issuing an update. An omitted desired address-pair MAC is compared as the
  port's current MAC, matching Neutron's materialized response. A converged
  port is reused without a `PUT`, while private-IP status projection still runs.
- Provider networks that require VLAN segmentation use the local VLAN allocator
  because OpenStack does not allocate those IDs for us.

## Server Observation

`projectServerState` projects one fresh provider read onto a `Server`'s status: health,
MAC once Nova has bound one, and live lifecycle state via `setServerActive`. It
takes the read rather than fetching one, so neither caller can observe at a
different moment from the one it decided at.

`UpdateServerState` is `observeServer` alone: it reads Nova, projects the read,
and returns `ErrResourceNotFound` for an absent server. The projection also logs
the provider's fault detail once, when the server enters error.

`createServer` calls it first in the pass, through `observeServer`, and so
**before the image rows**; the ordering is not free choice:

- `setServerActive` is where `ScheduledAt`, `LaunchedAt` and the write-once
  `ProvisionedAt` latch. `reconcileServerImage` returns early on most of its rows,
  so observing afterwards would skip the latch on exactly the passes that wait or
  yield — including the bounded create-retry guard that reads `ProvisionedAt`, so
  a skipped latch re-arms delete-and-retry on a server that has booted.
- An accepted rebuild stamps `Active=Rebuilding` from within the image rows. The
  read predates the submission, so projecting it afterwards reverts that stamp.

Observing first does not weaken the rule that an observation never authorises an
action: the image rows decide from the `GetServer` result directly, never from the
status the projection wrote.

The create branch deliberately does not observe. There is no Ironic node bound
yet, and Nova has not bound a port MAC, so it stamps health and lifecycle from the
create response alone.

`status.macAddress` is written from the Nova response once the server reaches
`ACTIVE`, which is the barrier at which the port MAC is guaranteed bound for VMs
and baremetal alike. Earlier values — the one visible at port-create time — are
the ephemeral Neutron MAC, which Ironic rebinds to the real NIC MAC during a
baremetal deploy, so `reconcileServerPort` must not record it. It is only ever
written, never cleared: gating on `ACTIVE` and skipping an empty read means a
transient read miss cannot unset a value already held, while writing a valid MAC
unconditionally self-heals drift.

**The pass observes first.** `createServer` reads Nova and projects the read
(`observeServer`) before it touches Neutron, so a Neutron fault cannot stop the
lifecycle, health, MAC and latches being observed. It then converges the port
and floating IP, and only then runs the image rows on a found server or creates
a missing one. An existing server never reaches the create, its preflight, or
the augmented copy `reconcileServerForCreate` makes.

**An outage is not an answer.** The server controller polls and passes
`providers.Transient`, which is `Transient` here, to core's `WithTransient`.
`Transient` is true for a network error or timeout, a body cut off mid-read
(unexpected EOF), a 429, and any 5xx: a service that failed to answer says
nothing about the resource. The cost is that a Nova returning 500 for ever
leaves a create showing its last condition for ever; operators see it in
core's `reconcile_outcomes_total{outcome="transient"}` and the Info log.
gophercloud wraps a request that needed a token refresh in types with no
`Unwrap`; `Transient` looks inside them, because every credential refreshes when
its token runs out.

- A failure with no disposition that `Transient` accepts leaves the `Available`
  condition as it was, saves the rest of status, and is logged at Info. Without
  this a blip would turn every server `Errored` on every poll.
- Any other untyped failure (a 4xx such as a refused refresh after a credential
  rotation, a resource deleted underneath) is `Errored`, logged at Error on
  every pass, and retried at the poll slot.
- A typed outcome (the image rows' yields, rechecks and user-action waits) passes
  through as it is. Handled failures log at Info.
- Delete ignores the classifier.

Status the pass did write is still saved, so it must only clear a field once it
knows the value is gone: `reconcileFloatingIP` clears `PublicIP` on a confirmed
absence, never before the read. A permanent transport fault, such as a bad CA
bundle or a wrong endpoint, also reads as an outage on a server; its only trace
there is the Info log line.

**References follow a fact, not an error.** `CreateServer` returns whether the
port converged: whether it now carries exactly the security groups the
specification asks for. The provisioner releases references to dropped groups on
that alone, whatever else the pass returned, so a rebuild that yields or waits
for half an hour does not hold a dropped group, and a pass that failed before the
port was written never releases a group still on it.

Each pass on a booted server also reads Neutron: the network, each security
group, the port and its floating IP, so four or more requests per server per
period, about 130 a second at 2000 servers with one group each (modelled, not
measured). They are not shared the way the Nova list is.

## Credential Sessions

A credential's callers arrive in herds. Every `New*Client` used to be a full
`AuthenticatedClient` — a Keystone password grant plus a service catalog fetch —
and a reconcile builds two or three. Meanwhile a pinned server authenticates as
the Region admin user scoped to the service principal's project rather than as the
tenant service principal, so every server pinned to one identity shares one
credential. A restart resync of an identity holding 1157 servers asked for that
one credential a couple of thousand times inside a few minutes, and the health
monitor asked for it again for every server, every minute. The monitor is gone;
  the reconcile pass polls instead, and shares the same session.

A `Session` is the per-credential state that outlives every service client built
from it, keyed on the whole credential so a rotated secret can never be served a
client authenticated with the old one. The key is a keyed digest under a
process-lifetime random key rather than the credential verbatim or a bare hash of
it: a credential's input space is small enough that an unkeyed digest is
reversible by enumeration, and nothing should hold a secret in a map key that
lives as long as the process.

What the key really has to capture is everything determining where the derived
service clients point. That is the credential today only because every
`New*Client` passes a bare `gophercloud.EndpointOpts{}` and takes the first public
catalog match. Should anything start selecting an endpoint by region, two
OpenStack regions behind one Keystone reached with one admin credential would
share both a pinned catalog and a session, and the region would have to join the
key. It caches the authenticated
`ProviderClient` and collapses concurrent cold-start logins into one, which is
what a controller restart needs: no client is cached yet at the moment the herd
arrives.

Cache the `ProviderClient`, not the derived service clients. It holds the token,
carries `ReauthFunc` and serialises its own reauth internally, so it refreshes in
place. Caching derived clients would synchronise token expiry across a burst —
everything built in one burst expiring in one burst — and reform the herd an hour
later.

Four things follow that are worth knowing.

**The service catalog is pinned for the life of the process.** gophercloud's
`v3auth` closes `EndpointLocator` over the catalog from the login that built the
client, and `ReauthFunc` only copies the refreshed token back, not a new catalog.
An operator who moves a service's public endpoint in Keystone needs this process
restarted; previously each client construction re-fetched the catalog and
self-healed within a reconcile. The same applies to a service *added* to the
catalog after startup — enabling Octavia on a live region leaves load-balancer
clients failing endpoint lookup until a restart. The operator-facing procedure is
in [ADMIN.md](./ADMIN.md), because the symptom points away from the cause: calls
fail against an endpoint that has already been changed while Keystone itself is
healthy, and nothing logs the staleness.

**Endpoint lookups are remembered for the life of the session.** gophercloud
resolves a service's endpoint on every service client it builds, and for an
unversioned catalog URL (Neutron's, Glance's, and usually Octavia's and
Placement's) it GETs the version document to check the major version. A server
reconcile builds a network client every time, so that was one extra Neutron round
trip per reconcile, in series with it: one per server per minute once servers are
polled. The session wraps `EndpointLocator` so each lookup is answered once per
session, and the wrapper survives reauth; a failed lookup is not remembered. With
one public endpoint per service, as every catalog seen so far has, it pins nothing
the catalog did not already pin. With several, gophercloud skips one whose version
document lacks the wanted version and takes the next, so a moment's glitch on the
first leaves the second remembered until a restart. Pinned by
`TestSessionLooksUpEachEndpointOnce`.

**The shared client carries a request timeout, and must.** Sharing a client shares
gophercloud's reauth serialisation: `AuthenticatedHeaders` waits for an
in-progress refresh on *every* request, on a channel receive that consults no
context. One caller whose refresh hangs would otherwise park every other caller on
that credential — reconciles and the synchronous reboot, start, stop
and console handlers — below the level at which their own contexts could rescue
them. A zero-value `http.Client` has no timeout, so the bound is set explicitly.

It is set *before* authenticating, which is not interchangeable with setting it
afterwards: gophercloud copies the client by value to build the one it
reauthenticates with, so a timeout assigned after the login leaves both the login
and every subsequent reauth unbounded — and the reauth is the request every other
caller waits behind. Pinned by `TestSessionBoundsTheLoginItself`.

The bound now applies to every OpenStack call made with a shared client, all of
which were previously unbounded. Every call in this package is ordinary
request/response and pagination pays the bound per page, so the value is
defensible, but a call that legitimately took longer would now fail where it used
to succeed.

It bounds a *request*, not a call. One call can serialise a context-free wait on
another caller's in-progress reauth, its own request, a reauth on a 401, and the
retry, so the worst case a caller observes is several multiples of it. A cold
login against a versionless Keystone endpoint is likewise two bounded requests,
discovery and the grant. Do not size an upstream timeout off the single-request
figure.

The detaching covers the cold-start login only, because that is the one this
package's code owns. gophercloud owns the reauth and runs it under whichever
caller's request received the 401, sharing that one result with every caller
refreshing at the same moment — so at token expiry a caller that hangs up
mid-refresh can hand its cancellation to the others. They error and retry and it
self-heals, so this is a spurious failure rather than a stuck credential, but it
is a consequence of sharing that did not exist when every caller refreshed its
own client.

Callers waiting on someone else's login keep their own contexts and stop waiting
when those are done. The login itself runs detached from whichever caller opened
it, so a handler whose client hung up cannot fail the healthy reconciles that
joined its flight, and a caller that gives up leaves the login to finish and
populate the cache rather than wasting it.

**Entries are never evicted**, and grow by two per `OpenstackIdentity` the process
has ever seen — the service principal's own password and the Region admin scoped
to that identity's project — rather than tracking the live identity count. An
entry appears when a provider is constructed, whether or not it ever logs in, and
rotating the Region admin secret re-keys every identity-scoped session and adds
another entry per live identity. Each retains a decoded token response and the
service catalog it closes over, which is tens of kilobytes, not nothing. For a
long-lived controller against a churning estate that is worth bounding; the cost
of an eviction is one login.

### What this deliberately does not do

It caches no provider *read* itself. Server, network and security group reads
are kept, by a separate mechanism with its own freshness rule; see
[Kept Lists](#kept-lists).

## Kept Lists

`GetServer` reads the project's servers unfiltered and picks its row by exact
name, from a list kept per project for a minute (`keptListTTL`) and shared by
every caller in the project: at most one list runs at a time per project, and
everyone who arrives while it runs joins it (`keptLists`). Nova evaluates
a name filter as a regular expression over the whole project, so a filtered read
per server made polling N servers cost N project scans per period.

The list is kept, not just shared, because sharing alone merged almost nothing
once every server and volume was polled: passes are spread over the period and
rarely overlap. The scale harness (`test/scale`) measured 500 servers in 10
projects, steady state, against a fake cloud: each pass decoded its whole
project to use one row, about 50,000 rows and 28 CPU-seconds a minute, where
the monitor this replaced cost 1.5. The cost grew with servers times servers per
project. Freshness is not a goal: a period of staleness is fine.

This was measured and rejected once, against the health monitor, which walked
servers one at a time: at concurrency 1 a shared read merges nothing, so the
larger response was pure cost. The figures behind that came from a model whose
service times were plausible rather than measured, and a real deployment
contradicted them by two orders of magnitude: over a representative estate of
around 1500 servers a sequential cycle took tens of minutes, where the model put
it at 35 seconds. The model counted requests and rows; it did not price what a
loaded Nova charges for a regular expression scan over a project. Do not size
anything off the 35s figure.

**Freshness.** What a kept or shared read must never do is tell a caller a
server is absent, or failed, when the cloud has moved on since. Two decisions
act on what a read says:

- Not-found. The pass is check-then-act — `createServer` reads, and only a
  not-found lets `reconcileServer` create — so a reconcile told that the server
  it just created does not exist creates a second one. The network cleanup's
  final lookup and volume detach act on not-found too.
- Failed. The create-retry gate deletes a server it reads as failed, so a
  server fixed in the cloud since the last list must not read as failed.

So:

- Every Nova server mutation retires its project's lists once it has returned,
  whether or not it succeeded: no list opened before then answers a read that
  begins after. A read takes that line once, when it begins, so writes landing
  while its list runs cannot send it round again: at most two lists.
- Only a list opened after a read began may answer it not-found. A server
  missing from a kept list is looked for again in a fresh one, because a kept
  list can predate a server something else made: another process, a former
  leader, an operator.
- `UpdateServerState`, the create-retry gate's read, retires the project's
  lists before reading, so it always asks the cloud.

A not-found retires nothing: a server missing for good costs one list per read
of it, and the rest of its project keeps the kept list. Lists are per project,
not per credential, because a pinned server is created with the Region admin
credential and read with the service principal's, both scoped to one project.
The two credentials see the same rows; the admin's also carry `user_data`, which
no reader uses. A token with no project shares nothing: an empty key would merge
projects.

`DeleteServer` does not retire. A list from before a delete can only show the
server still present, and every reader treats that as "not gone yet": teardown
yields, and the create-retry gate holds off. Teardown re-sends DELETE every
pass, so retiring there would stop a project mid-deletion keeping a list at all.
Console calls do not retire either; they change nothing a list shows.

The kept list is per process. The server controller, the volume controller and
the API each keep their own, and a mutation in one does not retire another's.
A stale row there is answered with an error from the cloud (a 404 or 409 on the
old ID), not acted on destructively.

**Networks and security groups.** `GetNetwork` and `GetSecurityGroup` keep each
project's list under the same rules. Every server in a project reads the same
network and the same groups each pass, and a group row carries all its rules: a
CPU profile at 500 servers put these reads at 30% of the server controller,
decoding the same rows about a hundred times a minute per project. Where they
differ from servers:

- Keyed by project and user, not project alone: Neutron shows an admin fields a
  member does not, such as the segmentation ID.
- Filtered by `project_id`: an admin token lists every project's.
- Every Neutron write retires the project's network and security group lists,
  as a Nova server write retires its server lists; the two are separate.
- The network and security group controllers write these from other processes,
  which never retire the server controller's lists. A stale row gives an ID
  that is either right or gone, because names are never reused; a gone ID fails
  the port write with a 404 and the next pass retries. Not-found is always
  fresh, so their own create gates are covered.

Ports and floating IPs are not kept. Each server reads only its own, so a
project list decodes the same rows and saves only requests, against the risk of
a second port or public IP from a stale not-found. Cinder volumes are read the
same way and are not kept either.

**Paging.** The server list pages explicitly rather than using `AllPages`, which holds every
page as a generic map tree and re-marshals the whole thing through JSON to decode
it, so that overhead scales with the project rather than the page. Because the
list is walked by marker, a server created mid-walk can be missed and read as
absent. That cannot reach the create gate: a reader is only answered from a list
opened after its own last mutation, so its own server existed before the walk
began. A server someone else created mid-walk is missed for that read only.

**Costs.**

- Steady state. Each process lists each project about once a TTL, whatever the
  poll period: the reader that finds the kept list expired opens the next one.
  Up to three processes keep their own, so up to three lists per project a
  minute. Each server missing from Nova for good adds one list per read of it.
- Bursts. A create or attachment burst retires lists as fast as it mutates, but
  callers held back by one list share the next, so a project still runs one
  list at a time. After a restart the first reader in each project lists and the
  rest join it.
- Outages. A failed list is never kept, so while Nova fails each pass sends its
  own list; a slow Nova still runs one at a time per project.
- Decode. Measured on one laptop core against an in-process fake, 1150 rows of
  about 3KB: 0.40s of CPU and 147MB allocated per list; rows read with the admin
  credential carry `user_data` and cost more. Production rows and cores differ.
- Memory. The decoded list is the whole project by construction, kept for up to
  a TTL after it is read: about 14MiB live for 1500 realistic rows, or 43MiB of
  heap arena counting the per-page decode churn, per project, per process. A
  quiet project's list is dropped when any later list is stored. Copies share
  nested maps with the kept list for its whole life, so nothing may write to
  them.

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

  `OS-SRV-USG:launched_at` is likewise policy-gated and the image-row
  decisions depend on it — the before-first-boot deferral and the
  never-launched exclusion on the failed-rebuild report — so a cloud hiding it
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
  The controller treats only this signature ("Cannot find image for rebuild",
  matched in the 400 response body) as an image wait, a recheck: the spec still
  asks for the image, so it is applied if the image returns, and a spec edit can
  name another. Other rebuild 400s are the pass's error: notably `ImageNotActive`
  from a *deactivated* Glance image, which an operator can clear by reactivating
  it. An HTTP 409 is a recheck, and every other rejection class surfaces as an
  error. A valid image Nova can resolve but qemu cannot use
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
