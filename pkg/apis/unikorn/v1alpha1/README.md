# pkg/apis/unikorn/v1alpha1

## Intention

`pkg/apis/unikorn/v1alpha1` defines the region service's Kubernetes storage
model and controller contract. It is not just a set of CRD structs for
generation. It is the persisted object model that handlers, provisioners,
providers, monitors, and controller-runtime integrations share.

The package contains three broad kinds of object:

- user-meaningful region resources such as `Region`, `Identity`, `Network`,
  `SecurityGroup`, `LoadBalancer`, `SSHCertificateAuthority`, `Server`, and
  `Volume`, and `FileStorage`
- service-internal provider state, primarily `OpenstackIdentity`
- operational support objects such as `VLANAllocation`, `FileStorageClass`, and
  `FileStorageProvisioner`

That split matters. Not every type in this package is part of the public
service model in the same way. Some types exist mainly so controllers and
providers have durable state to coordinate around, while others are historical
carryovers from older designs.

## Links

- [../../../constants](../../../constants/README.md)

`pkg/constants` defines much of the label and annotation vocabulary that these
stored objects rely on for linkage, migration, and operational coordination.

## Invariants And Guard Rails

- This package defines Kubernetes storage objects, not the full public service
  contract. Higher-level API semantics are layered on top elsewhere.
- A new external API generation does not necessarily imply a new CRD or storage
  model. This repository performs some API evolution in place over broadly
  stable stored shapes.
- `Region` is the configuration and capability root for a provider-backed
  region. It carries provider type, provider-specific configuration, stored
  visibility inputs, flavor/image/network/volume-class selection rules, and
  helper methods that downstream code actively depends on.
- `Region.Spec.Openstack.DefaultArchitecture` controls the Region-scoped
  fallback used when OpenStack flavor or image inventory lacks explicit
  architecture metadata. CRD admission defaults omission to `x86_64` and
  accepts only `x86_64` or `aarch64`; per-flavor `cpu.architecture` and the
  Glance `architecture` property remain authoritative when present.
- OpenStack `VolumeClass` configuration is Region-scoped inventory metadata. It
  records which provider volume classes are eligible for export and how that
  inventory should be enriched; it does not create a project-owned
  `VolumeClass` CRD or any user-managed lifecycle resource. OpenStack maps this
  inventory to Cinder volume types internally, but the Region storage and
  public/domain vocabulary remains `VolumeClass`. Selection is fail-closed:
  only provider IDs explicitly listed in
  `openstack.blockStorage.volumeClasses.selector.ids` are eligible. Missing
  `volumeClasses` configuration, a missing selector, or nil/empty IDs exports
  no VolumeClasses. Metadata may independently publish `minimumSizeGiB` and
  `maximumSizeGiB` as positive whole GiB values. When both are present, the
  maximum must be greater than or equal to the minimum. Metadata may also carry
  a `supportedFlavors` selector whose `ids` are a unique typed Region Flavor
  allowlist. An omitted selector or omitted/empty IDs means the VolumeClass is
  compatible with every Flavor. Flavor IDs must use canonical lowercase,
  hyphenated UUID spelling. CRD admission enforces that static UUID shape,
  uniqueness, and the capacity invariants without provider lookups.
- Namespaced Kubernetes storage scope and platform tenancy scope are separate
  concerns. These objects are namespaced, but their logical visibility and
  authorization are often organization-, project-, identity-, or region-scoped
  at higher layers.
- `OpenstackIdentity` is the remaining necessary provider-state record. It
  persists the information needed to find and use the ephemeral OpenStack user,
  project, and credentials that back a region `Identity`, because those values
  cannot be recovered later by deterministic lookup in the same way as many
  other cloud-side objects.
- `VLANAllocation` is a coordination object, not a user-facing resource. It is
  designed around there being only one allocation record per region and relies
  on Kubernetes optimistic locking for safe concurrent updates.
- Several resources implement helper methods such as `Paused()`,
  `StatusConditionRead()`, and `StatusConditionWrite()` because this package
  also satisfies generic controller contracts. It should not be described as
  schema-only.
- `Server.Spec.ProviderCreateGates` is immutable create-time desired state used
  by the server controller to pause before provider create. Matching
  `Server.Status.ProviderCreateGates` entries record the gate `state`, actor,
  reason, message, and transition time for operator diagnostics. Each gate is a
  three-state machine — `Closed`, `Open`, `Locked` — where `Closed` is the
  default resting state reached without any report (a gate with no status entry
  is treated as `Closed`). A satisfier reports a gate via
  `POST /api/v2/servers/{serverID}/provider-create-gates` carrying a `state`
  (`Open` satisfies — the default, backward compatible with satisfy-only
  callers). The `reason` and `message` are satisfier-supplied and
  length-bounded (256/1024) so a chatty caller cannot bloat the stored object.
  Lifecycle semantics the provisioner enforces:
  - `Closed` (unreported, or reported to record transient progress) → **hold**:
    the provisioner yields and waits for a later reconcile to resolve the gate.
    Re-reporting `Closed` is a self-loop that refreshes the reason without
    resolving the gate;
  - `Locked` → **fail terminally**: the gate can never be satisfied without
    external change, so provider-create fails rather than yielding forever (see
    `LockedProviderCreateGate()` and the server provisioner). The failure
    carries the closed-vocabulary `Errored` provisioning reason with the
    satisfier's own, length-bounded detail on the message — the untrusted text
    never becomes a bespoke reason;
  - all gates `Open` → provider-create proceeds.

  `Open` is monotonic for the life of an attempt: once a gate is `Open`,
  provider-create may already have started on the strength of it, so the report
  endpoint **rejects** a satisfier moving it back to `Closed` or `Locked` (HTTP
  409) — otherwise any holder of the endpoint could wedge or fail a running
  server on a later reconcile. Only Region resets gates, and only as part of a
  provider-create retry: `ProviderCreateGatesReset` returns every gate to
  `Closed` once a failed provider server is confirmed gone, starting a fresh
  attempt. That retry path runs only *after* a provider server was created and
  failed, so it never applies to a `Locked` gate (which fails *before* any
  provider server exists); recovery from `Locked` is out-of-band — recreate the
  server. The generic `Server.Status.Conditions` list remains reserved for
  Region-owned lifecycle conditions.

  The read API mirrors the write model: `Status.RemainingProviderCreateGates`
  lists every not-yet-`Open` gate with its resolved `state` (and reason), so a
  consumer can tell `Closed` (still being worked) from `Locked` (will never
  open) without string-matching the Available condition.

  Upgrade note: this `state` field replaced an earlier `status`
  (`True`/`False`/`Unknown`) field in the same API version, with no stored-data
  conversion. A gate persisted by the old code has no `state` key; the CRD
  defaults the field to `Closed` (`+kubebuilder:default=Closed`), applied when
  the stored object is decoded, so old entries read back as `Closed`
  (unresolved) — the safe direction, never a spurious `Open` — and subsequent
  status writes validate against the enum. Any server holding at a gate across
  the upgrade therefore waits for its satisfier to re-report; level-triggered
  satisfiers recover on their next reconcile.
- `FileStorage` carries a more explicit observed-state model than the older
  resource types. Attachment-level provisioning state, observed size, usage
  reporting, and per-policy snapshot status are part of the stored
  reconciliation contract.
- `FileStorage.Spec.NFS` stores POSIX ACL and atime update interval desired state
  as required, defaulted values. The CRD defaults missing values to `false` and
  `0` before validation. An atime value of `0` means read-driven updates are
  disabled.
- `Volume` is the Region-owned block storage primitive. It is anchored to a
  `Network`, carries its own requested capacity and volume class identity, and
  is expected to carry quota/accounting responsibility in the Region layer.
  `Volume` does not define a per-network name uniqueness key; its resource ID
  follows the platform's normal UUID v4 identity pattern, while mutable display
  names live in standard metadata labels. `Volume.Spec.ClaimRef` is internal
  handler-owned state that records the exclusive Server reservation; a nil claim
  means the volume is available for claiming. `Server` is the current supported
  claim kind. `Server.Status.Volumes` is the sole persisted projection of
  attachment progress, optional provider device, and a safe message. Future
  attachment reconciliation will
  advance `ObservedGeneration` only after both backing volume and requested
  attachment state converge, and will report attachment errors through the generic
  `Available` condition. The Volume controller drives provider create/delete,
  but provider-side volume identity is rediscovered by stable provider lookup
  rather than mirrored into status.
- `Server.Spec.Volumes` is the attach-existing-only desired state for block
  storage. Each row names an existing Region `Volume` by ID; inline
  server-created volume templates are deliberately excluded from the first
  implementation. `Server.Status.Volumes` is keyed by the same Volume ID and
  reports per-volume attachment reconciliation state and the observed guest
  device name for later controller and monitor work. The provider layer now
  supplies a server-owned attach/detach boundary and the OpenStack provider
  realizes it with Nova, but this package still only owns the persisted shape;
  reference placement, claim/locking behavior, and controller reconciliation live
  in later layers/tickets. The v2 Server read projects stored attachment status.
- The `Network -> Volume` graph edge is declared as containment for future
  behavior: Network scope propagates to Volume; co-location is implicit; Volume
  holds a reverse deletion-blocking relationship to Network for its lifetime;
  Network deletion may cascade to Volumes once dedicated graph-edge
  reconciliation exists; Volume status does not propagate upward to Network.
- `FileStorage.Spec.SnapshotPolicies` is an optional inline desired-state list
  keyed by policy `name`. In persisted storage, omitted and empty lists both mean
  no user-managed snapshot policies are desired. Default snapshot protection is
  represented separately by a resolved desired-state setting; the region API
  enables it on create when callers omit the public control field. When default
  snapshot protection is enabled, the region API also materializes a hidden
  platform-managed `system-default` entry into this same list so the existing
  storage controller reconciles it like any other policy; that entry is never exposed in public REST reads. The CRD
  schema therefore bounds the stored list to five entries — four user-managed
  policies plus the optional hidden `system-default` baseline — caps policy names
  at 19 characters, and validates the schedule/retention shape so direct CRD
  writes cannot persist unsupported policy combinations.
- `Server.Spec.Image` is desired state; Nova's observed image and status remain
  authoritative for live state.
  A rebuild failure is not attributable: an unrelated host failure on the desired
  image is indistinguishable from a failed rebuild, whatever is recorded, so it
  surfaces on the monitor's lifecycle axis rather than as a reconciler diagnosis.
  Recovery is another image or a replacement server — never data restoration.
- `Server.Status.Observed` is the partition that lets the two status writers stop
  arbitrating. `Server` status has two writers: the reconciler drives the provider
  toward spec, the monitor polls the provider and records what it saw. Anything they
  share needs an ordering argument between them; anything derived exactly one way
  does not. Every field under `Observed` comes from a single projection of one fresh
  provider read. The monitor's poll is the normal caller but not the only one — the
  reconciler's create-retry existence check reaches the same projection through the
  same provider method — and that costs nothing because there is nothing to
  arbitrate: both callers write the same derivation of the same kind of read, neither
  advances a state, and a losing race loses on `resourceVersion` rather than
  reverting a field. The retired `Status.Rebuild` marker failed on exactly the
  opposite property: two writers holding different models of one field.
  The governing rule is that **an observation never authorizes an action against
  the provider**. Actuation is decided from a fresh provider read in the acting
  pass, because an observation is stale by up to one poll interval and acting on
  one would let a read taken before an operation landed authorize a second one —
  which for a destructive operation means doing it twice. An observation may be
  read as a precondition that *refuses* an action. This is the platform
  specification's rule for projected status, not a local convention.
  `Generation` is the freshness stamp: `metadata.generation` as read when the
  snapshot was taken, so a reader can tell whether an observation postdates a spec
  edit. It is stamped on every poll, which means the subtree exists from the first
  poll that read the provider at all — a present subtree with no `Image` means
  "polled, image unreadable", a different fact from an absent subtree meaning
  "never successfully polled". The monitor patches with an optimistic lock, so a
  write whose object moved underneath it is rejected outright and the recorded
  generation is the one in force at write time.
  `Image` tracks the live provider image rather than latching, but an unreadable
  ref preserves the previous value and never clears it: a transient read miss must
  not erase a known image, because a reader cannot tell an erased image from one
  never observed. `Errored` is a neutral presence marker — "the provider reports
  the server in an error state" — carrying no provider vocabulary; the provider's
  own fault detail is written to the observing component's log at the moment of
  observation, where operator detail belongs. It is live state and does clear on
  an authoritative non-error read, which is safe only because an unreachable
  provider aborts the poll without writing at all — connectivity loss can never
  be mistaken for a recovery.
  The `Healthy` and `Active` conditions are deliberately not in this region: the API
  projects health from the condition, and the conditions array is shared with the
  reconciler either way — it writes both on create and on an accepted rebuild.
  **What this region can never tell you.** Every field under it is provider state,
  so it bounds at provider-level truth and stops there. A rebuild onto a
  well-formed but unbootable image was measured settling as `ACTIVE`, on the target
  ref, with an empty `task_state` and no fault — byte-identical at the provider
  layer to a perfect rebuild, with a dead workload inside. No enrichment of this
  region can distinguish the two, because the difference is not visible to the
  provider API. So `Image` matching the desired image means "the provider reports
  the server running that image", never "the workload works", and `Errored` being false
  means "the provider reports no failure", never "the guest is healthy". Note also
  that a provider's failure detail may not survive the read the monitor makes: see the
  OpenStack provider's `GetServer` notes on list responses omitting the fault. Workload
  liveness is a separate axis needing a signal from inside the guest; treating
  convergence here as proof of a working workload is a misreading this region
  cannot protect against.

## Caveats

- This package mixes durable public resource storage, internal provider state,
  and transitional compatibility fields in one API group. Readers must not
  assume that every type here is equally service-facing or equally stable.
- Some fields are explicitly transitional rather than ideal long-term schema.
  `Network.Spec.Provider` and `NetworkStatus.Openstack` are called out in code
  as temporary compatibility baggage.
- `OpenstackNetwork`, `OpenstackSecurityGroup`, and `OpenstackServer` are
  historical state-record types from an older design that attempted to mirror
  OpenStack state locally. That approach created drift and race conditions, and
  these types are now better understood as deletion candidates rather than
  durable architectural primitives.
- Where possible, OpenStack itself is now the intended source of truth for
  cloud-side state, with local code preferring deterministic lookup over
  mirrored persistence.
- `ResourceLabels()` exists on several resources to satisfy shared controller
  interfaces, but currently returns `nil, nil`. That is an implementation
  contract for generic integration, not proof that these resources already have
  a meaningful label-tuple identity model defined here.
- `SSHCertificateAuthority` is structurally much lighter than the other major
  resource types. It has no status and behaves more like a stored project-scoped
  OpenSSH user CA record than a long-running provisioned object.

## TODO

- Delete `OpenstackNetwork`, `OpenstackSecurityGroup`, and `OpenstackServer`.
  They are leftover mirror-state CRDs from an older design that drifted from
  OpenStack and introduced race conditions.
- Remove the remaining transitional `Network` compatibility baggage, especially
  `Network.Spec.Provider` and `NetworkStatus.Openstack`, once the old paths no
  longer need to be preserved.

## Cross-Package Context

- handler packages define the user-visible API behaviour, authorization checks,
  and migration semantics layered on top of these stored shapes
- provider and provisioner packages turn these stored specs and status records
  into concrete cloud-side resources and, where still necessary, internal
  provider state
- monitor code consumes the same stored model and status helpers, especially for
  server lifecycle and health transitions
