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
- An existing server's image drift against spec (`Server.Spec.Image` differing
  from what Nova reports) is converged in place by a Nova rebuild, one
  protocol action per reconcile pass. See "Server Image Rebuild" below.
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
  is never destroyed and recreated). The image-rebuild arming gate (see "Server
  Image Rebuild" below) does not read this monitor-owned latch: it authorizes
  from Nova `launched_at` read fresh on the same pass. Alongside it, `setServerMACAddress` records the other monitor-owned
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
- During the transition to the monitor-owned `status.observed` subtree, each
  state mutator (`setServerMACAddress`, `setServerActive`) records its fact in
  both places: the legacy top-level field and its `status.observed` mirror.
  `updateServerStateWithClients` stamps `status.observed.serverGeneration`
  from the server generation read at the top of the poll before the mutators
  run, so a reader can tell whether the subtree postdates a spec edit. Health
  stays on the `Healthy` condition and is not part of this migration.
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

## Server Image Rebuild

A desired image change on an existing server is realized as a Nova in-place
rebuild: the root disk is recreated from the new image while the server keeps
its UUID, ports, fixed and floating IP relationships, attached data volumes,
flavor, metadata, and placement. It stays on the same compute host;
evacuation is a separate operator workflow. Flavor changes remain
unsupported. An accepted rebuild destroys the previous root disk contents
even if the rebuild subsequently fails, so failure recovery is choosing
another image or replacing the server — never data restoration.

### The write-ahead marker and why commit precedes call

The one fact fresh observation can never reconstruct is whether Region
recently asked Nova for a destructive rebuild. That fact is recorded
write-ahead in `Server.Status.Rebuild`, a four-field marker
(`ServerRebuildStatus`): `TargetImageID` (the image this attempt converges
toward), `PreArmImageRef` (the provider's image ref at the moment the attempt
was armed), `Accepted` (the reconciler has committed to calling the
provider), and `Parked` (the attempt is abandoned pending new user intent).
The reconciler is the marker's sole writer; the health monitor never reads or
writes any field of it — nothing about this protocol is observation-driven,
because every decision below is made from a fresh `GetServer` read taken in
the same reconcile pass, not from anything the monitor has cached.

**The ordering between recording acceptance and calling the provider is the
single most important rule in this protocol.** The pass that decides to
commit to a rebuild sets `Accepted` and returns *without* calling Nova. A
later pass, having read that commitment back durable from etcd, makes the
actual call. This bounds the failure modes that matter: if the process
crashes, or an optimistic-lock write is lost, between deciding to commit and
that decision reaching etcd, no call was ever made — the next pass simply
re-decides from the same fresh evidence and tries the commit again. A crash
or a lost lock can therefore leave a rebuild request unmade, but it can never
leave a destructive call unrecorded.

The reverse ordering — call Nova first, record the acceptance afterward — is
unsafe, and was the previous implementation's approach. Under that ordering,
a pass that calls Nova and then dies (or loses the status write under
optimistic lock) before the acceptance record lands leaves no trace of the
call. The rebuild that was actually issued reads back as never having
happened, so a later pass, seeing no record and a server that is (from the
provider's perspective) still converging, decides to rebuild again and issues
a second Nova rebuild — destroying the root disk twice for what the caller
experiences as one request.

### The decision procedure

Every reconcile pass over an existing server takes a fresh Nova read and,
where the server is baremetal, a fresh Ironic read (the second evidence
channel, below), then picks exactly **one** action. The rows are evaluated in
order — order is load-bearing, not incidental — and the first matching row
wins:

| Marker | Provider image vs. target | Provider state | Second channel | Action |
|---|---|---|---|---|
| parked, target changed | — | — | — | unpark |
| parked, target unchanged | — | — | — | stay parked (noop) |
| (any/none) | ref unreadable | not errored | — | noop — cannot decide |
| none | ≠ desired | idle, ever launched | — | arm |
| none | otherwise | — | — | noop |
| unaccepted | == target | busy | — | commit |
| unaccepted | == target | idle | agrees | clear |
| unaccepted | == target | idle | disagrees | commit |
| unaccepted | (any) | errored | — | commit |
| unaccepted | ≠ target | idle | — | commit |
| unaccepted | ≠ target | busy | — | noop |
| accepted | == target | idle | agrees | clear |
| accepted | == target | idle | disagrees | park |
| accepted | (any) | errored | — | park |
| accepted | == pre-arm ref, ≠ target | idle, not yet launched | — | noop |
| accepted | == pre-arm ref, ≠ target | idle, launched | — | call |
| accepted | ≠ target, ≠ pre-arm ref | idle | — | park (superseded) |
| accepted | (any) | busy | — | noop |

Reading the table:

- **arm** stamps a fresh marker (`TargetImageID` = desired image,
  `PreArmImageRef` = the provider's current image) and nothing else. Arming
  is gated on the server having launched at least once — decided from a fresh
  `OS-SRV-USG:launched_at` read, not from the monitor's `status.observed`
  latch — because before first boot the image is a create parameter, not a
  rebuild target.
- **commit** sets `Accepted = true` and returns without calling the provider;
  this is the durable-write half of the ordering rule above.
- **call** issues the Nova rebuild. A `409 Conflict` (another operation holds
  the server) is pre-acceptance and yields quietly rather than reporting a
  failure.
- **clear** deletes the marker: the target image is what Nova reports, the
  server is quiescent, and the second channel (if any) agrees.
- **park** sets `Parked = true`, retaining the marker, and reports
  `UserActionRequired`/`Errored` on the `Available` condition. The only way
  out is a new image or server replacement.
- **unpark** deletes a parked marker whose target no longer matches the
  desired image — a new image selection is the only recovery path from a
  park, and this is where it takes effect.
- **noop** takes no action this pass; the accepted-and-outstanding cases
  still keep the object requeued (see "Requeue" below).

`idle` and `busy` classify a fresh Nova read (`rebuildProviderOp`).
`task_state` is the busy signal for the whole rebuild window — non-empty from
accept until settlement, empty at rest. `idle` is an **allow-list of
rebuild-admissible states**, not a fallback for "anything not obviously
busy": Nova only accepts a rebuild from `ACTIVE` or `SHUTOFF`. States that are
stable and taskless but still reject a rebuild with a 409 —
`VERIFY_RESIZE`, `PAUSED`, `SUSPENDED`, and `SHELVED_OFFLOADED` — classify as
busy, "not actionable right now", rather than idle. Reading them as idle was
tried and produces an endless 409 retry loop: the pass would submit, Nova
would refuse, and the marker would sit `Accepted` forever with the call being
retried every pass for a request that cannot succeed until an external actor
(e.g. confirming a resize, waking the server) changes the vm_state. `ERROR`
is tested first and always classifies as `errored`, ahead of `task_state`,
because Nova's error state is sticky and operator-actionable and must not be
held off the park by a stuck task signal.

**Pre-arm ref.** `PreArmImageRef` exists to answer one question an accepted
marker cannot otherwise answer from a single fresh read: has the provider
been asked yet? While accepted and idle, a fresh image ref equal to
`PreArmImageRef` means Nova still shows the image it showed at arm time — no
call has landed — so the pass calls it. A fresh image ref that differs from
*both* the target *and* the pre-arm ref means the image moved to something
this attempt never asked for while the attempt was still accepted-but-not-yet
-called — a rebuild driven by something other than this protocol — and that
is treated as superseded and parked, because this attempt can no longer
converge toward its recorded target.

### The park latch is a marker field, not a read of `Available`

Parking is decided from `Marker.Parked`, a field on the marker itself, never
by reading the core-owned `Available` condition to ask "am I already
parked?". This matters because core writes the generic `Errored` reason for
*any* provisioning failure, transient ones included — not only for a parked
rebuild. If parking were inferred from seeing `Available=Errored`, a
transient provisioning blip unrelated to this rebuild would be
indistinguishable from a real park. And the requeue (below) stops dead at a
parked server — its only exit is a spec edit. So misreading a blip as a park
would freeze a genuinely recoverable rebuild attempt until an operator
happened to edit the spec, for a failure that would otherwise have cleared on
its own. Only `Marker.Parked`, set exactly once by this decision procedure
under the same conditions every time, can answer that question safely.

### The second evidence channel

Nova's word alone is not always sufficient evidence that a rebuild converged.
A provider can report the target image ref with an idle, quiescent server —
the state this protocol otherwise treats as "converged" — while the physical
machine has not actually received the new image, because on baremetal the
image write happens through Ironic's deploy pipeline, asynchronously from
what Nova's own record shows. Trusting Nova alone there would let the marker
clear on a rebuild that never actually landed on disk.

The second channel is Ironic's `instance_info.image_source` on the node bound
to the server, read fresh alongside Nova on baremetal flavors only. It has
three states, and the caller must resolve which one applies before it may
call the decision procedure at all:

- **no channel**: no baremetal node is bound to the server (not a baremetal
  flavor, or Ironic has no node yet). The decision procedure falls back to
  Nova's word alone — there is nothing else to ask.
- **a channel that resolves**: the node exists and `image_source` resolves to
  an image ID (accepting either a bare UUID or an href whose final path
  segment is one). That resolved image is compared against the target: agreeing
  lets a converged-looking Nova read actually clear the marker; disagreeing
  means Nova's "converged" is not to be trusted yet, and an accepted attempt
  parks instead of clearing.
- **UNREACHABLE**: a node is bound, but its `instance_info` carries no
  resolvable image reference — missing, non-string, empty, or a value that
  does not parse. This is never treated as "no channel". The pass must yield
  and retry rather than deciding on Nova's word alone at the moment the
  second opinion cannot be had; deciding here would risk clearing a marker
  on a rebuild that Ironic cannot actually confirm.

### Requeue

An outstanding, unparked marker — armed but not yet accepted, or accepted but
not yet cleared — keeps the server enqueued for another reconcile pass by
returning a fixed-interval yield rather than completing cleanly. A parked
marker does the opposite: it returns the terminal `UserActionRequired`
disposition and is **not** requeued.

This has to be a returned-error mechanism rather than a Kubernetes watch
event, because the commit-then-call ordering above produces a state — the
marker committed, durable, with no provider call made yet — that a
generation-filtered watch will never observe. The controller's watch fires on
spec generation changes, and status writes do not bump generation, so the
very status write that records the commitment enqueues nothing on its own.
Nothing else about that state changes on its own either: there is no further
Nova observation to wait for, because the provider genuinely has not been
called yet. A wake predicate has nothing to trigger on. The reconcile's own
yield is therefore the only thing keeping the object alive between the commit
and the call.

Parked markers are deliberately excluded from this requeue. A parked
attempt's only exit is a spec edit selecting a different image, and a spec
edit is exactly what does change `metadata.generation` and re-triggers the
watch. Requeueing a parked server on a fixed interval as well would just spin
the workqueue forever on a resource that cannot self-heal.

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
- The rebuild protocol rests on two environmental facts about the target
  cloud that are **unverified assumptions**, not properties checked against a
  live cloud in this work:
  - **Accept-time atomicity.** The busy/idle classification a fresh Nova read
    gets assumes Nova sets `task_state` inside the same API call that accepts
    a rebuild, so an accepted rebuild is observable as busy from the instant
    it is accepted. If a cloud could accept a rebuild while a poll still read
    the server as idle at the old image, no classification here would be
    safe: retrying would double-submit against a rebuild already in flight,
    and parking on an unrelated signal would misfire on one that is actually
    progressing. The integration suite carries a Nova rebuild-atomicity probe
    for exactly this property, but it has not been run against a live cloud
    in this work.
  - **Ironic's `image_source` shape.** The second evidence channel accepts a
    bare image UUID or an href whose final path segment is one, and treats
    anything else as unreadable (`UNREACHABLE`). What Ironic actually writes
    into a real deployed node's `instance_info.image_source` has not been
    verified against a live cloud in this work. A shape outside those two
    forms would read as `UNREACHABLE` on every poll, which stalls rebuild
    settlement on the affected baremetal server rather than silently
    misreporting convergence — a safe failure mode, but an unverified one.

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
