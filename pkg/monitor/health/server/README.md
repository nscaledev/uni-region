# Server Health

`pkg/monitor/health/server` is the current concrete monitor checker.

It polls region servers, asks the backing provider for their effective state,
patches Kubernetes status, logs lifecycle transitions, and exports OTel metrics
for:

- current server counts by state/region/flavor
- provision duration (`Uni CreationTimestamp → Nova launched_at`)
- scheduling duration (`Uni CreationTimestamp → Nova created_at`)

This makes it a bridge between provider-observed reality and the platform's
status/telemetry model.

## Distinctive Behaviour

- resolves provider and flavor context per region while bucketing, and caches
  it for a poll cycle
- updates server status through provider `ObserveServers(...)`: one unfiltered
  read of an identity's whole project, projected onto every server in it
- refines the server's live lifecycle state from observed Nova + Ironic state. Lifecycle state rides the generic core `Active` condition (status `True` only when the server is running; the reason carries the precise state via the domain-owned `ActiveConditionReason` vocabulary — `Pending`/`Queued`/`Building`/`Running`/`Stopping`/`Stopped`/`Error`), not a bespoke status field. For OpenStack baremetal servers in Nova `BUILD`, an Ironic node lookup distinguishes `Queued` (provider has accepted the create but hardware is not yet engaged — pre-deploy Ironic states) from `Building` (Ironic actively deploying, including transient deploy failures). VMs in Nova `BUILD` go straight to `Building`. Provisioning status itself is a separate axis (the `Available` condition), condition-derived and provisioner-owned (one-shot): the monitor never writes it. The `Active` condition is the live readiness signal once provisioning status reaches `provisioned`.
- latches `status.provisionedAt` from Nova `launched_at`, alongside `launchedAt`
  and ahead of the `BUILD` early-return, so it fires for VMs and baremetal alike
  regardless of live power state. This is monitor-owned observed state (like
  `launchedAt`), not the provisioner-owned provisioning-status condition; the
  rebuild decision itself stays with the controller. Unlike `launchedAt` it is
  written once and never cleared, and the controller's bounded provider-create
  delete-and-retry guard keys off it so a server that has ever booted is never
  rebuilt. Servers predating the field backfill it on the next poll once booted.
- is the sole owner of `status.macAddress`, recorded from the Nova server
  response (the port MAC carried inline in `addresses`, reused from the poll's
  existing project read — no extra provider call) once the server reaches Nova
  `ACTIVE`. ACTIVE is the barrier at which the port MAC is guaranteed bound for
  VMs and baremetal alike: for baremetal Ironic rebinds the port to the real NIC
  MAC asynchronously during deploy, so the value observed earlier (e.g. by the
  reconciler at port-create time) is the ephemeral Neutron MAC and must not be
  trusted. A MAC is only ever written, never cleared: gating on ACTIVE and
  skipping an empty read means a transient port-read miss cannot unset a held
  value, while unconditionally writing a valid MAC self-heals drift (the status
  PATCH makes a same-value write a no-op).
- logs phase and health-condition transitions
- populates `status.observed` from the poll's existing project read. The
  region has one writer *function* rather than one caller: the reconciler's
  create-retry existence check takes its own per-server read but lands in the same
  `projectServerState`, and so the same projection. One derivation with no
  arbitration is what removes the ordering argument between the two status
  writers — not the monitor holding the region alone. That shared derivation also
  means a provider not-found is *surfaced* by both `Observe` and
  `UpdateServerState` — the create-retry path reads it as "confirmed gone" — but
  the absent observation (errored cleared, generation stamped, image sticky) is
  recorded on the server first, and this monitor persists it despite the error:
  the observed wake is what lets the reconciler notice the out-of-band deletion
  and recreate the server. The absent server is excluded from the state gauge for
  that cycle, as the skip was before — there is no provider state to count.
  `generation` is stamped unconditionally, so the subtree exists from the
  first poll that read the provider at all — a present subtree with no `image`
  means "polled, image unreadable", which is not the same fact as an absent
  subtree meaning "never successfully polled".
  `image` tracks the live provider image, but an unreadable ref (absent, empty or
  unparseable) preserves the previous value and never clears it, for the same
  reason `macAddress` is never cleared: a transient read miss must not erase a
  known fact. `errored` is the opposite — live state that clears on an authoritative
  non-error read. That is safe only because a provider that cannot be reached
  aborts the poll before any write, so connectivity loss can never be mistaken for
  a recovery. It is gated on the provider reporting `ERROR` rather than on Nova's
  `fault` being populated, because Nova leaves a stale `fault` on a server that has
  since recovered. The fault detail itself (code, message, created) never reaches
  projected status: it is fetched and logged once, best-effort, on the transition
  into the errored state, and `fault.details` is excluded even from the log as an
  admin-only stack trace.
  A write to this region wakes the reconciler: the server manager's
  `serverObservedUpdate` predicate (`pkg/managers/server`) fires on any change to
  the subtree, so the reconciler sleeps until a provider fact moves rather than
  requeueing to re-read one. Nothing reads the region's *contents* yet.
  Because `generation` is stamped unconditionally, the first poll after a spec edit
  writes a real patch even when no provider fact moved, so it wakes the reconciler
  once redundantly — the edit already woke it via the generation predicate. Harmless,
  and cheaper than the alternative of making the stamp conditional on other fields
  having changed, which would make the stamp mean something subtler than "the
  generation this was observed at".
  The rule for when something does read the contents: **an observation never
  authorizes an action against the provider** — actuation is decided from a fresh
  provider read, and an observation may only be read as a precondition that refuses
  one.
- rebuilds gauge counts from the effective server set each cycle

## The Cycle

A cycle lists Server resources from the informer cache, buckets them by
`(region, identity)`, and observes each bucket with one provider read. Buckets
are walked one at a time.

The bucket is the identity because the identity *is* the Keystone project: one
unfiltered list covers every server in it, whether a given server authenticates
as the tenant service principal or as the region admin scoped into that project.

This replaced a walk that paid a name-filtered Nova list *per server*. Nova
evaluates that filter as a regular expression against every row of the project,
so the cost grew with servers times project size. Over a representative estate of
around 1500 servers a cycle took tens of minutes against a one-minute poll
period — and because the ticker drops ticks when a cycle overruns, the cycle
length *is* how long a new server waits to be seen. See the
[provider README](../../../providers/internal/openstack/README.md) for the read
shape and why the create path keeps its own per-server read.

What changed is the shape, not just the constant. The old cost was the sum of
each project's size *squared*, because every server in a project scanned that
whole project; it is now `(identities x fixed) + servers-in-region`. So a region
that grows by adding tenants always cost linear and still does, but one that
grows by growing its existing tenants used to cost quadratic and no longer does.

Peak memory follows the largest single project rather than the estate, since one
project is decoded at a time: around 15MiB of heap arena for a project of 80
servers and 43MiB for one of 1500. A region with one very large tenant is the
shape to size the memory limit against, and it is not the same as the estate
total.

Two terms make up a cycle, and they scale differently:

- **The reads**, bound by the region's footprint. Around four seconds in steady
  state on that estate.
- **The logins**, bound by tenant count rather than floor space. Each credential
  logs in once per process, so the first cycle after a restart pays them all —
  around thirty of the first cycle's thirty-four seconds. A region with many
  small tenants stretches that, and only that; it is a one-off and the next tick
  is back to the reads.

The Keystone login is otherwise shared per credential, so it is not part of the
saving here. A release without that sharing pays a login per server on top, which
is worth knowing when comparing against an older deployment.

### What A Bucket Does Not Speed Up

The batch is taken once per bucket and projected serially, so the last server in
a large bucket is projected from a snapshot as old as the bucket took to walk. Two
per-server provider calls remain inside that loop: a fault fetch on a transition
into error, and an Ironic node lookup for a baremetal server in Nova `BUILD`.

A bucket mid baremetal deploy is therefore the shape this read does not help, and
the effect is not confined to those servers. Nothing partitions an identity by
flavour, so anything else in it — a VM included — is observed only once the walk
reaches it, behind one Ironic round trip per baremetal server still in `BUILD`.
It is a smaller wait than the per-server walk this replaced, where the same server
queued behind a Keystone login and a whole-project regexp scan as well, but it is
the remaining serial term. Batching it the way the Nova read was batched is not
open to us: Ironic nodes are not identity-scoped, so the per-bucket equivalent
lists every node in the region, and the phase-derivation credential is scoped to
the project.

A wedged provider holds the cycle for as long as its reads take to time out, and
the volume checker runs after this one on the same ticker, so its status goes
stale for that long too. That is the behaviour a per-server walk already had at a
finer grain, across far more read opportunities; bounding it properly means giving
the cycle a budget in `monitor.Run`, which is a change to this component's
contract and is not worth making to something already scheduled for deletion.

### Best Effort

A cycle is best effort: one failure must never stop anything else updating, and
there is no retry anywhere in it. The poll period is the retry — a minute later
the cycle re-derives everything from a fresh read, so a transient failure costs
one cycle of staleness on the servers it touched.

| failure | blast radius |
| -- | -- |
| region resolve | every bucket in that region skips |
| Identity read | that bucket skips |
| project read | that identity's servers skip |
| `Observe` on one server | that server skips |
| status patch | that server skips, conflicts included |
| the cycle's own context being cancelled | the cycle stops |

Note the last row carefully: it is the *cycle's context* being done, not an error
that happens to be a context error. A provider call that hits the shared client's
per-request timeout returns something for which `errors.Is(err, context.DeadlineExceeded)`
is true, and that is an ordinary bucket failure — logged, skipped, retried next
poll. Conflating the two is how a wedged Nova would be mistaken for an orderly
shutdown and go unreported, which is why nothing here classifies a failure by
inspecting its error: every failure is logged, shutdown included.

A patch conflict is dropped rather than retried: it means the reconciler won the
race, so re-deriving next cycle is the correct answer, not rewriting from a stale
base. Skipped servers keep their existing status and drop out of the state gauge
for that cycle, which is the same behaviour a region-wide provider outage always
had, now reachable at identity granularity too.

What makes a cycle best effort is `checkGroup` absorbing its own failures. A
shutdown does log an error per checker, which is accepted: suppressing it was
tried and cost more than it saved, because the only reliable way to tell a
shutdown from a wedged provider is the cycle's own context, and keying off the
error hid the wedged provider instead.

### Writes Only On Change

The projection is compared against what was read and the patch is skipped when
they match. The saving is cycle latency, not load on the API: a no-op patch
short-circuits the etcd write and emits no watch event, but it is still a round
trip, and a few thousand of them at 5-10ms each is the dominant term in a cycle
that is otherwise a handful of seconds.

The absent-server path is compared the same way, and this cannot lose the
observed wake: the reconciler's wake predicate is itself a comparison of
`status.observed` against its previous value, so an observation identical to the
stored one never woke anything to begin with. The first cycle after an instance
disappears does change the observation, is written, and does wake the reconciler.

## Invariants And Guard Rails

- The cycle's own context being cancelled aborts the poll cycle; every
  per-server and provider failure, context-flavoured errors included, is logged
  and skipped.
- Servers skipped because region/provider resolution fails are absent from the
  gauge for that cycle rather than misreported as a fake state.
- Provider-specific progress refinement must be best effort. For example,
  OpenStack Ironic lookup failures degrade baremetal `Active`-state derivation
  to the VM default (Building) so API responses still get a coherent live signal
  instead of failing status refresh. Baremetal progress refinement depends on
  the Region provider credential having Ironic node visibility by instance
  UUID; if local or production policy withholds that visibility, the monitor
  intentionally behaves like the pre-Ironic Nova-only path.

## Caveats

- This package is intentionally eventual and observational; it does not make
  provider state changes happen, it notices and projects them.
- The `Active` condition is a live readiness signal once provisioning status
  reaches `provisioned`. If the monitor stops running, or a server is
  persistently skipped before the status patch (region resolution, identity, or
  Nova lookup failures), it can lag observed reality by an unbounded amount. In
  healthy operation staleness is bounded by one poll period. A pending rebuild is
  unaffected: it converges on the reconciler's own requeue, so a stopped monitor does
  not stall it. It does leave the `Rebuilding` stamp standing after convergence,
  because only the monitor writes `Active=Running`. A server parked on a quiesced
  provider `ERROR` (the provider's failed-rebuild row) is different: no requeue
  exists there, so recovery without a spec change depends on this monitor's
  `status.observed` write. A stopped or persistently-skipping monitor (the failure
  modes above) pins such a server at `provisioningStatus=error` until a spec edit,
  whose generation wake is monitor-independent.
- `unikorn_region_server_provision_duration_seconds` measures
  `CreationTimestamp → OS-SRV-USG:launched_at`. `launched_at` is when the
  hypervisor boots the instance, not when the guest OS finishes booting. For
  VMs this gap is negligible (<1 min); for baremetal it can be ~15 minutes.
  Closing it requires a guest-side signal (e.g. cloud-init phone-home) and is
  out of scope here.
- `unikorn_region_server_scheduling_duration_seconds` measures
  `CreationTimestamp → Nova created_at` (when Nova accepted the request).
  Together the two histograms decompose pre-boot latency into scheduling
  overhead and Nova allocation time.
- Both duration metrics fire only once per server, on the first transition
  into Running where the relevant Nova timestamp is non-nil. The intermediate
  `Active`-state path (Pending → Building → Running for VMs, Pending → Queued →
  Building → Running for baremetal) is transparent to the histograms: they
  trigger on the move into Running regardless of which earlier state the
  server was last observed in. Negative durations (clock skew between the Uni
  controller and Nova) are logged and skipped rather than recorded.
