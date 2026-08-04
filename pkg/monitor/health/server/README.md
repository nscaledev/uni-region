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

- resolves provider and flavor context per region and caches it for a poll cycle
- updates server status through provider `UpdateServerState(...)`
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
  existing `GetServer` — no extra provider call) once the server reaches Nova
  `ACTIVE`. ACTIVE is the barrier at which the port MAC is guaranteed bound for
  VMs and baremetal alike: for baremetal Ironic rebinds the port to the real NIC
  MAC asynchronously during deploy, so the value observed earlier (e.g. by the
  reconciler at port-create time) is the ephemeral Neutron MAC and must not be
  trusted. A MAC is only ever written, never cleared: gating on ACTIVE and
  skipping an empty read means a transient port-read miss cannot unset a held
  value, while unconditionally writing a valid MAC self-heals drift (the status
  PATCH makes a same-value write a no-op).
- logs phase and health-condition transitions
- populates `status.observed` from the poll's existing `GetServer` response. The
  region has one writer *function* rather than one caller: the reconciler's
  create-retry existence check goes through the same `UpdateServerState`, and so the
  same projection. One derivation with no arbitration is what removes the ordering
  argument between the two status writers — not the monitor holding the region
  alone. `generation` is stamped unconditionally, so the subtree exists from the
  first poll that read the provider at all — a present subtree with no `image`
  means "polled, image unreadable", which is not the same fact as an absent
  subtree meaning "never successfully polled".
  `image` tracks the live provider image, but an unreadable ref (absent, empty or
  unparseable) preserves the previous value and never clears it, for the same
  reason `macAddress` is never cleared: a transient read miss must not erase a
  known fact. `error` is the opposite — live state that clears on an authoritative
  non-error read. That is safe only because a provider that cannot be reached
  aborts the poll before any write, so connectivity loss can never be mistaken for
  a recovery. It is gated on the provider reporting `ERROR` rather than on Nova's
  `fault` being populated, because Nova leaves a stale `fault` on a server that has
  since recovered; and Nova's `fault.details` is deliberately dropped, being an
  admin-only stack trace that must not reach projected status.
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

## Invariants And Guard Rails

- Fatal context cancellation/deadline errors abort the poll cycle; most
  per-server/provider failures are logged and skipped.
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
  because only the monitor writes `Active=Running`.
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
