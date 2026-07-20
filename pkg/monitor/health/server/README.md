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
- the provider's poll also advances `Status.Rebuild.State` from observed Nova
  evidence, forward-only and never creating, clearing, or retargeting the
  marker. Advancement is attributed by image ref, not by spec match: only an
  observed ref equal to the marker's target advances `Rebuilding` (an active
  `task_state`) or `Succeeded` (converged and quiescent — a stable non-error
  status with an empty `task_state`), and an `ERROR` under that ref, or under a
  marker already durably accepted, advances `Failed`; a durably accepted
  rebuild whose readable ref has moved off the target advances `Failed` by
  supersession. A marker still `Initiated` with a non-matching ref advances
  nothing, so an unattributed observation cannot destroy the submission gate.
  That terminal stamp is the wake signal that settles a pending server rebuild:
  a `Succeeded`/`Failed` state trips the server manager's `RebuildSettled` watch
  predicate (`pkg/provisioners/managers/server`), which wakes the reconciler for
  a settlement pass — marker clear on success, `UserActionRequired` park on
  failure. The chain is: monitor stamps the terminal observation → predicate
  fires → reconcile → the reconciler re-decides from its own fresh provider
  read. The monitor's stamp is stimulus, not authorization — the reconciler
  never trusts the projected status to make the rebuild decision.
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
  provider state changes happen, it notices and projects them. That still holds
  literally — the monitor issues no provider calls — but its
  `Status.Rebuild.State` stamps are now load-bearing for rebuild settlement
  liveness: since the reconciler stopped self-polling a rebuild to completion,
  a pending rebuild settles (marker clear on success, failure park) only when
  the monitor records a terminal observation and that level wakes the
  reconciler. Observation is no longer purely for display.
- Lost marker stamps self-heal by recomputation, not by re-assertion. Each poll
  recomputes the stamp from a fresh Nova read and patches the difference under
  optimistic lock; a conflict skips that cycle's patch, but the underlying
  evidence persists (a quiescent convergence is stable, an `ERROR` is terminal),
  so the next poll recomputes a value that still differs from etcd and its patch
  is non-empty and produces a real watch event. Re-asserting a value already in
  etcd would be the wrong mechanism: a merge patch with no change is an empty
  patch, makes no API-server write, and produces no watch event — so the design
  never relies on re-assertion to re-fire a settlement wake.
- The rebuild marker-state advance and the health condition are written in a
  single `Status().Patch` per poll cycle (`check.go`). This is a load-bearing
  liveness invariant, not an implementation accident. A conflict-dropped failure
  park is recovered by the `RebuildSettled` wake re-firing on the next non-empty
  status write while the terminal marker still stands; splitting this into
  separate patches with health written first would let a health-already-matching
  no-op patch produce no event and drop that wake, reopening the window in which
  a dropped park stalls. See `pkg/provisioners/managers/server` for the wake
  predicate that depends on it.
- The `Active` condition is a live readiness signal once provisioning status
  reaches `provisioned`. If the monitor stops running, or a server is
  persistently skipped before the status patch (region resolution, identity, or
  Nova lookup failures), it can lag observed reality by an unbounded amount. In
  healthy operation staleness is bounded by one poll period. For a pending
  rebuild the same stall is now functional, not merely cosmetic: a stopped or
  persistently-skipping monitor never records the terminal observation, so the
  marker clear and the failure park wait indefinitely — until a controller
  restart re-lists the server or a spec change wakes the reconciler through
  another path. The rebuild is delayed, not lost.
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
