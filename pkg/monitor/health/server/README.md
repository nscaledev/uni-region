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
- refines the server's live `Phase` from observed Nova + Ironic state. For OpenStack baremetal servers in Nova `BUILD`, an Ironic node lookup distinguishes `Queued` (provider has accepted the create but hardware is not yet engaged — pre-deploy Ironic states) from `Building` (Ironic actively deploying, including transient deploy failures). VMs in Nova `BUILD` go straight to `Building`. Provisioning status itself stays purely condition-derived (provisioner-owned, one-shot): the monitor never writes it. Phase is the live readiness signal once provisioning status reaches `provisioned`.
- latches `status.provisionedAt` from Nova `launched_at`, alongside `launchedAt`
  and ahead of the `BUILD` early-return, so it fires for VMs and baremetal alike
  regardless of live power state. This is monitor-owned observed state (like
  `launchedAt`), not the provisioner-owned provisioning-status condition; the
  rebuild decision itself stays with the controller. Unlike `launchedAt` it is
  written once and never cleared, and the controller's bounded provider-create
  delete-and-retry guard keys off it so a server that has ever booted is never
  rebuilt. Servers predating the field backfill it on the next poll once booted.
- logs phase and health-condition transitions
- rebuilds gauge counts from the effective server set each cycle

## Invariants And Guard Rails

- Fatal context cancellation/deadline errors abort the poll cycle; most
  per-server/provider failures are logged and skipped.
- Servers skipped because region/provider resolution fails are absent from the
  gauge for that cycle rather than misreported as a fake state.
- Provider-specific progress refinement must be best effort. For example,
  OpenStack Ironic lookup failures degrade baremetal Phase derivation to the
  VM default (Building) so API responses still get a coherent live signal
  instead of failing status refresh. Baremetal progress refinement depends on
  the Region provider credential having Ironic node visibility by instance
  UUID; if local or production policy withholds that visibility, the monitor
  intentionally behaves like the pre-Ironic Nova-only path.

## Caveats

- This package is intentionally eventual and observational; it does not make
  provider state changes happen, it notices and projects them.
- Phase is a live readiness signal once provisioning status reaches
  `provisioned`. If the monitor stops running, or a server is persistently
  skipped before the status patch (region resolution, identity, or Nova lookup
  failures), Phase can lag observed reality by an unbounded amount. In healthy
  operation staleness is bounded by one poll period.
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
  Phase path (Pending → Building → Running for VMs, Pending → Queued →
  Building → Running for baremetal) is transparent to the histograms: they
  trigger on the move into Running regardless of which earlier phase the
  server was last observed in. Negative durations (clock skew between the Uni
  controller and Nova) are logged and skipped rather than recorded.
