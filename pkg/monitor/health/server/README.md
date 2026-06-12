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
- projects provider-observed provisioning metadata when the provider can distinguish lifecycle sub-states; OpenStack baremetal servers in Nova `BUILD` use Ironic node state to report `queued`, active `provisioning`, or deploy `error`, and any Nova `ERROR` instance reports `error` rather than the condition-derived `provisioned`
- logs phase and health-condition transitions
- rebuilds gauge counts from the effective server set each cycle

## Invariants And Guard Rails

- Fatal context cancellation/deadline errors abort the poll cycle; most
  per-server/provider failures are logged and skipped.
- Servers skipped because region/provider resolution fails are absent from the
  gauge for that cycle rather than misreported as a fake state.
- Provider-specific progress refinement must be best effort. For example,
  OpenStack Ironic lookup failures leave provider provisioning metadata unset so
  API responses fall back to the generic condition-derived lifecycle instead of
  failing status refresh. Baremetal progress refinement depends on the Region
  provider credential having Ironic node visibility by instance UUID; if local or
  production policy withholds that visibility, the monitor intentionally behaves
  like the pre-Ironic Nova-only path.

## Caveats

- This package is intentionally eventual and observational; it does not make
  provider state changes happen, it notices and projects them.
- Provider provisioning metadata is only cleared by a successful poll pass, yet
  it takes precedence over condition-derived status in API responses. If the
  monitor stops running, or a server is persistently skipped before the status
  patch (region resolution, identity, or Nova lookup failures), a stale
  `queued`/`provisioning` override can mask a newer condition-derived state.
  In healthy operation staleness is bounded by one poll period; a prolonged
  mismatch between `metadata.provisioningStatus` and the server's conditions
  is a signal that this monitor is unhealthy.
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
- Both duration metrics fire only once per server, on the first
  Pending → Running transition where the relevant Nova timestamp is non-nil.
  Negative durations (clock skew between the Uni controller and Nova) are
  logged and skipped rather than recorded.
