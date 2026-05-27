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
- logs phase and health-condition transitions
- preserves provider health condition messages, including OpenStack fault
  messages for servers observed in `ERROR`, so the API can expose actionable
  failure context to upstream services
- rebuilds gauge counts from the effective server set each cycle

## Invariants And Guard Rails

- Fatal context cancellation/deadline errors abort the poll cycle; most
  per-server/provider failures are logged and skipped.
- Servers skipped because region/provider resolution fails are absent from the
  gauge for that cycle rather than misreported as a fake state.

## Caveats

- This package is intentionally eventual and observational; it does not make
  provider state changes happen, it notices and projects them.
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
