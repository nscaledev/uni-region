# Server Health

`pkg/monitor/health/server` is the current concrete monitor checker.

It polls region servers, asks the backing provider for their effective state,
patches Kubernetes status, logs lifecycle transitions, and exports OTel metrics
for:

- current server counts by state/region/flavor
- pending-to-running provision duration

This makes it a bridge between provider-observed reality and the platform's
status/telemetry model.

## Distinctive Behaviour

- resolves provider and flavor context per region and caches it for a poll cycle
- updates server status through provider `UpdateServerState(...)`
- logs phase and health-condition transitions
- stamps and clears the pending-entry-time annotation used for provision-duration
  measurement
- rebuilds gauge counts from the effective server set each cycle

## Invariants And Guard Rails

- Fatal context cancellation/deadline errors abort the poll cycle; most
  per-server/provider failures are logged and skipped.
- Annotation patch failures for pending-entry time are non-fatal and retried on
  later polls.
- Servers skipped because region/provider resolution fails are absent from the
  gauge for that cycle rather than misreported as a fake state.

## Caveats

- This package is intentionally eventual and observational; it does not make
  provider state changes happen, it notices and projects them.
- Metric correctness depends on poll cadence and on the pending-entry annotation
  surviving long enough to observe the transition.
