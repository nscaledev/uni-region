# `pkg/monitor`

`pkg/monitor` is the polling monitor framework for region.

Unlike handlers and managers, this layer is not driving desired-state
reconciliation directly. It periodically inspects live provider-backed resource
state and projects that back into:

- Kubernetes status updates
- structured transition logs
- OpenTelemetry metrics

Architecturally, this is important because it is a cross-resource, potentially
cross-repo pattern rather than a one-off local helper. It is where the platform
admits that some lifecycle truth must be polled and observed, not only pushed by
controller watches.

## Current Shape

- builds a shared provider registry
- creates OTel instruments
- runs one or more `Checker`s on a poll interval
- logs and continues on non-fatal per-check failures

Right now the only checker is
[health/server](./health/server/README.md), but the abstraction is clearly
intended to allow additional monitor classes later.

## Caveats

- This is polling by design. That makes it simpler and more decoupled, but also
  means timeliness and overhead are governed by poll period rather than watches.
- Provider/cache readiness is part of monitor startup, but unlike the API server
  and controller manager this process opts into
  `providers.Options.TolerateRegionInitErrors`. A single region with a broken
  provider (e.g. an expired or invalid TLS certificate) is logged and skipped at
  startup instead of crash-looping the whole process; that region is retried on
  every subsequent lookup until it initializes cleanly. Servers in an
  unavailable region are simply absent from that poll's checks, per
  [health/server](./health/server/README.md).
