# `pkg/monitor`

`pkg/monitor` is the polling monitor framework for region.

Unlike handlers and managers, this layer is not driving desired-state
reconciliation directly. It periodically inspects live provider-backed resource
state and projects it back into Kubernetes status.

Servers are not polled here. The server controller polls in its own reconcile
pass, which also emits transitions and lifecycle metrics; see
[`pkg/managers/server`](../managers/server/README.md) and
[`pkg/provisioners/managers/server`](../provisioners/managers/server/README.md).
The `unikorn_region_server_state` gauge this package used to export is gone.

What it still measures is scraped from `/metrics` on `:8080`.

Architecturally, this is important because it is a cross-resource, potentially
cross-repo pattern rather than a one-off local helper. It is where the platform
admits that some lifecycle truth must be polled and observed, not only pushed by
controller watches.

## Current Shape

- builds a shared provider registry
- runs one or more `Checker`s on a poll interval
- logs and continues on non-fatal per-check failures

The current checker is [health/volume](./health/volume/README.md), which
projects provider-neutral Volume size and health while preserving
controller-owned provisioning state.

## Caveats

- This is polling by design. That makes it simpler and more decoupled, but also
  means timeliness and overhead are governed by poll period rather than watches.
- Provider/cache readiness is part of monitor startup, but a region whose
  provider cannot be initialized is skipped rather than taking the process down;
  see [providers](../providers/README.md).
