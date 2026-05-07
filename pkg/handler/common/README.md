# Common

## Purpose

`pkg/handler/common` defines the shared constructor dependency bundle for the
region handler layer.

Its entire job is `ClientArgs`: a pragmatic package-level contract for the
ambient capabilities most handlers need in order to do useful work.

Those capabilities are:

- cached Kubernetes access
- process namespace
- provider lookup
- outbound identity API access

This is not an especially pure abstraction. It is a practical way to keep
handler construction uniform without hiding runtime dependencies in
`context.Context` or forcing a much larger refactor around a dedicated handler
runtime object.

## Main Component

### ClientArgs

`ClientArgs` is the shared constructor shape used by most region handlers and
their helper clients.

It carries:

- `client.Client` for cached Kubernetes access
- `Namespace` for process-local namespace scoping
- `providers.Providers` for provider lookup
- `identityapi.ClientWithResponsesInterface` for identity-side RBAC and tenancy
  interactions

The struct is intentionally made of interfaces and scalars so handlers remain
easy to unit test and do not need to construct their own ambient clients
ad hoc.

## Invariants And Guard Rails

- This package owns wiring shape, not business logic.
- `ClientArgs` is a shared handler-layer constructor contract with wide fan-out
  across concrete handler packages and top-level server wiring.
- The dependency bundle is intentionally coarse-grained for practicality, but it
  should still stay limited to ambient capabilities that are genuinely shared
  across the handler layer.
- Provider access is injected as the lookup façade in
  [`pkg/providers`](../../providers/README.md), not as concrete provider
  implementations.
- Identity access is treated as a normal ambient dependency of region handlers,
  not something each handler should construct independently.

## Caveats

- The package name `common` is broader than the actual responsibility. This is
  really a handler wiring/dependency contract package.
- `ClientArgs` is a pragmatic compromise, not an ideal architectural endpoint.
  It exists because:
  - hiding these dependencies in `context.Context` would be worse
  - pushing a dedicated runtime object through every constructor would have been
    more disruptive than the codebase needed at the time
- Not every consumer uses every field. The bundle is broader than any one
  handler because it is optimized for uniform construction rather than perfect
  per-handler minimalism.
- Because the struct has wide fan-out, casual field churn here would fragment
  constructor conventions across the handler layer quickly.

## Cross-Package Context

- [../README.md](../README.md) aggregates the concrete handlers built on this
  dependency bundle
- [../../providers](../../providers/README.md) provides the provider lookup
  façade injected through `ClientArgs`
- [`identity/pkg/handler/common`](../../../identity/pkg/handler/common/README.md)
  provides identity-specific handler helpers that many concrete region handlers
  also depend on alongside this package
