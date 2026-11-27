# Common

## Purpose

`pkg/handler/common` defines shared handler dependencies, Identity allocation
delegation, and the shared provisioning-status read projection for the region
handler layer.

`ClientArgs` is a pragmatic package-level contract for the ambient capabilities
that most handlers need.

Those capabilities are:

- direct Kubernetes access, reads and writes alike
- process namespace
- provider lookup
- outbound identity API access
- Identity allocation create, update, and delete delegation

This package keeps handler construction uniform. It does not hide runtime
dependencies in `context.Context` or require a separate handler runtime object.

## Main Component

### ClientArgs

`ClientArgs` is the shared constructor shape used by most region handlers and
their helper clients.

It also delegates Identity allocation create, update, and delete calls. Concrete
handlers keep their allocation requirements, compensation, and error handling.

It carries:

- `client.Client` for direct Kubernetes access, reads and writes alike
- `Namespace` for process-local namespace scoping
- `providers.Providers` for provider lookup
- `identityapi.ClientWithResponsesInterface` for identity-side RBAC and tenancy
  interactions
- `RetryConflictOnce`, which retries a conflicted guarded write once against a
  fresh read and returns `409` if that conflicts too

The struct is intentionally made of interfaces and scalars so handlers remain
easy to unit test and do not need to construct their own ambient clients
ad hoc.

### GetV2 and FetchV2

`GetV2` loads a `v2` resource and authorizes an `authz.Target` on it, declaring
a primary target before the fetch. `FetchV2` loads one without a check, for the
one case that needs a resource's scope before its own check; whatever it
returns must be authorized before use. See the
[handler README's Authorization section](../README.md#authorization).

### ProjectScopedReadMetadata

`ProjectScopedReadMetadata` wraps core's project-scoped read metadata. Core
derives `provisioningStatus` from the `Available` condition alone, which between
a spec update and the next reconcile still holds the previous spec's result. A
result not stamped with the current `metadata.generation` therefore reads as
`provisioning`, with reason `Provisioning` and message "awaiting reconciliation
of the current specification". A deleting resource stays `deprovisioning` and a
never-evaluated one stays `pending`.

A resource opts in by stamping its `Available` condition with the evaluated
generation and implementing `ProvisioningResult`; see the
[API types README](../../apis/unikorn/v1alpha1/README.md).

## Invariants And Guard Rails

- This package owns shared wiring, Identity allocation delegation, and the
  shared provisioning-status read projection. It does not own
  resource-specific allocation requirements or lifecycle behavior.
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
- [`identity/pkg/handler/common`](https://github.com/nscaledev/uni-identity/blob/main/pkg/handler/common/README.md)
  provides identity-specific handler helpers that many concrete region handlers
  also depend on alongside this package
