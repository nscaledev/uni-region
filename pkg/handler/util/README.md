# Util

## Purpose

`pkg/handler/util` is a small support package for the region `v2` handler
model.

Its current role is to preserve two things after the API moved away from the
older org/project path-nested shape:

- efficient pre-RBAC working-set reduction for list operations
- correct principal context for write operations where org/project can no
  longer be derived from the request path

So this is not a generic utility package in the usual sense. It is a narrow
collection of shared handler helpers that make the flatter `v2` API shape
workable.

## Main Responsibilities

### Query Constraint Helpers

`OrganizationIDQuery(...)`, `ProjectIDQuery(...)`, `AddRegionIDQuery(...)`, and
`AddNetworkIDQuery(...)` support `v2` list handlers.

`v2` list APIs allow callers to query visible resources through API query
parameters rather than relying only on path-scoped tenancy. These helpers
translate optional OpenAPI query parameters into the selector/RBAC query model
used by handlers so the candidate working set can be constrained before the
handler walks it for authorization and visibility checks.

That is an efficiency and scalability concern, not just a cosmetic helper.

### Principal Context Repair

`InjectUserPrincipal(...)` supports `v2` write handlers.

In the older nested API shape, org/project context could often be derived from
the request path itself. In `v2`, write operations such as `POST /api/v2/...`
do not necessarily carry that tenancy context in the URL, but the handler still
needs it for:

- audit attribution
- quota charging
- billing/accounting
- ownership enforcement

This helper updates the current principal when those fields were absent from the
inbound request-derived principal but are available from the request body or can
be inferred from a dependent resource that already carries the binding.

### Delete Propagation

`ForegroundDeleteOptions()` standardizes foreground deletion for handlers that
need Kubernetes owner/child cleanup to complete before delete processing is
considered finished.

## Invariants And Guard Rails

- This package exists to support shared `v2` handler behaviour, not to become a
  grab-bag of unrelated helpers.
- Query helpers should stay aligned with the label-selector and RBAC filtering
  model used by list handlers.
- Principal repair is only justified because the flatter `v2` API shape no
  longer always carries tenancy context in the path. It should remain tightly
  scoped to restoring audit/ownership/quota context, not mutating principals
  arbitrarily.
- Foreground deletion is a behavioural choice with lifecycle implications, not a
  random Kubernetes convenience default.

## Caveats

- The package name `util` is weak. The real scope is “shared `v2` handler
  support”.
- The current helpers are semantically coherent, but the package would become a
  junk drawer quickly if resource-specific logic were allowed to accumulate
  here.
- `InjectUserPrincipal(...)` reflects a real consequence of the `v2` API design:
  flatter resource URLs improve ergonomics, but they push more responsibility
  into handler logic to recover the operational context that older nested paths
  carried implicitly.

## Cross-Package Context

- [../README.md](../README.md) and concrete `v2` handler packages consume these
  helpers when implementing flat region API endpoints
- [../../openapi](../../openapi/README.md) defines the query-parameter shapes
  these helpers normalize
- [`identity/pkg/middleware/openapi`](../../../identity/pkg/middleware/openapi/README.md)
  defines the inbound principal derivation path that this package sometimes has
  to complete with additional org/project context
