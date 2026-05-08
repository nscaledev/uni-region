# Client

## Purpose

This package is the region-specific realization of the generic client machinery
in [`core/pkg/client`](https://github.com/nscaledev/uni-core/blob/main/pkg/client/README.md),
built on top of the outbound identity-aware transport model already established
in [`identity/pkg/client`](https://github.com/nscaledev/uni-identity/blob/main/pkg/client/README.md).

Its main job is to construct outbound region API clients that obey the same
internal service-to-service trust model used elsewhere in the platform.

In practice that means:

- building generated [OpenAPI](../openapi/README.md) clients for the region API
- reusing the shared TLS and HTTP client construction from
  [`core/pkg/client`](https://github.com/nscaledev/uni-core/blob/main/pkg/client/README.md)
- reusing the delegated-principal and trace-propagation model from
  [`identity/pkg/client`](https://github.com/nscaledev/uni-identity/blob/main/pkg/client/README.md)
- exposing a small region-specific helper for network reference lifecycle

This is not a general client-abstraction package. Most of the interesting trust
and transport behaviour lives below it in `core` and `identity`. This package
mainly binds those shared client foundations to the region OpenAPI surface.

## Main Components

### Client

`Client` is a thin wrapper around `identity/pkg/client.BaseClient`.

It carries:

- a Kubernetes client
- region HTTP endpoint options
- optional HTTP client certificate configuration

It does not reimplement transport behaviour itself. It reuses the base client
so region callers inherit the same internal trust and delegation machinery as
other service-to-service clients.

### APIClient

`APIClient(...)` is the normal service-to-service path.

It constructs a generated region API client from [`pkg/openapi`](../openapi)
and delegates request construction to `identity/pkg/client` so outbound calls
carry the same trace and principal propagation model expected by the wider
platform.

### ControllerClient

`ControllerClient(...)` is the controller/provisioner path.

Instead of assuming an active request principal already exists in context, it
reconstructs delegated principal information from a persisted Kubernetes
resource and applies that to the outbound region API request.

This is what allows controller-style workflows in other services to call the
region API while still participating in the same delegated identity model as
request-originated flows.

### References

`References` is the only region-specific helper currently living in this
package.

It wraps the region API's network-reference endpoints so remote services can add
or remove dependency references on a `Network` using the shared resource
reference model from [`core/pkg/manager`](https://github.com/nscaledev/uni-core/blob/main/pkg/manager/README.md).

That matters because deletion protection is not purely local to region-owned
descendants. Other services may hold logical dependencies on a network, and the
reference API is how they register or release those dependencies over the
normal service boundary.

## Invariants And Guard Rails

- This package is an outbound region-API client binding, not a standalone trust
  or transport implementation.
- The authoritative transport and delegation behaviour comes from
  `core/pkg/client` and `identity/pkg/client`; this package should stay thin and
  avoid forking those rules locally.
- `APIClient` is for request-context service-to-service calls.
- `ControllerClient` is for controller/provisioner-style calls that must derive
  delegated principal context from durable resource metadata.
- `References` uses the shared resource-reference model from
  [`core/pkg/manager`](https://github.com/nscaledev/uni-core/blob/main/pkg/manager/README.md) rather than inventing
  a region-specific dependency identity format.
- Reference add/remove operations are thin API wrappers intended for normal
  convergent lifecycle use, with success determined by the region API response
  rather than by local client-side assumptions.

## Caveats

- The package name is broader than the current responsibility. This is mostly a
  region OpenAPI client wrapper plus one network-reference helper.
- Most of the interesting behaviour is inherited rather than implemented here.
  If the trust model or principal propagation changes, the real source of truth
  is in `core` and `identity`, not this package.
- `References` currently covers only network references. That is a real current
  contract surface, not a generic reusable dependency helper for every region
  resource type.
- `References` still carries dead constructor shape inherited from the matching
  identity helper: `serviceDescriptor` is accepted but not currently used here.
  If outbound wire identity is ever added, it should be implemented in the
  shared client-construction path rather than hidden in this helper.
- Because this package is intentionally thin, it is easy to overestimate how
  much “region client logic” actually lives here. Most failures in outbound
  trust semantics would originate below this package, even if they surface here.
