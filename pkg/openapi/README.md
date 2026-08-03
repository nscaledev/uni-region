# OpenAPI

## Purpose

This package is the canonical wire-contract package for the region service.

Its job is to define the HTTP/API surface in one place and materialize that
contract into the generated client, server, router, and type bindings used by
the rest of the service.

The service is used both directly and indirectly. Some parts of the contract
are intended for direct consumption, while higher-level services such as
compute- or Kubernetes-facing APIs may also expose curated subsets of the same
underlying capabilities.

The important point is that this package is not "just generated stubs". The
generated files are derivative. The authoritative source is
[`server.spec.yaml`](./server.spec.yaml), and the running service depends on
that contract both at build time and at runtime.

## What Lives Here

- `server.spec.yaml`: the authoritative API specification
- `types.go`: generated request/response/domain types
- `client.go`: generated typed client bindings
- `router.go`: generated server interface and router bindings
- `schema.go`: embedded schema used at runtime
- `builder.go`: a small local adapter used by
  [pkg/client](../client/README.md) to construct generated clients in the shape
  expected by the region service

## Why This Package Matters

This package sits at the meeting point of several layers:

- [pkg/server](../server/README.md) uses it to bind the concrete handler
  implementation to the generated HTTP router
- service middleware and routing layers depend on the runtime schema for route
  resolution and request/response validation
- [pkg/client](../client/README.md) wraps the generated client with the region
  service-to-service trust model
- [pkg/handler](../handler/README.md) implements the user-facing request and
  response semantics expressed by these types

So this package is the canonical wire contract, while those other packages
explain how the service enforces, consumes, or implements that contract.

## Visibility And Publication

The specification intentionally contains more than one surface in one schema:

- a deprecated `v1` surface, much of which remains hidden
- a newer `v2` resource surface that is the intended direction for public use,
  even though some operations still remain hidden
- protocol-supporting endpoints such as
  `/.well-known/openid-protected-resource`

Annotations such as `x-hidden` control whether an endpoint appears in
public-facing generated documentation. They do **not** mean the endpoint is
outside the canonical API contract.

`GET /api/v2/volumeclasses` is a published inventory endpoint. It follows the
flat list shape used by file-storage classes: callers can supply the repeatable
`regionID` query parameter. Each result carries its required Region binding and
encryption flag, with provider-neutral media and advertised-performance metadata
when the Region publishes them. The public contract deliberately contains no
Cinder, storage-pool, or other provider-specific fields.

Keeping the schema unified matters because it allows:

- one generated client/server contract
- one runtime validation and route-resolution source
- one place to track coexistence between deprecated and preferred API
  generations

The core design shift in `v2` is that resource relationships carry more of the
context that `v1` encoded directly into deeply nested paths. In the newer
surface, an identity already implies its organization/project placement, and a
network linked to that identity can derive that surrounding scope rather than
requiring every operation to restate the full hierarchy explicitly.

The newer shape also tries to preserve a read/modify/write-style duck-typed
contract where practical. When some parameters are only valid during creation
and become immutable afterwards, the readable model can still surface the
effective value through status/read-only fields so clients can round-trip the
resource shape without translating between unrelated models.

For public-facing API documentation, the specification should also be treated as
the primary authoring surface:

- every published endpoint should have a `summary`
- every published endpoint should have `tags` so related operations group
  together coherently in generated docs
- every endpoint should have a meaningful `description` explaining what the user
  is doing, how the operation works, and any important caveats

## Core Schema Pinning

All `$ref` URLs in `server.spec.yaml` and the import mapping in `config.yaml`
reference a **pinned release tag** of `unikorn-cloud/core` rather than `main`.
This is intentional: pointing at `main` causes `schema.go` (which embeds the
fully-resolved spec) to change whenever the upstream core schema moves,
producing spurious diffs in otherwise unrelated pull requests.

When bumping the `github.com/unikorn-cloud/core` dependency version, update the
pinned tag in both files to match:

```sh
# replace v1.x.y with the new release tag
OLD=v1.x.y
NEW=v1.a.b
sed -i "s|unikorn-cloud/core/${OLD}/|unikorn-cloud/core/${NEW}/|g" \
    pkg/openapi/server.spec.yaml \
    pkg/openapi/config.yaml
make validate   # regenerates schema.go and verifies the spec resolves cleanly
```

Commit the updated spec files, `config.yaml`, regenerated `schema.go`, and the
`go.mod`/`go.sum` changes together in one commit so the dependency and its
schema reference stay in sync.

## Overriding A Referenced Schema's Description

Shared schemas are deliberately generic, so a field that `$ref`s one often wants
a domain-specific description in its place — `ipv4Address` says "An IPv4
address", but `loadBalancerV2Status.vipAddress` wants "The provisioned virtual IP
address". The obvious way to write that does **not** work:

```yaml
# WRONG: silently discarded, and fails `make validate`
vipAddress:
  description: The provisioned virtual IP address.
  $ref: '#/components/schemas/ipv4Address'
```

This specification is `openapi: 3.0.3`, and in OpenAPI 3.0 a `$ref` must be the
only key in its object. Sibling keys are not part of the data model, so
conformant tooling drops them — `oapi-codegen` emits the *referenced* schema's
generic description and the override never reaches generated code or published
documentation. Worse, it fails quietly: the prose looks present in the spec and
is simply never rendered anywhere.

Since kin-openapi `v0.144.0` this is also a hard failure rather than a silent
one, which is the behaviour to rely on:

```
failed to validate spec invalid components:
  schema "loadBalancerListenerV2": extra sibling fields: [description]
```

Note that the validator reports only the first offending schema it encounters,
and map ordering is not stable between runs, so the schema named in the error
will move around. Fix every occurrence, not just the one reported.

Wrap the reference in a single-member `allOf` instead:

```yaml
# RIGHT: description is a sibling of allOf, not of $ref
vipAddress:
  description: The provisioned virtual IP address.
  allOf:
  - $ref: '#/components/schemas/ipv4Address'
```

This is the standard OpenAPI 3.0 idiom for annotating a reference. It changes
only the generated doc comment — the generated Go types are identical, because
`allOf` with a single member resolves to the referenced type.

To find every occurrence in the spec:

```sh
python3 -c '
import yaml
def walk(n, path):
    if isinstance(n, dict):
        if "$ref" in n and len(n) > 1:
            print(".".join(path), sorted(k for k in n if k != "$ref"))
        for k, v in n.items(): walk(v, path + [str(k)])
    elif isinstance(n, list):
        for i, v in enumerate(n): walk(v, path + [str(i)])
walk(yaml.safe_load(open("pkg/openapi/server.spec.yaml")), [])'
```

OpenAPI 3.1 removes this restriction and permits `$ref` siblings directly, which
would make the `allOf` wrapper unnecessary. Moving is blocked on the toolchain
rather than on the spec: `oapi-codegen` and the `make validate` checker both go
through kin-openapi, which supports 3.0 only —
[getkin/kin-openapi#230](https://github.com/getkin/kin-openapi/issues/230) tracks
3.1 support. When that lands, the migration is to bump `openapi:` to `3.1.0`,
unwrap every single-member `allOf` back to a bare `$ref` with its sibling
`description`, and regenerate.

Renderer support for `allOf` varies. If the published API documentation ever
shows a generic description where an override is expected, this section is the
first place to look.

## Invariants And Guard Rails

- a `description` may never be a sibling of a `$ref`; wrap the reference in a
  single-member `allOf` — see
  [Overriding A Referenced Schema's Description](#overriding-a-referenced-schemas-description)
  above
- `server.spec.yaml` is the source of truth; generated code is derivative
- the service runtime depends on the embedded schema, not only on generated Go
  interfaces
- schema changes can affect documentation, client generation, server binding,
  route resolution, and request/response validation simultaneously
- shared platform API primitives are imported from
  [`core/pkg/openapi`](https://github.com/nscaledev/uni-core/blob/main/pkg/openapi/README.md),
  rather than being redefined here
- the core schema reference must be pinned to a release tag, not `main` — see
  [Core Schema Pinning](#core-schema-pinning) above
- this package carries both deprecated `v1` and preferred `v2` generations in
  one contract, so compatibility changes, migration steps, and publication
  decisions must be made deliberately
- `builder.go` is intentionally small; it exists to adapt the generated client
  construction API to the expectations of higher-level region client code, not
  to invent a second client abstraction

## Semantics That Live Elsewhere

The schema defines the transport contract, but a number of important service
semantics are intentionally documented in higher-level packages rather than
fully encoded here:

- [pkg/handler](../handler/README.md): read/modify/write semantics, API/storage
  conversion rules, authorization-visible behaviour, lifecycle caveats, and the
  inference rules that let `v2` recover surrounding scope from linked resources
- [pkg/server](../server/README.md): runtime composition of the generated router
  into the actual middleware and handler stack
- [pkg/apis/unikorn/v1alpha1](../apis/unikorn/v1alpha1/README.md): persisted
  storage model and the split between service-facing resources and internal
  state
- [pkg/client](../client/README.md): outbound trust model and generated-client
  consumption

## Caveats

- the specification still carries a deprecated `v1` surface alongside the newer
  `v2` surface, so "canonical contract" does not mean "single-shape public API"
- some `v2` resources are clearly documented for publication, while others such
  as many server operations remain hidden; readers should not assume version
  number alone determines visibility
- the published VolumeClass route is backed by provider-neutral Region
  discovery; repeated Region filters act as selectors over the visible Region
  set, so missing or inaccessible Regions are omitted and the response can be
  empty or partial;
  its metadata uses core's `staticResourceMetadata`, matching Flavor inventory;
  because the provider model supplies no creation time, the generated response
  retains the same zero-value timestamp behaviour as Flavor
- the main value of `v2` is not just shorter paths. It is the shift toward a
  relationship-driven API shape where surrounding tenancy and placement context
  can often be inferred from the addressed resource graph
- preserving read/modify/write ergonomics in `v2` does not mean every field is
  always mutable. Some create-time choices are intentionally immutable later and
  are reflected back through read-only/status fields instead
- because generated code dominates the package by line count, it is easy to
  under-document the package even though it is architecturally central
- if higher-level documentation drifts from the schema, this package is where
  those mismatches become concrete first

## TODO

- Remove the deprecated `v1` surface over time so the unified schema does not
  permanently carry old and new API generations longer than necessary.
- Promote or remove ambiguous partially hidden `v2` endpoints deliberately,
  especially where resource families are split between published and hidden
  operations.
