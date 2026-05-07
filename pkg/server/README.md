# `pkg/server`

This package is the API server composition layer for region.

## Intent

It takes the region service's handler layer and wraps it in the concrete HTTP
server, OpenAPI router, middleware stack, and runtime dependency construction
needed to serve the API.

Structurally, it is very close to
[`identity/pkg/server`](../../../identity/pkg/server/README.md). The important
difference is that region does not own the full authentication and authorization
stack locally. Instead it delegates trust assembly back through identity and
focuses on constructing:

- the shared core middleware pipeline
- the region-specific OpenAPI server wrapper
- the outbound identity client used for remote authorization
- the provider registry used by handlers
- the thin handler dependency bundle in [`pkg/handler/common`](../handler/common/README.md)

## Middleware Architecture

Like identity, the package composes two middleware layers:

- the shared pre-routing `core` middleware stack
- the post-routing OpenAPI middleware stack used for validation and audit

### Pre-Routing Core Middleware

The raw router is wrapped in this order:

1. OpenTelemetry
2. logging
3. route resolver
4. CORS

The ordering has the same rationale as identity:

- OpenTelemetry runs first so trace context exists before anything else
- logging runs early so failures before deep handler logic are still captured
  with correlation context
- route resolution must happen before middleware that depends on OpenAPI
  operation/schema metadata
- CORS comes after route resolution because its schema-driven behaviour depends
  on the resolved route

### Post-Routing OpenAPI Middleware

Region then attaches service-specific middleware through the generated OpenAPI
server wrapper:

1. validator
2. audit

As with identity, those are applied in reverse by the generated wrapper, so the
validator/authorizer stage runs before audit and both run before the handler
implementation.

## The Big Difference From Identity

The trust model is not assembled locally here the way it is in identity.

Identity builds its own local authn/authz runtime:

- JWT issuer
- OAuth2 authenticator
- RBAC engine
- user database
- local OpenAPI authorizer

Region does not.

Instead, region constructs a remote authorizer using
[`identity/pkg/middleware/openapi/remote`](../../../identity/pkg/middleware/openapi/remote/README.md)
and an outbound identity API client configuration. That means:

- identity remains the source of truth for trust and authorization context
- region server wiring is thinner and more dependent on cross-service identity
  integration
- region is implementing a platform-defined server and trust composition
  contract here, not inventing service-local policy choices about how validation,
  audit, and authorization should fundamentally work
- trust breakage here is often really a mismatch between region's remote
  authorizer use and identity's middleware expectations

## Construction Flow

At a high level, server construction is:

1. build the OpenAPI schema
2. create the raw router
3. install the shared pre-routing middleware stack
4. create the remote identity-backed authorizer
5. build validator and audit middleware
6. construct the outbound identity API client
7. construct the provider registry, including image-cache warmup
8. assemble [`handler/common.ClientArgs`](../handler/common/README.md)
9. construct the region handler
10. attach everything through the generated OpenAPI router and return
   `http.Server`

That is the main package-specific delta from identity: region server startup
includes provider bootstrap and remote authorization wiring rather than local
identity-authority bootstrap.

## Runtime Dependencies

The most important constructed runtime dependencies are:

- an identity API client for remote authorization and handler-side identity
  operations
- a provider registry from [`pkg/providers`](../providers/README.md)
- a thin handler dependency bundle in
  [`pkg/handler/common`](../handler/common/README.md)

This is why the region handler constructor is much narrower than identity's.
Most heavy runtime concerns have already been pushed into identity or the
provider layer before the handler is built.

## Distinctive Operational Behaviour

- `pprof` is started on a separate listener at `:6060`
- provider startup currently requests image-cache warmup
- the server relies on a remote trust boundary with identity rather than being
  a self-contained identity authority

## Invariants And Guard Rails

- The shared `core` middleware stack runs before any region-specific OpenAPI
  middleware.
- Middleware ordering is part of the package contract because later stages
  depend on context established by earlier ones.
- The server composition choices here should be treated as platform contract,
  not service-local freedom. Region assembles the prescribed layers; it does
  not define their high-level trust semantics independently.
- Region authorization context is expected to be assembled through identity's
  remote authorizer model, not recreated ad hoc in handlers.
- Provider construction is a server startup concern, not something individual
  handlers should perform independently.
- Handler construction should stay thin and pass through
  [`handler/common.ClientArgs`](../handler/common/README.md) rather than growing
  a second identity-like runtime object.

## Caveats

- This package is highly ordering-sensitive, just like identity's server
  package.
- The remote authorizer means region server correctness depends on a
  cross-service contract with identity, not just local code.
- Provider bootstrap at server start is convenient, but it also means provider
  readiness and image-cache behaviour are part of API readiness.
- The separate `pprof` listener is operationally useful, but it is also a
  second exposed server process concern that deployments must account for.

## Cross-Package Context

- [../handler](../handler/README.md) documents the application layer this
  package serves
- [../providers](../providers/README.md) documents the provider registry built
  here
- [`../../../identity/pkg/server`](../../../identity/pkg/server/README.md)
  documents the closely related server composition pattern this package mirrors
- [`../../../identity/pkg/middleware/openapi/remote`](../../../identity/pkg/middleware/openapi/remote/README.md)
  documents the remote trust model region relies on
- [`../../../core/pkg/server/middleware`](../../../core/pkg/server/middleware/README.md)
  documents the canonical shared pre-routing middleware pipeline composed here
