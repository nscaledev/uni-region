# `pkg/handler`

This package is the API application layer for region.

## Intent

The handler layer sits below middleware and above persisted Kubernetes
resources, provider abstractions, and a small amount of cross-service API
coordination with identity.

It is where the region API turns:

- authenticated and authorized request context
- OpenAPI request/response models
- CRD-backed storage
- provider-backed non-CRD capabilities

into resource-specific behaviour.

At the top level, [`handler.go`](./handler.go), [`handler_v2.go`](./handler_v2.go),
[`handler_v2_server.go`](./handler_v2_server.go), and the image-specific glue are
mostly transport wiring: they perform final handler-level RBAC checks where needed,
read request bodies, delegate to resource-specific clients, and normalize response
and error handling. The real package behaviour lives in the per-resource clients
beneath them.

The most important architectural fact in this package is that `v2` is the intended
handler model. `v1` is deprecated compatibility surface and should be migrated
away from as quickly as practical.

So this package should be understood primarily in `v2` terms:

- flatter API shapes
- direct resource lookup in a shared namespace
- label- and relationship-derived scope
- selector-prefiltered list operations
- saga-backed multi-object workflows where needed

`v1` remains important only because migration is not complete yet.

## Shared Handler Model

Most handler clients follow the same broad pattern:

1. resolve logical scope and visibility — including region ACL enforcement via
   `region.CheckAccess` for any operation that accepts a user-supplied region ID
   (path parameter, query parameter, or request body field)
2. load current state where mutation is involved
3. convert API request shape into required stored or provider-facing shape
4. merge system-owned metadata and derived context
5. write back with conflict detection where applicable
6. convert stored or provider-derived state back into API read models

This is not a blind REST-to-CRD translation layer. The handler layer is allowed
to enforce cross-resource invariants, repair missing operational context, manage
best-effort consistency across multiple objects, and reject requests that would
create obviously broken relationships — including ACL-mediated region access
control.

## Typed Identifiers at the Boundary

Resource identifiers reach the handler already typed. The OpenAPI layer binds
path parameters and create-body ID fields to the `regionids.*ID` types from
[`../ids`](../ids/README.md), so a non-UUID is rejected with a 400 at the router
before any handler runs — which is also what makes `region.CheckAccess` safe to
treat its region ID as well-formed. Handlers carry those typed IDs through their
per-resource client methods, and the types now continue past the handler into
region-owned CRD spec fields (e.g. the `Server` CRD's `FlavorID`, `Image.ID`,
`SecurityGroups[].ID`, `Networks[].ID`) and the provider image interface, so the
conversion to a plain string happens deeper — only at genuine sinks: Kubernetes
object names and labels, still-string read-model/status fields, and external
provider/region SDK calls. The by-name lookup primitives (`GetRaw`/`GetV2Raw`)
stay string-keyed and do that conversion at the `ObjectKey`. Read-model and
parent-linkage IDs are recovered fail-closed from labels/names via CRD accessor
methods (`Server.RegionID()`, `Network.NetworkID()`, `*.OrganizationID()`).

Tenancy, RBAC, and principal attribution are not re-derived here. Handlers
consume the identity service's scope-reader surface (the RBAC reader variants,
`ids.OwnedByProject`, and the principal enrichment helpers) as a black box.

This is a deliberate seam, not a dead end: the CRD and provider layers behind the
string sinks can be given typed IDs in a later pass without disturbing the handler
surface.

## `v2` First

`v2` is not just a flatter URL scheme. It changes how the handler layer works.

Compared with the older nested `v1` model:

- org/project context is no longer always present in the request path
- handlers often infer context from the request body or a dependent resource
- direct resource IDs are favored over path nesting
- list handlers use query parameters to constrain the working set before RBAC
  walks it
- resources created by the newer API are often gated with
  `ResourceAPIVersionLabel=2`

This is why the `v2` support helpers in [`util`](./util/README.md) exist at all.

### Principal Context Completion

In `v1`, tenancy context was often explicit in the path.

In `v2`, write paths such as `POST /api/v2/...` may not carry organization and
project in the URL, but the handler still needs that context for:

- audit attribution
- quota charging
- billing/accounting
- ownership enforcement

So `v2` handlers often recover org/project context from:

- required request fields
- or a dependent resource that already carries the binding, such as
  `server -> network`

### Selector-Prefiltered Lists

`v2` list handlers typically:

1. start from a label selector
2. add org/project constraints using RBAC query helpers
3. add region/network constraints where applicable
4. list from the shared namespace
5. apply tag filtering
6. apply per-item RBAC filtering

This is a real scalability and consistency pattern, not incidental code style.

## Shared Scoping Model

Unlike identity, region does not primarily resolve user-visible scope into a
separate Kubernetes namespace. Most region resources live in one shared
namespace.

That means handler scope is reconstructed through:

- labels
- owner relationships
- dependent-resource lookups
- RBAC checks against recovered organization/project bindings

This is one of the biggest architectural differences from
[`identity/pkg/handler`](https://github.com/nscaledev/uni-identity/blob/main/pkg/handler/README.md).

## Shared Lifecycle Graph

The other major difference from identity is that region makes the platform's
lifecycle graph very visible.

In practice, the system behaves like a DAG of resources connected by edges with
different semantics. Those edges can encode:

- propagation: should lifecycle intent flow across this edge?
- blocking: should deletion or teardown be prevented while this edge exists?

In region, the common edge mechanisms are:

- Kubernetes owner references for strong propagation and parent blocking
- foreground deletion for some older `v1` roots
- explicit resource references or finalizers for blocking edges without
  ownership
- cross-service consumers for propagation bridges across repositories
- quota/allocation relationships for accounting consistency edges

Examples:

- `v1` `Identity` acts as the root of the older ownership tree for dependent
  resources
- `v2` `Network` is special and creates its own service-principal identity
- `v2` `SecurityGroup`, `LoadBalancer`, and `Server` are generally owned by a
  `Network`
- `SSHCertificateAuthority v2` blocks deletion through explicit reference checks
- `Network v2` supports external references that block deletion

So the lifecycle invariant is:

- users should delete the visible parent resource
- handler, controller, and cross-service consumer logic should make downstream
  propagation or blocking happen appropriately for each edge type
- clients should not need to hunt for every child manually

## Shared Consistency Model

Many handler workflows touch more than one object or subsystem.

Examples include:

- quota/allocation changes alongside resource creation or update
- service-principal creation plus network creation
- resource validation against other resources before mutation
- provider-backed checks such as image lookup or network suitability

Because the backing store is Kubernetes objects and some workflows also cross
service or provider boundaries, there is no transaction layer.

The main consistency tools are:

- explicit read/modify/write
- optimistic-locking patch semantics
- owner refs and deletion blocking
- saga-based compensating workflows where a handler must coordinate multiple API
  operations rather than simply write Kubernetes state and rely on watch-driven
  propagation

### Saga Use

This package is the first place in region where the saga pattern becomes a real
architectural tool rather than an abstract library concept.

Sagas are used where handlers need ordered multi-step workflows with explicit
rollback/compensation, for example:

- `network v2` create
- `loadbalancer v2` create/update
- `storage v2` create/update

That is the handler-layer answer to “we need consistency across multiple steps,
but we do not have transactions.”

## Resource Patterns

- [`identity`](./identity/README.md): deprecated `v1` compatibility surface for
  the still-important service-principal/project-scoping concept
- [`region`](./region/README.md): read-side visibility and capability exposure
- [`image`](./image/README.md): provider-backed image import/query/delete and
  provenance handling
- [`network`](./network/README.md): core connectivity resource; `v2` network is
  the visible coordination point for a hidden service-principal-backed ownership
  root
- [`securitygroup`](./securitygroup/README.md): network-linked policy resource
- [`server`](./server/README.md): compute lifecycle plus operational verbs and
  snapshot bridge into image semantics
- [`loadbalancer`](./loadbalancer/README.md): network-linked service with
  stronger validation and quota coupling
- [`sshcertificateauthority`](./sshcertificateauthority/README.md): project-scoped
  SSH CA records with explicit reference-blocked deletion
- [`storage`](./storage/README.md): quota-heavy stateful resource with saga-backed
  create/update and attachment validation
- `VolumeClass`: read-only Region-scoped provider inventory. The v2 list handler
  requires `region:volumeclasses:v2/read`, validates explicit Region filters,
  excludes inaccessible Regions from unfiltered results, and maps only
  provider-neutral discovery fields.

## Caveats

- `v1` and `v2` are not equal architectural citizens. `v1` is deprecated and
  should not be treated as the model for future work.
- The flatter `v2` API is better for clients, but it pushes more hidden
  complexity into handlers:
  - context inference
  - principal repair
  - direct relationship lookup
  - API-version gating
- Because most resources live in one namespace, label discipline is critical.
  Scope, visibility, ancestry, and migration state all depend on it.
- Cross-object invariants are only best-effort. Owner references, finalizers,
  allocation records, and saga compensation improve consistency, but they do not
  turn the system into an ACID store.
- `GET /api/v2/volumeclasses` is a live provider-backed inventory route rather
  than a lifecycle resource surface. A failure from any selected Region fails
  the whole request; the handler does not return partial inventory.
- Identity roles must grant `region:volumeclasses:v2/read` before this route is
  rolled out. Without that grant, callers receive `404` for explicit Region
  filters and an empty list for unfiltered inventory. A global endpoint grant
  is evaluated only after canonical Region visibility.

## TODO

- Continue migrating all remaining `v1` handler surfaces to `v2` equivalents and
  then delete the deprecated `v1` compatibility paths.
- Remove handler behaviours that still depend on transitional provider-specific
  status or older API/storage shapes as those compatibility bridges disappear.
- Revisit places where the current `v2` model still hides an implicit resource
  or service-principal concept that would be cleaner as an explicit API object.
- Audit `v2` mutation RBAC verbs for copy/paste drift. Some update paths appear
  to check `Delete` where `Update` is more likely to be the intended action.

## Related Documentation

- [`../openapi`](../openapi/README.md), which documents the public contract these
  handlers implement
- [`identity/pkg/middleware/openapi`](https://github.com/nscaledev/uni-identity/blob/main/pkg/middleware/openapi/README.md),
  which establishes the trusted request context handlers consume
- [`../apis/unikorn/v1alpha1`](../apis/unikorn/v1alpha1/README.md), which defines
  the persisted storage contract the handlers read and write
- [`../providers`](../providers/README.md), which documents the provider layer
  many handlers depend on for real cloud-side behaviour
- [`core/pkg/server/conversion`](https://github.com/nscaledev/uni-core/blob/main/pkg/server/conversion/README.md),
  which provides shared metadata and conversion helpers used heavily here
