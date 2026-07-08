# Packages

## Purpose

This tree contains the region service implementation.

At a high level it splits into six layers:

- API and storage model definition
- cloud-provider abstraction and concrete provider bindings
- request handling and server composition
- controller/provisioner lifecycle management
- polling-based status and telemetry projection
- a small amount of shared client and wiring glue

The useful way to read it is not as a directory tree, but as one system:

- handlers shape and validate the lifecycle graph
- provisioners and managers realize provider-side effects
- monitors project observed provider truth back into status and metrics
- providers bind the region model to real or simulated clouds
- `Volume` is an internal Region storage model today: a network-anchored,
  quota-carrying block storage resource whose public API, controller, and
  provider behavior are deliberately introduced by later tickets

## Recommended Reading Order

### API And Contract Model

- [constants](./constants/README.md)
- [apis/unikorn/v1alpha1](./apis/unikorn/v1alpha1/README.md)
- [ids](./ids/README.md)
- [openapi](./openapi/README.md)

These packages define the shared control vocabulary, the stored Kubernetes
resource model, the typed resource identifiers exposed at the API layer, and the
HTTP wire contract.

The most important direction here is that `v2` is the intended API shape.
`v1` remains as deprecated compatibility surface and should be migrated away
from as quickly as practical.

### Provider Model

- [providers](./providers/README.md)
- [providers/types](./providers/types/README.md)
- [providers/internal/openstack](./providers/internal/openstack/README.md)
- [providers/internal/kubernetes](./providers/internal/kubernetes/README.md)
- [providers/internal/simulated](./providers/internal/simulated/README.md)

These packages define the mixed provider boundary:

- CRD-backed service resources are still passed through in native region shapes
- non-CRD provider concepts use intermediate provider-neutral types
- concrete providers preserve the linkage between region resources and real
  cloud resources

OpenStack is the real heavyweight implementation. Kubernetes and simulated are
alternative substrates shaped to fit the same broad service model.

### Handler And Server Layer

- [client](./client/README.md)
- [handler](./handler/README.md)
- [server](./server/README.md)

These packages define the application layer:

- direct lookup in a shared namespace rather than namespace indirection
- label- and relationship-derived scope
- `v2` selector-prefiltered listing and principal-context completion
- request-to-storage/provider translation
- platform-defined middleware and server composition

### Controller Lifecycle Layer

- [provisioners](./provisioners/README.md)
- [managers](./managers/README.md)

These packages define how desired state becomes provider-side effects.

Managers are thin controller factories. Provisioners hold the resource-specific
lifecycle logic: waiting for prerequisite identity readiness, maintaining
reference edges, calling providers, and cleaning up allocation/accounting
relationships.

### Monitor Layer

- [monitor](./monitor/README.md)
- [monitor/health/server](./monitor/health/server/README.md)

These packages cover the part of the system that is intentionally observational
rather than declarative.

They poll provider-backed reality and project it back into Kubernetes status,
logs, and telemetry. That is an important architectural admission: not all
lifecycle truth in this platform arrives through controller watches alone.

## Important Cross-Cutting Themes

### `v2` First

The service is converging on flat `v2` APIs.

Compared with the older nested `v1` model, that means:

- direct resource addressing instead of deep path hierarchy
- org/project context recovered from request fields or dependent resources
- list working sets constrained before RBAC walks
- more handler responsibility for inferred scope and graph validation

`v1` is not an equal architectural citizen. It is deprecated compatibility
surface.

### Shared Namespace, Recovered Scope

Unlike identity, region does not primarily model user-visible scope by mapping
it onto separate Kubernetes namespaces.

Most resources live in one shared namespace. Scope is reconstructed through:

- labels
- owner relationships
- dependent-resource lookup
- RBAC checks over recovered organization/project bindings

That difference is one of the most important things to understand before
reading the handlers.

### Lifecycle DAG

The service behaves like a lifecycle DAG whose edges carry different blocking
and propagation semantics.

Common edge types include:

- owner references
- explicit blocking references
- quota/allocation consistency edges
- hidden service-principal roots
- cross-service propagation bridges

This is the abstraction that ties together handlers, provisioners, monitors,
and even command-level consumers outside `pkg`.

### OpenStack Project Scoping

OpenStack is not just a provider backend here. It strongly shapes the service
model.

The important pattern is:

- managed-domain authority provisions user/project scaffolding
- most real cloud resources are then created in the per-identity project
- the OpenStack project becomes the main lookup, isolation, and intended
  accounting boundary

That is why service principals, hidden identity roots, deterministic lookup,
and image/resource visibility rules matter so much throughout this tree.

### Best-Effort Consistency

Much of the service operates over Kubernetes objects plus external provider and
service APIs rather than a single transaction system.

The main consistency tools are:

- optimistic read/modify/write
- ownership and deletion blocking
- saga-based compensation for true multi-operation workflows
- polling where observed truth cannot be trusted to arrive through watches

This is especially visible in:

- [handler](./handler/README.md)
- [provisioners](./provisioners/README.md)
- [monitor](./monitor/README.md)

## Caveats

- The package graph still contains transitional compatibility debt, especially
  around `v1`, provider-specific historical state, and version-label handling.
- Some of the most important lifecycle edges are not contained entirely within
  `pkg`; for example, cross-service project deletion propagation is implemented
  by [`cmd/unikorn-region-project-consumer`](../cmd/unikorn-region-project-consumer/README.md).
