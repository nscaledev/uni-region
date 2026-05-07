# Network

## Purpose

`pkg/handler/network` handles the region network resource in both the deprecated
`v1` model and the preferred `v2` model.

The `v1` path is the older nested identity-scoped resource surface.

The `v2` path is much more important architecturally. `Network v2` is special:
it provisions a service-principal identity, becomes an ownership root for later
resources, carries quota allocation, and supports external references that can
block deletion.

So this package is not just “CRUD for networks.” It is the point where the
preferred flat API model starts building a new resource tree under a hidden
service-principal root.

## Distinctive Behaviour

- `v1` networks are direct children of an explicit `Identity`
- `v2` network creation provisions a service-principal identity implicitly
- `v2` network creation uses a saga because creation spans multiple dependent
  steps:
  - validate request
  - create service principal
  - generate network
  - create quota allocation
  - create network
- `v2` delete does not delete the visible network object directly; it deletes
  the hidden service-principal root and relies on cascading deletion
- external references are represented as finalizers on the network and block
  delete until removed

## Invariants And Guard Rails

- `v2` is the intended model; `v1` is compatibility surface only.
- `Network v2` resources are labeled with `ResourceAPIVersionLabel=2`, and
  direct object access paths are gated accordingly.
- `v2` lists prefilter by organization/project/region before per-item RBAC.
- A `Network v2` is the visible coordination point for a resource subtree whose
  real ownership root is the hidden service principal created for it.
- Delete must respect both ownership cascade and explicit external references.

## Caveats

- The service principal created for `Network v2` is implicit in the API even
  though it is central to the real ownership model.
- `v2` network deletion is intentionally indirect, which is correct
  architecturally but easy to miss from the API surface alone.
- Some network behaviour still depends on transitional provider-specific status
  details downstream, especially for consumers like storage.

## TODO

- Revisit whether the hidden `v2` service-principal concept should become an
  explicit API object in a future cleaner model.
- Delete the deprecated `v1` nested network surface once migration is complete.

## Cross-Package Context

- [../identity](../identity/README.md) explains the hidden service-principal
  concept this package still relies on
- [../storage](../storage/README.md), [../securitygroup](../securitygroup/README.md),
  [../loadbalancer](../loadbalancer/README.md), and [../server](../server/README.md)
  all depend on `Network v2` as a parent/linkage root
- [../../../core/pkg/server/saga](../../../core/pkg/server/saga/README.md)
  documents the saga machinery used heavily here
