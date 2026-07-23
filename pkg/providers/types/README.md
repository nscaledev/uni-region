# pkg/providers/types

## Intention

`pkg/providers/types` defines the provider-agnostic intermediate contract used
between handlers and concrete providers where the service does not have, or does
not want to depend on, a first-class custom resource shape for the thing being
exchanged.

That makes this package a mixed abstraction layer on purpose:

- when the service already has a stable persisted model, provider interfaces
  still operate directly on `pkg/apis/unikorn/v1alpha1` resources such as
  `Identity`, `Network`, `SecurityGroup`, `LoadBalancer`, and `Server`
- when the thing is provider-derived, query-driven, transient, or otherwise not
  represented as a concrete CRD, this package provides the neutral shape and
  capability contract instead, for example `Flavor`, `Image`,
  `VolumeClass`, `ExternalNetwork`, `ServerCreateOptions`, and the image query
  interfaces

So this package is not "all provider models". It is the intermediate
portability layer for provider-facing concepts that higher layers still need to
reason about even when no persisted service-native resource exists for them.

## Links

- [../../apis/unikorn/v1alpha1](../../apis/unikorn/v1alpha1/README.md)

`pkg/apis/unikorn/v1alpha1` defines the service-native persisted resources that
continue to be passed directly through many provider interface methods.

## Invariants And Guard Rails

- `Provider` is a capability composition interface, not one monolithic "SDK"
  wrapper. It embeds smaller contracts such as `ImageRead`, `ImageWrite`,
  `Network`, `Server`, `ServerConsole`, and `ServerSnapshot`.
- CRD-backed lifecycle operations continue to use repo-native
  `unikornv1.*` resource types where those are the stable service contract.
- Provider-derived or non-CRD concepts use the intermediate types defined in
  this package instead of leaking concrete provider SDK shapes upward.
- `ImageQuery` is a provider-neutral query-builder contract for image listing
  and filtering, not just a raw slice-returning helper.
- `ImageList` is a cached snapshot abstraction rather than a plain slice,
  shaped to support efficient repeated reads and memoization where provider
  implementations choose to provide them.
- `Image.Index()`, `Image.Equal()`, and `Image.DeepCopy()` are part of that
  cached-snapshot contract, not incidental helpers.
- `VolumeClass` is Region-scoped provider inventory, not a Volume lifecycle
  resource. It carries the immutable provider identifier and user-facing
  metadata that Region configuration can filter or enrich before a public API
  exposes the inventory.
- `ServerCreateOptions` carries launch-time derived inputs without forcing them
  into the persisted `Server` CRD shape.
- Exported errors such as `ErrImageNotReadyForUpload` and
  `ErrImageStillInUse` are semantic contract values used to communicate provider
  behaviour upward.

## Caveats

- This package is intentionally not a pure abstraction boundary. It mixes
  provider-neutral intermediate types with direct use of service-native CRD
  types where that is the clearer contract.
- Because of that mixed model, readers should not expect every provider-facing
  concept to be normalized into this package. Some concepts belong here, others
  deliberately remain owned by `pkg/apis/unikorn/v1alpha1`.
- `Image` carries a large amount of behaviourally important state: ownership,
  tags, readiness, OS identity, package inventory, virtualization mode, and GPU
  compatibility. It is not a thin transport struct.
- `Image.Tags` are described here as arbitrary labels, but higher layers in this
  repository currently derive some service semantics from image tags. See
  [../../constants](../../constants/README.md) for related discussion of that
  design smell. Callers should not assume tags are always semantically neutral
  just because this intermediate model presents them generically.
- Not every concrete provider is guaranteed to support every concept equally
  well. This package standardizes the contract surface, but concrete behaviour
  still depends on provider implementation choices and limitations.
- There is stale historical scar tissue in the interface layer, especially
  around old network-detail propagation commentary. That comment block is now a
  cleanup problem more than a live contract.

## TODO

- Remove the stale network-detail/CAPO-related comment baggage from the
  `Network` interface so the package does not imply a dead contract still
  exists.
- Re-evaluate whether image metadata that currently carries service semantics
  should remain represented as generic tags in this intermediate model.

## Cross-Package Context

- [../internal/openstack](../internal/openstack/README.md),
  [../internal/kubernetes](../internal/kubernetes/README.md), and
  [../internal/simulated](../internal/simulated/README.md) implement these
  contracts concretely
- [../../handler](../../handler/README.md) and specific handler subpackages
  consume these types when converting provider-derived information into API
  reads and actions
- [../../monitor](../../monitor/README.md) consumes provider-neutral read-side
  information such as flavors when observing runtime state
