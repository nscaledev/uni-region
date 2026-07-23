# pkg/providers

## Intention

`pkg/providers` is the provider layer for region.

It sits between handler-level service semantics and concrete cloud backends. Its
job is to turn region-native resources and provider-neutral intermediate types
into real infrastructure operations against a substrate such as OpenStack or a
Kubernetes-backed region.

This is not a pure abstraction boundary in the academic sense. When the service
already has a strong persisted resource model, providers operate directly on
repo-native CRDs. When the thing being exchanged is provider-derived,
transient, or not modeled as a first-class Kubernetes resource, providers use
the neutral contract in [./types](./types/README.md).

The important design goal is shape preservation: higher layers should be able to
reason about regions, identities, networks, images, servers, and related
operations without having to absorb every provider's native object model.

## Links

- [./types](./types/README.md)
- [./util](./util/README.md)
- [./allocation/vlan](./allocation/vlan/README.md)
- [./internal/openstack](./internal/openstack/README.md)
- [./internal/kubernetes](./internal/kubernetes/README.md)
- [./internal/simulated](./internal/simulated/README.md)

`pkg/providers/types` defines the neutral intermediate contract. `pkg/providers/util`
covers narrow provider-support helpers. `pkg/providers/allocation/vlan` covers a
local compensating allocator for provider-network VLAN IDs. The `internal/*`
packages are the concrete provider implementations.

## Invariants And Guard Rails

- The package exposes two lookup surfaces:
  - `LookupCommon` returns a `types.CommonProvider` for region-level capability
    discovery that every provider must support
  - `LookupCloud` returns a full `types.Provider` for regions that implement the
    full cloud lifecycle surface
- `types.CommonProvider` is the minimum substrate contract:
  - return the effective `Region`
  - return allocatable `Flavor` inventory
  - return Region-scoped `VolumeClass` inventory
- `types.Provider` extends that common base with the broader image, identity,
  network, security-group, load-balancer, server, console, and snapshot
  lifecycle surfaces.
- The provider abstraction is intentionally mixed:
  - CRD-backed lifecycle operations still speak in repo-native
    `pkg/apis/unikorn/v1alpha1` resource types
  - provider-derived or non-CRD concepts use neutral types from
    [./types](./types/README.md)
- Concrete providers must preserve stable linkage between Unikorn resources and
  cloud-side resources. The mechanism may differ by backend, but the contract is
  the same:
  - higher layers need a reliable way to create, re-find, inspect, and delete
    the real backing resources
  - mirrored provider-state records are not the preferred answer unless the
    state cannot be reconstructed safely enough by other means
- Provider `Delete*` methods must be idempotent and must tolerate an unrealized
  identity as a no-op. Callers delegate unconditionally; the provider
  self-gates on realized identity rather than the caller gating on readiness or
  status:
  - rediscover backing resources by name rather than trusting recorded status,
    and treat already-absent resources as success
  - when the backing service-principal identity has not been realized (the
    `OpenstackIdentity` is absent, or has no project allocated yet) nothing
    could have been created, so the delete returns cleanly instead of erroring
  - this is safe because finalizer ordering keeps the identity alive until its
    consumers are gone: at delete time it is either realized-and-complete or
    never realized. Callers must therefore never gate a delete on identity
    readiness or recorded status — that belongs to this layer.
- Providers must tolerate changing backing credentials and region state rather
  than assuming client material is static for process lifetime.
  Credential rotation, secret refresh, and region configuration refresh are part
  of the provider contract, not incidental operational concerns.
- The provider layer is allowed to carry compensating local mechanisms where the
  underlying substrate is insufficient on its own:
  - OpenStack image caching exists because raw image API behaviour is too slow
    and awkward to expose directly
  - VLAN allocation exists because provider-network segmentation IDs are not
    allocated for us
- The provider layer is also where substrate quirks are normalized or fenced
  off. Providers may need to compensate for fuzzy list filters, missing
  allocation primitives, incomplete metadata, or other cloud-specific
  behaviour so higher layers can operate against a more stable contract.

## Backend Patterns

- [./internal/openstack](./internal/openstack/README.md) is the real full cloud
  provider:
  - it implements the full `types.Provider` contract
  - it prefers deterministic lookup against OpenStack over broad mirrored CRD
    state
  - it still carries a shrinking amount of persisted provider state via
    `OpenstackIdentity`
- [./internal/kubernetes](./internal/kubernetes/README.md) currently implements
  only `types.CommonProvider`:
  - it exposes a Kubernetes-backed region as a cloud-like substrate
  - it exports curated node-class-backed flavor inventory for higher layers that
    can consume the normal region shape
  - it returns empty block-storage `VolumeClass` inventory because the
    Kubernetes-backed substrate does not currently expose a Region block-storage
    class surface
- [./internal/simulated](./internal/simulated/README.md) implements the full
  interface in contract-shaped but deliberately incomplete form:
  - it exists to push broad integration coverage left
  - it is useful for deterministic load, race, and bottleneck testing at higher
    layers without requiring a real cloud deployment

## Caveats

- This is not a “write once, run everywhere” cloud abstraction. Provider
  differences still matter, and some of them are important enough that they
  appear directly in provider-specific code and docs.
- The mixed abstraction style is deliberate, but it does mean the provider
  boundary is not perfectly uniform. Some operations feel cloud-neutral, while
  others necessarily carry repo-native lifecycle and tenancy semantics.
- Stable linkage is a hard requirement, but the implementation strategy can be
  fragile:
  - deterministic lookup depends on stable naming, metadata, and scoping
    conventions
  - persisted provider-state records risk drift and race conditions if they
    duplicate cloud reality instead of anchoring genuinely unreconstructable
    state
- Credential handling remains one of the sharpest edges in this layer. Some
  current flows still rely on service-managed secret material and delegated
  application credentials that the wider platform would ideally stop exposing.
- Some provider-specific compensating mechanisms are valuable but architectural
  debt at the same time. Caches, local allocators, and compatibility bridges are
  signs that the substrate contract is imperfect, not proof that those patterns
  should expand unchecked.

## TODO

- Keep reducing persisted provider-state patterns in favour of deterministic or
  otherwise reconstructable linkage where that can be done safely.
- Continue shrinking flows that require the service to own or expose private
  credential material.
- Revisit mixed abstraction areas where provider-neutral logic has drifted into
  concrete provider packages because of historical coupling.

## Cross-Package Context

- [../handler](../handler/README.md) and specific handler packages depend on
  this layer to turn service API operations into real substrate behaviour
- [./types](./types/README.md) defines the contract surface concrete providers
  satisfy
- [../apis/unikorn/v1alpha1](../apis/unikorn/v1alpha1/README.md) defines the
  repo-native resources providers consume directly where a strong stored model
  already exists
