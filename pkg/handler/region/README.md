# Region

## Purpose

`pkg/handler/region` is the read-side handler for region capabilities and
visibility.

Unlike most other handlers in this tree, it is not primarily about creating or
mutating user-owned lifecycle resources. Its job is to expose:

- visible regions
- region detail
- provider-derived flavor inventory
- provider-derived external network inventory

So this package is where the service turns stored region configuration and
provider capability discovery into user-visible region catalogue data.

## Distinctive Behaviour

- region visibility is filtered against region security constraints and the
  caller's organization scope
- flavor and external-network reads cross the provider boundary rather than
  reading from CRD-backed child resources
- flavor conversion passes through the shared
  [`conversion`](../conversion/README.md) package because flavor is a provider
  concept rather than a first-class CRD

## Invariants And Guard Rails

- Regions are looked up directly from shared storage and then filtered for
  visibility.
- Provider-derived capability reads must resolve the correct provider for the
  selected region rather than trusting client-supplied assumptions.
- Flavor ordering is intentionally stable and user-facing.

## Caveats

- This package is mostly read-side and therefore much simpler than the resource
  lifecycle handlers. Do not use it as the model for the rest of the handler
  layer.
- Visibility filtering for regions is a service policy concern, not a storage
  property of the `Region` CRD by itself.

## Cross-Package Context

- [../README.md](../README.md) explains why provider-backed capability reads sit
  alongside CRD-backed handler logic in this layer
- [../conversion](../conversion/README.md) covers the shared flavor conversion
  boundary
- [../../providers](../../providers/README.md) documents the provider capability
  contracts consumed here
