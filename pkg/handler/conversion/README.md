# Conversion

## Purpose

`pkg/handler/conversion` is the handler-layer analogue of
[`pkg/providers/types`](../../providers/types/README.md).

Where `pkg/providers/types` defines provider-neutral intermediate shapes for
concepts that do not have a first-class CRD or durable Kubernetes storage
model, this package owns the shared conversion of those intermediate shapes into
the region OpenAPI model when they need to cross the handler boundary.

So this is not “all handler conversion logic”. It is the small shared adapter
layer for non-CRD concepts that multiple handlers may need to expose through the
API in a consistent form.

## Current Scope

Today the package is deliberately narrow.

It currently provides shared conversion for provider-neutral flavor and
VolumeClass data:

- `types.Architecture` -> `openapi.Architecture`
- `types.GPUVendor` -> `openapi.GpuVendor`
- `types.Flavor` -> `openapi.Flavor`
- `[]types.Flavor` -> `openapi.Flavors`
- `types.VolumeClass` -> `openapi.VolumeClassV2Read`
- `types.VolumeClassList` -> `openapi.VolumeClassListV2Read`

That is why the package may look under-populated at first glance: the
abstraction line is broader than the current amount of code, but the shape is
coherent.

## Invariants And Guard Rails

- This package is for shared conversion of provider-neutral, non-CRD concepts
  into region API shapes.
- Resource-specific conversion should stay close to the owning handler or
  resource package rather than accumulating here.
- The package should remain aligned with
  [`pkg/providers/types`](../../providers/types/README.md): if a concept lives
  there because it has no first-class CRD, and multiple handlers need to expose
  it through the API, this package is the right place for the shared mapping.
- Enum and shape translation here is part of the wire contract. Careless changes
  can break API stability even if the underlying provider-neutral type remains
  unchanged.

## Caveats

- The package name is broader than the current implementation. Right now this is
  the shared conversion boundary for flavor and VolumeClass inventory plus a
  small amount of supporting enum translation.
- That broad name is still defensible because the intended boundary is
  meaningful: shared non-CRD type conversion belongs here, while resource-local
  conversion belongs elsewhere.
- Because the package is small, it would be easy to dissolve it back into
  individual handlers. That would make short-term editing simpler, but would
  reintroduce duplicated translation logic for the same provider-neutral types.

## Cross-Package Context

- [../../providers/types](../../providers/types/README.md) defines the
  intermediate provider-neutral shapes converted here
- [../../openapi](../../openapi/README.md) defines the wire-visible API types
  this package produces
- [../region](../region/README.md) and other handler packages consume these
  conversions when exposing provider-derived shared concepts through the region
  API
