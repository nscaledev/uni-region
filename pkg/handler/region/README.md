# Region

## Purpose

`pkg/handler/region` is the read-side handler for region capabilities and
visibility.

Unlike most other handlers in this tree, it is not primarily about creating or
mutating user-owned lifecycle resources. Its job is to expose:

- visible regions
- region detail
- provider-derived flavor inventory
- provider-derived VolumeClass inventory
- provider-derived external network inventory

So this package is where the service turns stored region configuration and
provider capability discovery into user-visible region catalogue data.

## Distinctive Behaviour

- region visibility is filtered against region security constraints and the
  caller's organization scope
- flavor, VolumeClass, and external-network reads cross the provider boundary
  rather than reading from CRD-backed child resources
- flavor and VolumeClass conversion passes through the shared
  [`conversion`](../conversion/README.md) package because both are provider
  concepts rather than first-class CRDs

## Invariants And Guard Rails

- Regions are looked up directly from shared storage and then filtered for
  visibility.
- Provider-derived capability reads must resolve the correct provider for the
  selected region rather than trusting client-supplied assumptions.
- Flavor ordering is intentionally stable and user-facing.
- VolumeClass inventory is ordered by Region, class name, and class ID. Empty
  provider inventory remains a non-nil empty API list.
- Optional VolumeClass capacity bounds flow from Region-authored configuration
  through the provider-neutral inventory model. The handler does not derive
  them from provider data and leaves omitted bounds absent from the response.
- VolumeClass listing applies the canonical Region visibility filter before
  provider discovery. Explicit `regionID` values then act as selectors over
  that visible set. Repeated selectors do not duplicate results, and missing or
  inaccessible Regions are omitted so the response can be empty or partial.
- VolumeClass access preserves the existing Region visibility distinction:
  a nil organization allowlist is unrestricted, while a configured but empty
  allowlist permits no organizations.
- VolumeClass provider discovery requires global
  `region:volumeclasses:v2/read` or that grant in at least one organization
  visible to the caller. Global VolumeClass permission applies only to Regions
  retained by the canonical Region visibility filter; it does not expand the
  visible Region set. Requests without either grant omit the selected Regions
  without performing provider lookups.
- Region ACL checking is enforced in two places:
  - **List responses** (`FilterRegions`) — removes regions the caller cannot see
    before building the response or applying list selectors such as the
    VolumeClass `regionID` query.
  - **Direct Region references** (`CheckAccess`) — used by read or mutation
    operations that address or depend on one specific Region.
- `CheckAccess` returns `HTTPNotFound` rather than `HTTPForbidden` to avoid
  confirming the existence of regions the caller cannot see.

## Caveats

- This package is mostly read-side and therefore much simpler than the resource
  lifecycle handlers. Do not use it as the model for the rest of the handler
  layer.
- Region visibility is a service policy concern, not a storage property of the
  `Region` CRD by itself. Both the list filter and the per-ID access check must
  use the same ACL logic — they share the unexported `checkAccess` helper to
  enforce this.

## Cross-Package Context

- [../README.md](../README.md) explains why provider-backed capability reads sit
  alongside CRD-backed handler logic in this layer
- [../conversion](../conversion/README.md) covers the shared flavor and
  VolumeClass conversion boundary
- [../../providers](../../providers/README.md) documents the provider capability
  contracts consumed here
