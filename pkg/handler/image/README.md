# Image

## Purpose

`pkg/handler/image` is the image-specific handler client.

It is one of the biggest outliers in the handler graph because it is mostly
provider-backed rather than CRD-backed. The package does not primarily manage a
stored Kubernetes image resource. Instead it coordinates image import, query,
deletion, visibility, and snapshot-adjacent metadata through the provider layer.

It therefore sits closer to the provider image-policy surface than to the
normal CRUD-over-CRD pattern used by many other handlers.

## Distinctive Behaviour

- `v1` image list/create/delete flows are organization- and region-scoped
- `v2` image query is flatter and provider-query-driven
- import validates the remote image by peeking the MBR and currently requires a
  raw-format style bootable image
- image provenance and ownership semantics are carried through tags and
  organization scoping
- delete enforces ownership visibility and surfaces “still in use” conflicts

## Invariants And Guard Rails

- Region access is enforced via `region.CheckAccess` for all image operations
  (`v1` list/create/delete and `v2` query), preventing access to regions the
  caller cannot see.
- Image visibility is provider-mediated, not inferred from CRD ancestry.
- Imported images are tagged to distinguish provenance and organization
  ownership.
- Delete only succeeds for images effectively owned by the caller's
  organization.
- `v2` query semantics are intentionally driven through provider query
  interfaces rather than reimplementing image indexing locally.

## Caveats

- This package inherits the image-origin/tag design smell already documented in
  [`../../constants`](../../constants/README.md): tags are carrying semantics
  that would be cleaner as typed API fields.
- Import validation is intentionally narrow and conservative at present.
- Because images are mostly provider-backed, this package is not a good example
  of the normal CRD-centric handler pattern.

## Cross-Package Context

- [../README.md](../README.md) explains why image is an outlier in the handler
  graph
- [../../providers/types](../../providers/types/README.md) and
  [../../providers/internal/openstack](../../providers/internal/openstack/README.md)
  describe the provider-side image model this package consumes
- [../../constants](../../constants/README.md) documents the image provenance
  tag contract
