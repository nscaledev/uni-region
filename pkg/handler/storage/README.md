# Storage

## Purpose

`pkg/handler/storage` handles `v2` file storage.

It is one of the strongest examples of why the saga pattern exists in this
repository. Storage create and update are not just “write one CRD” operations.
They coordinate:

- request validation
- storage-class lookup
- attachment/network validation
- quota allocation changes
- storage-object mutation

So this package is where stateful lifecycle, attachment semantics, and quota
accounting meet.

## Distinctive Behaviour

- create and update both use sagas with explicit compensation for quota
  allocation changes
- attachments are validated against `Network v2` resources in the caller's
  project
- storage-class and region compatibility are validated before mutation
- attachment IP ranges are derived from transitional provider-specific network
  storage-range information
- attachment status reporting is currently based partly on desired state rather
  than fully observed actual state

## Invariants And Guard Rails

- Storage is a `v2` resource and follows the flatter direct-lookup model.
- Region access is enforced via `region.CheckAccess` during request validation,
  preventing callers from creating storage in regions they cannot see.
- Quota allocation changes are part of the storage lifecycle contract, not an
  optional side effect.
- Attachments must reference visible, provisioned networks in the same project.
- Update preserves the existing allocation annotation while mutating the storage
  resource.

## Caveats

- This package still depends on transitional provider-specific network status
  (`Status.Openstack.StorageRange`) because a cleaner generic source of that
  information does not yet exist.
- Attachment status is intentionally conservative and not fully actual-state
  derived yet.
- The package relies heavily on saga compensation because there is no transaction
  boundary for storage-plus-allocation changes.

## TODO

- Remove the dependency on transitional provider-specific network status once a
  generic storage-range source exists.
- Tighten attachment status so it reflects observed state rather than mostly
  desired state where practical.

## Cross-Package Context

- [../network](../network/README.md) documents the network dependency used for
  attachments
- [core/pkg/server/saga](https://github.com/nscaledev/uni-core/blob/main/pkg/server/saga/README.md)
  documents the compensating-workflow machinery used heavily here
- [`identity/pkg/client`](https://github.com/nscaledev/uni-identity/blob/main/pkg/client/README.md)
  documents the allocation client helpers this package coordinates with
