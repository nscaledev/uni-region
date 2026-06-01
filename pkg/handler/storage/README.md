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
- attachment parallelism is capped to the usable network storage range; smaller
  non-empty storage ranges are accepted and used in full
- attachment status rows follow desired attachments, then project observed
  attachment provisioning state and API-safe mount options when available
- inline snapshot policies are optional and stored on the file storage resource
  as named schedules with `retention.keep`
- attachment status reporting is currently based partly on desired state rather
  than fully observed actual state

## Invariants And Guard Rails

- Storage is a `v2` resource and follows the flatter direct-lookup model.
- Region access is enforced via `region.CheckAccess` during request validation,
  preventing callers from creating storage in regions they cannot see.
- Quota allocation changes are part of the storage lifecycle contract, not an
  optional side effect.
- Attachments must reference visible, provisioned networks in the same project.
- Attached networks must expose a valid non-empty IPv4 storage range.
- Snapshot policy `name` is the stable identity key; omitting
  `snapshotPolicies` on create stores no policies.
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
- Expand attachment status only when public API consumers need additional
  API-safe observed fields.

## Cross-Package Context

- [../network](../network/README.md) documents the network dependency used for
  attachments
- [core/pkg/server/saga](https://github.com/nscaledev/uni-core/blob/main/pkg/server/saga/README.md)
  documents the compensating-workflow machinery used heavily here
- [`identity/pkg/client`](https://github.com/nscaledev/uni-identity/blob/main/pkg/client/README.md)
  documents the allocation client helpers this package coordinates with
