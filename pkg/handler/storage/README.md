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
- user-managed inline snapshot policies are optional and stored on the file
  storage resource as named schedules with `retention.keep`
- default snapshot protection is controlled separately from user-managed
  snapshot policies through `defaultSnapshotProtectionEnabled`
- parent File Storage create and update requests manage the user-managed
  snapshot policy list and default snapshot protection setting; snapshot
  policies do not create independent public resources or IDs
- parent File Storage reads expose desired user-managed snapshot policy
  configuration in spec and projected per-policy status in status, reporting
  pending when no observed policy condition exists yet
- default snapshot protection is implemented by materializing a hidden
  platform-managed `system-default` snapshot policy into the stored policy list,
  which the existing storage controller reconciles like any other policy (no
  controller change)
- parent File Storage reads expose the resolved default snapshot protection
  setting but not the materialized `system-default` policy that implements it
- attachment status reporting is currently based partly on desired state rather
  than fully observed actual state

## Invariants And Guard Rails

- Storage is a `v2` resource and follows the flatter direct-lookup model.
- Region access is enforced via `region.CheckAccess` during request validation,
  preventing callers from creating storage in regions they cannot see.
- File Storage update requires File Storage update authorization before mutating
  storage or allocation state.
- Quota allocation changes are part of the storage lifecycle contract, not an
  optional side effect.
- Attachments must reference visible, provisioned networks in the same project.
- Attached networks must expose a valid non-empty IPv4 storage range.
- Snapshot policy `name` is the stable identity key for user-managed policies.
  Create requests with omitted or empty `snapshotPolicies` store no
  user-managed policies, and non-empty create lists store exactly the caller
  list.
- `defaultSnapshotProtectionEnabled` controls the hidden platform-managed
  baseline. It defaults to enabled when omitted on create, is preserved when
  omitted on update, rejects null, and is the authoritative public desired state.
  The handler keeps a materialized `system-default` entry in the stored policy
  list present if and only if the boolean is true (a fixed `daily`/`04:00Z`/
  `keep 7` schedule), so the boolean and the stored entry never drift, and that
  entry is never exposed in public REST responses.
- `system-default` is a reserved snapshot policy name: a
  user-managed policy may never use it, independent of whether default snapshot
  protection is enabled. Server rejects any caller-supplied
  policy named `system-default` (422) on both create and update, alongside the
  uniqueness and schedule-shape rules. The name is reserved for the hidden
  platform-managed baseline, which is materialized into the stored spec only while
  default protection is enabled.
- Parent File Storage update preserves existing user-managed snapshot policies
  when `snapshotPolicies` is omitted, clears them when the list is
  empty, and replaces them when the list is non-empty.
- Snapshot policy mutations use File Storage authorization, are blocked while
  the parent File Storage object is deleting, and mutate only the parent inline
  desired-state list.
- Snapshot policy primitive constraints (name pattern and the provider-safe
  19-character limit, the four-policy caller maximum, retention, and per-field
  schedule values) are enforced by the OpenAPI schema through the
  request-validation middleware before the handler runs. The handler validates
  only the rules the schema cannot express: rejecting duplicate policy names, the
  reserved `system-default` name, and invalid schedule shapes (the interval/field
  combinations). The four-policy limit
  is caller-facing; the stored CRD list allows a fifth entry for the materialized
  hidden `system-default` baseline, which never counts against the caller maximum.
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
- Snapshot policy status is a public projection of stored per-policy conditions.
  API acceptance means desired state was stored; provider-side protection may
  still be pending until reconciliation observes it.

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
