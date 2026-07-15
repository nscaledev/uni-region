# pkg/apis/unikorn/v1alpha1

## Intention

`pkg/apis/unikorn/v1alpha1` defines the region service's Kubernetes storage
model and controller contract. It is not just a set of CRD structs for
generation. It is the persisted object model that handlers, provisioners,
providers, monitors, and controller-runtime integrations share.

The package contains three broad kinds of object:

- user-meaningful region resources such as `Region`, `Identity`, `Network`,
  `SecurityGroup`, `LoadBalancer`, `SSHCertificateAuthority`, `Server`, and
  `Volume`, and `FileStorage`
- service-internal provider state, primarily `OpenstackIdentity`
- operational support objects such as `VLANAllocation`, `FileStorageClass`, and
  `FileStorageProvisioner`

That split matters. Not every type in this package is part of the public
service model in the same way. Some types exist mainly so controllers and
providers have durable state to coordinate around, while others are historical
carryovers from older designs.

## Links

- [../../constants](../../constants/README.md)

`pkg/constants` defines much of the label and annotation vocabulary that these
stored objects rely on for linkage, migration, and operational coordination.

## Invariants And Guard Rails

- This package defines Kubernetes storage objects, not the full public service
  contract. Higher-level API semantics are layered on top elsewhere.
- A new external API generation does not necessarily imply a new CRD or storage
  model. This repository performs some API evolution in place over broadly
  stable stored shapes.
- `Region` is the configuration and capability root for a provider-backed
  region. It carries provider type, provider-specific configuration, stored
  visibility inputs, flavor/image/network/volume-class selection rules, and
  helper methods that downstream code actively depends on.
- OpenStack `VolumeClass` configuration is Region-scoped inventory metadata. It
  records which provider volume classes are eligible for export and how that
  inventory should be enriched; it does not create a project-owned
  `VolumeClass` CRD or any user-managed lifecycle resource. OpenStack maps this
  inventory to Cinder volume types internally, but the Region storage and
  public/domain vocabulary remains `VolumeClass`.
- Namespaced Kubernetes storage scope and platform tenancy scope are separate
  concerns. These objects are namespaced, but their logical visibility and
  authorization are often organization-, project-, identity-, or region-scoped
  at higher layers.
- `OpenstackIdentity` is the remaining necessary provider-state record. It
  persists the information needed to find and use the ephemeral OpenStack user,
  project, and credentials that back a region `Identity`, because those values
  cannot be recovered later by deterministic lookup in the same way as many
  other cloud-side objects.
- `VLANAllocation` is a coordination object, not a user-facing resource. It is
  designed around there being only one allocation record per region and relies
  on Kubernetes optimistic locking for safe concurrent updates.
- Several resources implement helper methods such as `Paused()`,
  `StatusConditionRead()`, and `StatusConditionWrite()` because this package
  also satisfies generic controller contracts. It should not be described as
  schema-only.
- `FileStorage` carries a more explicit observed-state model than the older
  resource types. Attachment-level provisioning state, observed size, usage
  reporting, and per-policy snapshot status are part of the stored
  reconciliation contract.
- `Volume` is the Region-owned block storage primitive. It is anchored to a
  `Network`, carries its own requested capacity and volume class identity, and
  is expected to carry quota/accounting responsibility in the Region layer.
  `Volume` does not define a per-network name uniqueness key; its resource ID
  follows the platform's normal UUID v4 identity pattern, while mutable display
  names live in standard metadata labels. `Volume.Spec.ClaimRef` records the
  kind and Region resource ID of the resource that owns the volume's attachment
  claim; a nil claim means the volume is available for claiming. `Server` is the
  current supported claim kind. Attachment realization remains outside
  `Volume.Status`, which is conditions-first and also reserves observed size for
  later controller/provider work. Provider-side volume identity is expected to
  be rediscovered by stable provider lookup rather than mirrored into status.
- The `Network -> Volume` graph edge is declared as containment for future
  behavior: Network scope propagates to Volume; co-location is implicit; Volume
  holds a reverse deletion-blocking relationship to Network for its lifetime;
  Network deletion may cascade to Volumes once controller/API behavior exists;
  Volume status does not propagate upward to Network.
- `FileStorage.Spec.SnapshotPolicies` is an optional inline desired-state list
  keyed by policy `name`. In persisted storage, omitted and empty lists both mean
  no user-managed snapshot policies are desired. Default snapshot protection is
  represented separately by a resolved desired-state setting; the region API
  enables it on create when callers omit the public control field. When default
  snapshot protection is enabled, the region API also materializes a hidden
  platform-managed `system-default` entry into this same list so the existing
  storage controller reconciles it like any other policy; that entry is never exposed in public REST reads. The CRD
  schema therefore bounds the stored list to five entries — four user-managed
  policies plus the optional hidden `system-default` baseline — caps policy names
  at 19 characters, and validates the schedule/retention shape so direct CRD
  writes cannot persist unsupported policy combinations.
- `Server.Spec.Image` is desired state. `Server.Spec.RebuildGeneration` is an
  internal command generation owned by the Region retry API; ordinary server
  updates preserve it. Nova's observed image and status remain authoritative
  for live state. `Server.Status.Rebuild` only records the target, generation,
  and accepted-attempt bookkeeping needed to classify a failed Region-issued
  rebuild. It is not proof of provider reality, and missing or mismatched
  bookkeeping must fail closed rather than authorize a destructive action.

## Caveats

- This package mixes durable public resource storage, internal provider state,
  and transitional compatibility fields in one API group. Readers must not
  assume that every type here is equally service-facing or equally stable.
- Some fields are explicitly transitional rather than ideal long-term schema.
  `Network.Spec.Provider` and `NetworkStatus.Openstack` are called out in code
  as temporary compatibility baggage.
- `OpenstackNetwork`, `OpenstackSecurityGroup`, and `OpenstackServer` are
  historical state-record types from an older design that attempted to mirror
  OpenStack state locally. That approach created drift and race conditions, and
  these types are now better understood as deletion candidates rather than
  durable architectural primitives.
- Where possible, OpenStack itself is now the intended source of truth for
  cloud-side state, with local code preferring deterministic lookup over
  mirrored persistence.
- `ResourceLabels()` exists on several resources to satisfy shared controller
  interfaces, but currently returns `nil, nil`. That is an implementation
  contract for generic integration, not proof that these resources already have
  a meaningful label-tuple identity model defined here.
- `SSHCertificateAuthority` is structurally much lighter than the other major
  resource types. It has no status and behaves more like a stored project-scoped
  OpenSSH user CA record than a long-running provisioned object.

## TODO

- Delete `OpenstackNetwork`, `OpenstackSecurityGroup`, and `OpenstackServer`.
  They are leftover mirror-state CRDs from an older design that drifted from
  OpenStack and introduced race conditions.
- Remove the remaining transitional `Network` compatibility baggage, especially
  `Network.Spec.Provider` and `NetworkStatus.Openstack`, once the old paths no
  longer need to be preserved.

## Cross-Package Context

- handler packages define the user-visible API behaviour, authorization checks,
  and migration semantics layered on top of these stored shapes
- provider and provisioner packages turn these stored specs and status records
  into concrete cloud-side resources and, where still necessary, internal
  provider state
- monitor code consumes the same stored model and status helpers, especially for
  server lifecycle and health transitions
