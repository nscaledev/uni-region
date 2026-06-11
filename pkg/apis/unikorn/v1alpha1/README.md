# pkg/apis/unikorn/v1alpha1

## Intention

`pkg/apis/unikorn/v1alpha1` defines the region service's Kubernetes storage
model and controller contract. It is not just a set of CRD structs for
generation. It is the persisted object model that handlers, provisioners,
providers, monitors, and controller-runtime integrations share.

The package contains three broad kinds of object:

- user-meaningful region resources such as `Region`, `Identity`, `Network`,
  `SecurityGroup`, `LoadBalancer`, `SSHCertificateAuthority`, `Server`, and
  `FileStorage`
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
  visibility inputs, flavor/image/network selection rules, and helper methods
  that downstream code actively depends on.
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
- `FileStorage.Spec.SnapshotPolicies` is an optional inline desired-state list
  keyed by policy `name`. Omitted and empty lists both mean no snapshot
  protection is desired. The CRD schema bounds the list to four entries and
  validates the schedule/retention shape so direct CRD writes cannot persist
  unsupported policy combinations.
- `FileStorage.Status.SnapshotPolicies` mirrors the embedded child-status
  pattern: each entry is keyed by `name` and contains only optional generic
  conditions. Provider identifiers, observed schedule copies, and aggregate
  snapshot health are intentionally outside this storage model.

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
