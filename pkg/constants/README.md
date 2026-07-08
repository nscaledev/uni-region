# pkg/constants

## Intention

`pkg/constants` is the region service's shared control vocabulary. It is the
single place that defines the service's canonical runtime identity and the
metadata keys that other packages rely on for resource linkage, in-place API
migration, image-origin discrimination, and a small amount of operational state
tracking.

Most of the package is not "just constants" in the casual sense. It contains a
small number of contract clusters:

- runtime identity for the service binary
- linkage labels that tie stored resources back to their region, identity, or
  network context, and to first-class dependent resources such as volumes
- resource type/reference strings used by RBAC and future reference-management
  surfaces
- an API-generation label used to distinguish old and new external API
  semantics while keeping storage broadly in place
- specialized image and server-state metadata that drives snapshot/import
  provenance and monitor-owned pending-state timing

The same package also defines the process-level build metadata for the running
binary: application name, version, revision, and the derived service
descriptor/version string used by shared runtime layers.

## Invariants And Guard Rails

- This package is a shared contract package, not a miscellaneous bucket for
  arbitrary constants.
- Code that reads or writes the region service's standard labels, annotations,
  and tags should use these constants rather than open-coded strings.
- `RegionLabel`, `IdentityLabel`, `NetworkLabel`, and `VolumeLabel` are part of
  the service's resource-linkage model. They are not optional decorative metadata.
- `VolumeResourceType`, `VolumeResourceReference`, and
  `VolumeReferencesResourceReference` define the canonical string vocabulary for
  the Region-owned block storage volume resource. No public Volume handler uses
  them yet; they exist so the internal model and later API/RBAC work share one
  name.
- `ResourceAPIVersionLabel` is the canonical stored discriminator used to
  distinguish old and new external API generations when the underlying CRD
  shape remains broadly stable and objects are migrated in place rather than
  split into separate storage models.
- `MarshalAPIVersion()` and `UnmarshalAPIVersion()` define the current storage
  encoding for that API version discriminator as a decimal string.
- `ServerPendingEntryTimeAnnotation` has a single-writer operational contract:
  the region monitor stamps it when a server enters `Pending` and removes it
  when the server leaves that state.
- `ImageSourceTag`, `ImageSourceImport`, `ImageSourceSnapshot`, and
  `ImageOrganizationIDTag` are part of the current image-origin contract used to
  distinguish imported images pushed into OpenStack via the back channel from
  snapshot-derived images, and to preserve organization ownership where display
  and deletion semantics differ.
- `Application`, `Version`, and `Revision` are the canonical runtime identity
  for the binary in this repository.
- `ServiceDescriptor()` must remain aligned with the shared `core`
  `ServiceDescriptor` shape so manager and runtime code can consume it
  generically.
- `VersionString()` must remain suitable for wire-visible client identity such
  as HTTP `User-Agent` style reporting.

## Caveats

- Changing active metadata keys here is a compatibility change across multiple
  packages and, in some cases, across repositories. It is not a local refactor.
- `Application` is derived from `os.Args[0]`, so reported process identity
  depends partly on how the binary is packaged or invoked.
- If the build does not inject `Version` or `Revision`, the package still
  compiles, but much of its deployment-debugging value is lost.
- `ServerPendingEntryTimeAnnotation` records an entry timestamp, but its value
  is not corrected while the server stays pending. Manual edits therefore remain
  visible until the next state transition out of and back into `Pending`.
- The image-origin contract is currently encoded in generic user-visible tags,
  which is a weak abstraction for service-owned semantics. A typed API field
  would be a safer long-term design than relying on mutable key/value metadata.
- `SecurityGroupLabel` and `ServerLabel` are currently better treated as
  transitional vocabulary than as strong active contracts. If their remaining
  consumers disappear, they are plausible deletion candidates rather than keys
  that should be preserved indefinitely.
- The package mixes two related but distinct concerns: runtime service identity
  and resource metadata contract. That is coherent today, but it means readers
  should not undersell the package because of its small size.

## Cross-Repo Context

This package follows the same cross-repository pattern used elsewhere for
runtime identity and service descriptors, but most of its metadata vocabulary is
best understood first as a region-repository contract for resource linkage,
in-place API migration, image-origin handling, and monitor-managed server
timing.
