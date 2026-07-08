# User Data

## Purpose

`pkg/userdata` owns the API-boundary contract for cloud-init user-data
validation: which payloads a create request may carry, and the exact HTTP 422
(status and message) returned when one is rejected.

It exists as a standalone package — rather than living in a handler — because
the contract is shared across services: this repository's v2 server handler
and the compute service's instances handler both call `Validate`, so the
behaviour is identical everywhere by construction rather than by convention.

## Behaviour

- Absent user-data is valid.
- Unmanaged payloads (no SSH certificate authority) must be recognizable
  cloud-init; gzip is additionally permitted because it is passed to the
  platform unmodified.
- Managed payloads (an SSH certificate authority is referenced) must support
  managed cloud-init augmentation, which excludes gzip.
- Rejections carry the parser's specific reason, recovered structurally from
  the parser's typed error — never by parsing message strings.

## Cross-Package Context

- [../provisioners/managers/server](../provisioners/managers/server/README.md)
  owns the underlying cloud-init parser, so the boundary check and provisioning
  behaviour cannot drift apart.
