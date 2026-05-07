# SSH Certificate Authority

## Purpose

`pkg/handler/sshcertificateauthority` handles the `v2` SSH certificate
authority resource.

Compared with most other region handlers, this package is intentionally small.
Its distinctive concerns are:

- public-key validation and normalization
- project-scoped visibility
- explicit deletion blocking when references still exist

## Distinctive Behaviour

- public keys are normalized and validated as OpenSSH authorized keys
- unsupported key options and unsupported key types are rejected
- deletion is blocked if explicit resource references still exist
- a `ResourceAPIVersionLabel` is still written even though there is no active
  `v1 -> v2` migration concern for this resource; it is there as future-proofing
  rather than because the handler is carrying old API baggage
- unlike network-linked resources, deletion safety here is based on explicit
  reference checking rather than owner-ref cascade

## Invariants And Guard Rails

- This is a `v2` resource, but unlike several sibling handlers it does not have
  meaningful `v1` migration baggage. The version label here is primarily a
  forward-compatibility affordance rather than evidence of an active old/new
  split for this resource.
- Create requires explicit organization/project input because there is no
  parent resource to infer scope from.
- The stored public key should be normalized enough that later consumers do not
  have to re-interpret malformed input.

## Caveats

- The package is intentionally narrow; most of the interesting architectural
  context sits in the handler roll-up and in the server package that references
  SSH certificate authorities.
- Deletion safety depends on callers correctly maintaining references.

## TODO

- Decide whether direct-read enforcement should remain coupled to
  `ResourceAPIVersionLabel` for future-proofing, given that this resource did
  not need the label for a `v1 -> v2` migration in the first place.

## Cross-Package Context

- [../server](../server/README.md) documents the main consumer of SSH
  certificate authorities
- [../README.md](../README.md) documents the explicit-reference deletion model
  used here instead of pure ownership cascade
