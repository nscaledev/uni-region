# Security Group

## Purpose

`pkg/handler/securitygroup` handles security groups in both the older `v1`
identity-scoped model and the preferred `v2` network-linked model.

In `v2`, a security group is no longer addressed through an identity path. It
is attached directly to a network and inherits most of its real context from
that network.

So the distinctive concerns here are linkage, cascade, and a small amount of
rule-shape validation rather than deep multi-object orchestration.

## Distinctive Behaviour

- `v1` security groups are owned by an `Identity`
- `v2` security groups are owned by a `Network`
- `v2` create derives organization/project/region/identity context from the
  selected network
- `v2` rules are converted into a flatter wire shape with protocol/port/prefix
  validation rules

## Invariants And Guard Rails

- `v2` is the intended model; `v1` is compatibility surface only.
- direct `v2` object access is gated to resources labeled with
  `ResourceAPIVersionLabel=2`.
- A `SecurityGroup v2` must belong to a visible and authorized network in the
  same project context.
- Deletion is primarily handled through the ownership graph rooted at the
  network rather than bespoke orchestration here.

## Caveats

- Most of the interesting behaviour here is inherited from the handler roll-up:
  inferred scope, direct shared-namespace lookup, and ownership graph semantics.
- This package is intentionally not doing very much beyond linkage and rule
  translation; that is a sign of decent scoping rather than missing behaviour.

## TODO

- Delete the deprecated `v1` handler surface once migration is complete.

## Cross-Package Context

- [../network](../network/README.md) is the real parent context for `v2`
  security groups
- [../README.md](../README.md) documents the shared `v2` list/filter and
  direct-lookup model this package follows
