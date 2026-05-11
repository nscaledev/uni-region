# Base

## Purpose

`pkg/provisioners/internal/base` is the shared helper for manager provisioners.

It provides the common lookup logic for:

- resolving a cloud provider from a resource's `region` label
- resolving the backing `Identity` from a resource's `identity` label
- returning both together when a provisioner needs project-scoped provider access

This is small, but important. Most resource provisioners in region are really
operating against a provider plus an identity-scoped cloud project, and this
package keeps that resolution logic consistent.

## Invariants And Guard Rails

- The package assumes label discipline is correct. Missing or wrong
  `RegionLabel`/`IdentityLabel` values are consistency failures, not normal
  business cases.
- Provider lookup is region-based, identity lookup is label-based.
- This package is not where provisioning policy lives; it only resolves the
  inputs that provisioners need.

## Caveats

- Because it resolves identity from labels, it is tightly coupled to the
  lifecycle-DAG labeling model documented in the handler layer.
- This package uses the contextual Kubernetes client from `core/pkg/client`,
  which means callers must already be running inside the controller/reconciler
  execution model.

## Cross-Package Context

- [../../README.md](../../README.md) documents the higher-level provisioner split
- [../../../handler/README.md](../../../handler/README.md) documents the label
  and root semantics that make these lookups possible
