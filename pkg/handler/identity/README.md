# Identity

## Purpose

`pkg/handler/identity` is the legacy `v1` handler for region identities.

As a handler surface, it is deprecated along with the older nested `v1`
Kubernetes-service-oriented model. It should not be treated as the future shape
of region APIs.

The underlying concept is still important, though. An `Identity` is the
project-scoped service-principal anchor that allows region to wire real cloud
resources into a provider such as OpenStack. In that sense it is somewhat
analogous to an Azure service principal, even though the surrounding topology is
different.

Today, `v2` often hides that concept implicitly, most notably by creating a
service principal as part of `Network v2` creation. So the handler is legacy,
but the architectural idea is not.

## Current Responsibilities

- create and list legacy `v1` region identities
- get legacy `v1` identities
- expose provider-specific convenience state on read, especially for OpenStack
- provide cloud credentials and related provider state to deprecated `v1`
  Kubernetes/CAPO-oriented flows
- delete identity roots and rely on cascading deletion of dependants

There is no meaningful update lifecycle here in the modern sense. This handler
is mainly retained as create/read/delete compatibility surface for the
deprecated `v1` model.

The OpenStack read path is the most distinctive behaviour:

- cloud and cloud-config convenience fields
- user/project IDs
- server-group ID
- SSH key name
- persisted private key material where still present

That is one of the places where provider scaffolding becomes directly user-visible.

## Invariants And Guard Rails

- This package is `v1` compatibility surface, not the preferred handler model.
- `Identity` is the visible root of the older `v1` ownership graph.
- Deleting an identity uses foreground deletion so dependent resources remain
  coordinated beneath the visible parent.
- Provider selection and wiring are derived from the selected region during
  generation rather than trusted blindly from the caller.

## Caveats

- The handler is deprecated, but the resource concept may become relevant again
  in a cleaner future model.
- The handler still matters operationally for remaining deprecated `v1`
  Kubernetes flows because it is how those paths obtain cloud credentials and
  later trigger cleanup.
- The current `v2` network-to-service-principal mapping is effectively `1:1`.
  If project mapping became more explicit again, identity-like resources could
  simplify handling of project-scoped cloud artefacts such as uploaded images
  and snapshots.
- Exposing OpenStack convenience state here is operationally useful, but it also
  reflects transitional provider-state ownership that the wider system should
  continue shrinking over time.

## TODO

- Remove this handler surface when the remaining deprecated `v1` flows are gone.
- Revisit whether the underlying service-principal/project-scoping concept
  should later return as a cleaner explicit `v2` API object rather than staying
  implicit inside other resources.

## Cross-Package Context

- [../README.md](../README.md) documents why this handler is legacy rather than
  central to the future API model
- [../network](../network/README.md) documents the `v2` network flow that now
  creates service principals implicitly
- [../../apis/unikorn/v1alpha1](../../apis/unikorn/v1alpha1/README.md) documents
  the `Identity` and `OpenstackIdentity` storage contracts
