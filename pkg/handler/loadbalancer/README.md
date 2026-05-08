# Load Balancer

## Purpose

`pkg/handler/loadbalancer` handles `v2` load balancers.

This package is mostly about three things:

- linkage to a parent network
- quota/allocation coordination
- stronger semantic validation than many other handlers

So although it follows the common `v2` model, it is one of the more
domain-specific resource handlers.

## Distinctive Behaviour

- load balancers are network-linked and inherit region/project context from the
  selected network
- create and update both use sagas so allocation changes and resource mutation
  can be compensated on failure
- listener, pool, and member shapes are validated aggressively:
  - DNS-label listener names
  - protocol restrictions
  - port ranges
  - member uniqueness
  - health-check constraints
- requested VIP validation is tied to the selected network's prefix

## Invariants And Guard Rails

- `LoadBalancer v2` resources are labeled with `ResourceAPIVersionLabel=2`, and
  direct object access is gated accordingly.
- A load balancer must belong to an authorized network in the same project.
- Quota allocation and resource mutation should move together as far as the saga
  model can make them move together.
- Deletion is straightforward ownership/lifecycle teardown and does not use the
  extra reference model that some other resources do.

## Caveats

- This package carries more domain validation than many sibling handlers.
- The saga pattern improves consistency, but create/update still remain
  best-effort multi-step workflows rather than true transactions.

## Cross-Package Context

- [../network](../network/README.md) documents the parent linkage model
- [core/pkg/server/saga](https://github.com/nscaledev/uni-core/blob/main/pkg/server/saga/README.md)
  documents the compensating-workflow machinery used here
