# `pkg/provisioners`

This tree contains the controller-side provisioning logic for region resources.

At a high level, the split is:

- `pkg/managers/*`: controller factories and watch registration
- `pkg/provisioners/managers/*`: per-resource reconcile/provision/deprovision logic
- `pkg/provisioners/internal/base`: shared helpers for resolving providers and
  identities from region resources

The overall pattern is conventional across resources:

1. a manager watches one CRD
2. the reconciler constructs one provisioner
3. the provisioner resolves any prerequisite identity/provider context
4. it calls the provider or performs controller-side cleanup/augmentation

This layer is where the platform lifecycle DAG becomes controller behaviour.
Handlers create or mutate roots and references; provisioners turn that desired
state into provider-side effects and edge maintenance.

The main deviations from a trivial “call provider create/delete” model are:

- some provisioners must wait for a parent/service-principal identity to be ready
- some maintain cross-resource reference edges explicitly
- some release or reconcile identity-side quota allocations on deprovision
- some augment provider create options, especially for server cloud-init / SSH CA integration

## Deprovisioning Partial State

Provisioners must handle deletion from any state a handler or earlier reconcile
step can leave behind. Teardown should split provider cleanup, reference
cleanup, and quota/accounting cleanup into separate idempotent steps. Gate each
step on the minimum recorded state it needs rather than on a broad prerequisite
such as parent identity readiness.

This matters for partially created resources: an allocation or reference may
already exist even when the provider resource was never created. Waiting for
provider prerequisites in that window can block cleanup of the side effects that
do exist. When a lifecycle edge is subtle, keep the predicate named after the
state it actually observes and document the partial-state window next to that
predicate.

## Cross-Package Context

- [../managers](../managers/README.md) wraps these provisioners in controller factories
- [../handler](../handler/README.md) documents the API-layer creation of many of
  the roots and reference edges provisioners later realize
- [../providers](../providers/README.md) documents the provider contract this
  layer drives
