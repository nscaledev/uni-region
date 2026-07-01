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
cleanup, and quota/accounting cleanup into separate idempotent steps that each
run unconditionally.

Crucially, a delete step must never be gated on a readiness condition or on
best-effort recorded status (for example provider resource IDs written to
`Status`). Status is non-authoritative and can lag or be lost, so gating on it
skips a cleanup that is genuinely required and leaks the resource. Instead, make
each step idempotent and push tolerance for partial state down to where the
authoritative truth lives: the provider rediscovers its resources by name and
no-ops when the parent identity was never realized (see
[providers](../providers/README.md)). Finalizer ordering guarantees the parent
identity outlives its consumers, so at delete time it is either
realized-and-complete or never realized — in both cases an unconditional,
idempotent delete is correct.

This matters for partially created resources: an allocation or reference may
already exist even when the provider resource was never created. The provider
delete simply finds nothing to do; the allocation/reference cleanup still runs.

## Cross-Package Context

- [../managers](../managers/README.md) wraps these provisioners in controller factories
- [../handler](../handler/README.md) documents the API-layer creation of many of
  the roots and reference edges provisioners later realize
- [../providers](../providers/README.md) documents the provider contract this
  layer drives
