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

## Cross-Package Context

- [../managers](../managers/README.md) wraps these provisioners in controller factories
- [../handler](../handler/README.md) documents the API-layer creation of many of
  the roots and reference edges provisioners later realize
- [../providers](../providers/README.md) documents the provider contract this
  layer drives
