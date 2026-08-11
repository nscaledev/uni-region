# Volume

`pkg/provisioners/managers/volume` owns controller-side create/delete lifecycle
for Region `Volume` resources.

Provisioning resolves the full cloud provider and backing service-principal
`Identity`, waits for that Identity to be ready, then delegates idempotent
Volume creation. Provider `ErrYield` results keep the Volume
`Available=False` with reason `Provisioning` and schedule another reconcile;
only provider convergence allows `Provisioned`. A typed terminal provider
failure is surfaced as the provider's safe reason/message and parked until
deletion or operator intervention. This package does not check quota or
create/promote an Identity allocation; admission and allocation creation belong
to the HTTP create handler.

Deprovisioning deliberately has stricter ordering:

1. resolve the provider and Identity through the shared provisioner lookup, then
   call provider deletion without consulting Identity readiness or best-effort
   Volume status;
2. retain the finalizer while an accepted asynchronous provider deletion
   yields, and only after rediscovery confirms the provider resource is absent,
   delete the Identity allocation named by the allocation annotation;
3. return any provider or allocation error so the generic reconciler retains
   the finalizer and retries.

Missing allocation metadata is a successful no-op, as is an allocation already
absent from Identity. A retry repeats provider deletion before allocation
cleanup; provider deletion is idempotent by contract. Finalizer ordering keeps
the referenced Region `Identity` available through this cleanup; a missing
Identity remains an error and preserves the Volume finalizer.
Provider lookup errors also preserve the allocation and finalizer for retry.

General provider observation/status mapping, quota admission, Network
graph-edge reconciliation, HTTP handlers, and server attachment reconciliation
are outside this package. The provider-specific state classification needed to
decide whether create has converged remains inside the provider implementation.

## Cross-Package Context

- [../../../providers](../../../providers/README.md) defines provider lookup and
  the lifecycle contract
- [../../../providers/internal/openstack](../../../providers/internal/openstack/README.md)
  implements Cinder rediscovery, creation, and deletion
- [../../../managers/volume](../../../managers/volume/README.md) wires this
  provisioner into the controller runtime
