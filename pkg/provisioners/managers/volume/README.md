# Volume

`pkg/provisioners/managers/volume` owns controller-side create/delete lifecycle
for Region `Volume` resources.

Provisioning resolves the full cloud provider and backing service-principal
`Identity`, waits for that Identity to be ready, then delegates idempotent
Volume creation. Provider `ErrYield` results keep the Volume
`Available=False` with reason `Provisioning` and schedule another reconcile;
only provider convergence allows `Provisioned`. A typed terminal provider
failure is surfaced as the provider's safe reason/message and parked until
deletion or operator intervention. This package does not check quota; the HTTP
create handler allocates the requested capacity and stores the Identity
allocation ID before the controller can observe the Volume.

Provision passes always re-derive provider state. OpenStack uses the stable
provider name and idempotent create path, so an existing backing volume is
adopted. Before `VolumeStatus.ProvisionedAt` is set, a missing backing volume
is created under the same Region Volume ID. Afterward, confirmed provider loss
requires a replacement Volume; it is not recreated under the same ID.

Deprovisioning deliberately has stricter ordering:

1. resolve the provider and Identity through the shared provisioner lookup, then
   discover and detach provider attachments by Volume, then call provider
   deletion without consulting Identity readiness or derived status;
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

After the backing Volume converges, this provisioner reconciles its single
claimed Server attachment. It reads the handler-owned Volume claim and Server
intent, then calls the provider attachment boundary. A provisioning or errored
Server yields; its condition can recover without a Volume generation change.
If the claimed Server is absent, the provisioner detaches any old provider
attachments, retains the claim, and yields so Server creation can complete. If
the Server is deleting or no longer requests the Volume, it
conflict-safely releases that claim and yields. The following no-claim pass
detaches provider attachments and clears stale Server status.
The provider remains authoritative for attachment and detach work. The
provisioner projects progress only onto `Server.Status.Volumes`; it never uses
that derived projection to decide provider cleanup. It advances the Volume
observed generation only when both the backing Volume and attachment converge.
It does not project attachment status until the backing Volume has converged
and attachment reconciliation begins. Before an asynchronous detach, existing
attachment rows are marked `Deprovisioning`; they are removed only after the
provider confirms detachment.
Each projection re-reads the Server and retries status conflicts while merging
only the claimed Volume's entry.

Provider observation/status projection lives in
[`pkg/monitor/health/volume`](../../../monitor/health/volume/README.md). Quota
policy, Network graph-edge reconciliation, and HTTP handlers remain outside
this package. The provider-specific state classification needed to decide
whether create has converged remains inside the provider implementation.

## Cross-Package Context

- [../../../providers](../../../providers/README.md) defines provider lookup and
  the lifecycle contract
- [../../../providers/internal/openstack](../../../providers/internal/openstack/README.md)
  implements Cinder rediscovery, creation, and deletion
- [../../../managers/volume](../../../managers/volume/README.md) wires this
  provisioner into the controller runtime
