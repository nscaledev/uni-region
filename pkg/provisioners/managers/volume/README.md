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

1. resolve the provider and Identity through the shared provisioner lookup,
   then call provider deletion without consulting Identity readiness or
   derived status; the API rejects deletion of a claimed Volume, so attachment
   teardown has already completed;
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

Attachment setup starts only after the backing Volume converges. Teardown intent
is evaluated first so provider creation readiness cannot block claim release or
detachment. The provisioner reads the handler-owned Volume claim and Server
intent, then calls the provider attachment boundary. A provisioning or errored
Server yields; its condition can recover without a Volume generation change.
If the claimed Server is absent and `Volume.Status.AttachedAt` is unset, the
provisioner retains the claim and yields so Server creation can complete. A
recorded attachment means that a now-absent Server completed deletion, so only
Cinder convergence remains before claim release. When the Server is deleting,
the provider waits for Nova to delete it and does not request a competing Nova
detach; after Nova is absent it cleans stale Cinder state and waits for Cinder
convergence. When a live Server no longer requests the Volume, the full Server
remains available to the provider until it confirms Nova and Cinder teardown.
A provider yield or error retains the claim and its recovery context.
The provider remains authoritative for attachment and detach work. The
provisioner projects `AttachmentProvisioning` with a waiting message until the
claimed Cinder attachment `in-use`, then records the first confirmed current
attachment in `Volume.Status.AttachedAt`; it clears that timestamp after
confirmed detachment. It never uses either derived projection to decide
provider cleanup. It advances the Volume observed generation only when both
the backing Volume and attachment converge.
It does not project attachment status until the backing Volume has converged
and attachment reconciliation begins. Before an asynchronous detach, existing
attachment rows are marked `Deprovisioning`; they and the claim are removed only
after the provider confirms detachment.
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
