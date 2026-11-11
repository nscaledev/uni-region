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
detachment. The provisioner reads the Volume claim created by the Server handler
and the Server intent, then calls the provider attachment boundary. A
provisioning or errored Server yields; its condition can recover without a
Volume generation change.
Claims are created before the terminal Server write. While `AttachedAt` is nil,
the provisioner retains a claim if the Server is absent or does not yet request
the Volume. This wait lets the handler persist attachment intent or complete
saga compensation.

This coordination does not record which request owns a claim. Concurrent
updates for the same Server can both treat a same-Server claim as their own. A
losing update can then clear the claim that the winning update needs. During a
multi-Volume claim, failed rollback can also leave claims without Server intent.
The controller cannot distinguish these orphaned claims from claims that await
the terminal Server write. It leaves the Volume in the provisioning state until
an operator repairs the claim. This behavior is an accepted limitation until
claim records include durable ownership or phase.
Before provider attachment, the Volume controller uses the core reference
helpers to place its canonical per-Volume reference on the Server. During Server
deletion those references block Server deprovisioning, so each Volume actively
detaches from Nova and waits for Cinder convergence first. After provider
detachment, the controller removes only that Volume's Server reference before
releasing the claim. The same ordering applies when a live Server no longer
requests the Volume. Teardown does not require Identity readiness; provider
state is authoritative. A provider yield or error retains the claim, reference,
and recovery context.
An attachment conflict is projected as errored and retained for retry or
operator repair; it never authorizes detaching the conflicting attachment.
The provider remains authoritative for attachment and detach work. The
provisioner projects `AttachmentProvisioning` with a waiting message until the
claimed Cinder attachment `in-use`, then records the first confirmed current
attachment in `Volume.Status.AttachedAt`; it clears that timestamp after
confirmed detachment. It advances the Volume observed generation only when both
the backing Volume and attachment converge.
It does not project attachment status until the backing Volume has converged
and attachment reconciliation begins. Before an asynchronous detach, existing
attachment rows are marked `Deprovisioning`; they, the Server reference, and the
claim are removed only after the provider confirms detachment.
After releasing a claim, the provisioner yields so the refreshed Volume is
reconciled before its generation is observed.
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
