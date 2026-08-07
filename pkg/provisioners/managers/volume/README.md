# Volume

`pkg/provisioners/managers/volume` owns controller-side create/delete lifecycle
for Region `Volume` resources.

Provisioning resolves the focused provider `Volume` capability and the backing
service-principal `Identity`, waits for that Identity to be ready, then delegates
idempotent provider creation. It does not check quota or create/promote an
Identity allocation; admission and allocation creation belong to the HTTP create
handler.

Deprovisioning deliberately has stricter ordering:

1. call provider deletion unconditionally, without consulting Identity
   readiness or best-effort Volume status;
2. only after provider deletion succeeds or converges with an already-absent
   provider resource, delete the Identity allocation named by the allocation
   annotation;
3. return any provider or allocation error so the generic reconciler retains
   the finalizer and retries.

Missing allocation metadata is a successful no-op, as is an allocation already
absent from Identity. A retry repeats provider deletion before allocation
cleanup; provider deletion is idempotent by contract. If the referenced Region
`Identity` is already absent despite finalizer ordering, deletion still passes
its stable namespace/name to the provider so absence can converge before the
allocation is released from Volume metadata.

If provider lookup reports `ErrRegionWrongKind`, the focused Volume capability
is absent and therefore could not have created provider state. Deprovisioning
treats that case as already absent and continues annotated allocation cleanup so
the finalizer can converge. Missing regions and other provider lookup failures
remain errors: they preserve the allocation and finalizer for retry rather than
assuming cleanup is safe.

Provider observation/status mapping, quota admission, Network graph-edge
reconciliation, HTTP handlers, and server attachment reconciliation are outside
this package.

## Cross-Package Context

- [../../../providers](../../../providers/README.md) defines capability lookup
  and the provider lifecycle contract
- [../../../providers/internal/openstack](../../../providers/internal/openstack/README.md)
  implements Cinder rediscovery, creation, and deletion
- [../../../managers/volume](../../../managers/volume/README.md) wires this
  provisioner into the controller runtime
