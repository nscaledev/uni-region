# Volume

This package is the controller factory for `Volume` reconciliation.

It registers a watch for Region `Volume` generation changes, loads the Region
scheme and provider registry, and delegates lifecycle behavior to
[`pkg/provisioners/managers/volume`](../../provisioners/managers/volume/README.md).
The shared core reconciler owns finalizer and lifecycle-condition handling. A
provider yield schedules fixed-delay polling and retains
`Available=False/Provisioning`; provider success marks the Volume provisioned,
while a typed terminal provider error records its safe `Available=False`
reason/message without continued polling. Kubernetes increments generation when
marking a resource for deletion, so the generation predicate also enqueues
deprovisioning.

`VolumeStatus.ProvisionedAt` records the first successful discovery of backing
storage. Later generation events continue reconciliation, but a missing
backing volume is never recreated under the same Region Volume ID. Provider loss
is reported through `Healthy` by the pass that observed it.

## Polling

The controller polls. Cinder moves a volume underneath us — size, attachment
state, and the `error` family — and none of that writes to the CRD, so no watch
can fire for it. Each pass observes from its own fresh read; there is no separate
observer.

Only a settled `available` volume reaches the success branch that requeues on the
poll period. Anything else yields, which requeues faster, and a terminal
disposition parks with no requeue at all — so a volume whose create failed, or
whose backing storage has gone, waits for a replacement rather than being
re-read. A bare Cinder `error` is that terminal case; the `error_*` sub-states
are a failed operation on a volume that still exists and can clear on its own, so
they yield instead. See
[`pkg/providers/internal/openstack`](../../providers/internal/openstack/README.md).
