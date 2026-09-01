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
backing volume is never recreated under the same Region Volume ID. The health
monitor reports provider loss separately through `Healthy`.
