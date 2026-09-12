# Volume

This package is the controller factory for `Volume` reconciliation.

It registers watches for Region `Volume` generation changes and Server Volume
intent, loads the Region scheme and provider registry, and delegates lifecycle behavior to
[`pkg/provisioners/managers/volume`](../../provisioners/managers/volume/README.md).
The shared core reconciler owns finalizer and lifecycle-condition handling. A
provider yield schedules fixed-delay polling and retains
`Available=False/Provisioning`; provider success marks the Volume provisioned,
while a typed terminal provider error records its safe `Available=False`
reason/message without continued polling. Kubernetes increments generation when
marking a resource for deletion, so the generation predicate also enqueues
deprovisioning.

Create and update claim Volumes before their terminal Server write. A claim
generation change may therefore reconcile before the Server exists; the
provisioner recognizes that claim-before-create window and yields safely. The
subsequent Server create or spec change enqueues every Volume in both the old
and new attachment sets. A Server deletion transition also enqueues its
requested Volumes.

`VolumeStatus.ProvisionedAt` records the first successful discovery of backing
storage. Later generation events continue reconciliation, but a missing
backing volume is never recreated under the same Region Volume ID. The health
monitor reports provider loss separately through `Healthy`.
