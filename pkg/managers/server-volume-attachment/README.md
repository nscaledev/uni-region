# `server-volume-attachment`

This manager wraps the generic UNI reconciler for one
`ServerVolumeAttachment`. The generic reconciler owns its finalizer and
`Available` condition, which is why this controller is attachment-keyed rather
than Volume-keyed.

The provisioner verifies the coordinator's `Volume.spec.claimRef`, persists
endpoint references, then performs provider attach or detach.
