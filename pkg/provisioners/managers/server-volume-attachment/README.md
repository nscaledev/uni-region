# `server-volume-attachment`

This provisioner realizes one claimed Server–Volume relationship. Before an
attach it writes and rereads the attachment finalizer and endpoint references;
on deletion it detaches before removing those references.

It projects confirmed attachment state into the matching
`Server.status.volumes` row. `Volume.spec.claimRef` is owned by the separate
Volume-keyed coordinator and is only a gate here.
