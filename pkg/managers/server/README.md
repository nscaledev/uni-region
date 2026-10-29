# Server

This package is the controller factory for `Server` reconciliation.

It is structurally standard, but it fronts the richest provisioner in the tree:
[`pkg/provisioners/managers/server`](../../provisioners/managers/server/README.md),
which maintains explicit resource-reference edges and SSH CA cloud-init
augmentation.

## Polling

Nova moves a server underneath us (power state, health, the image reference on a
rebuild) and none of that writes to the CRD, so no watch fires. The reconciler
polls: every pass reads the provider and projects the read onto status. Core
decides the next pass from the outcome:

- a plain yield retries in 10 seconds;
- everything else (success, recheck, terminal, user action required, an untyped
  error, a failed status write) waits for the poll slot. Nothing parks.

The region is the control plane. A change made by hand in the cloud is undone at
the next poll: a deleted VM is recreated, a rebuild onto another image is
reverted. Change the `Server`, never Nova.

`WithTransient(providers.Transient)` covers an outage. A failure with no
disposition that says OpenStack (or Kubernetes) could not be reached leaves the
`Available` condition as it was, saves the rest of status, and is logged at Info.
Without it, a short outage would turn every server `Errored`. The rule is
[`openstack.Transient`](../../providers/internal/openstack/README.md); any 5xx
counts, since a service that failed to answer says nothing about the server.
Failures with a disposition log at Info; any
other failure logs at Error on every pass.

## Watches

Besides spec generation changes, the watch wakes the controller when a
pre-launch provider server lands in `Healthy/Errored`. That status edge is the
trigger for bounded delete-and-retry in the server provisioner.

The "pre-launch" test is the shared `ProviderCreateFailure` predicate exported by
[`pkg/provisioners/managers/server`](../../provisioners/managers/server/README.md),
reused here verbatim so the watch trigger and the provisioner action are decided
by the same code. It blocks the rebuild for any server that has ever been
provisioned (authoritatively via the write-once `status.provisionedAt` latch,
with `launchedAt` and the `Active` condition as backstops), so a healthy,
data-bearing server that later errors never re-arms delete-and-retry.
