# Server

This package is the controller factory for `Server` reconciliation.

It is structurally standard, but it fronts the richest provisioner in the tree:
[`pkg/provisioners/managers/server`](../../provisioners/managers/server/README.md),
which maintains explicit resource-reference edges and SSH CA cloud-init
augmentation.

The watch is slightly broader than the other resource managers: besides server
spec generation changes, it also wakes the controller when a pre-launch provider
server is first seen in `Active/Errored`. That status edge is the trigger for
bounded delete-and-retry handling in the server provisioner, and it comes from
the reconcile pass's own projection, so a failed create is adopted on the next
pass rather than a poll later.

The controller **polls**. Nova moves a server underneath us — power state, health,
and the image reference on a rebuild — and none of that writes to the CRD, so no
watch can fire for it. That is what let `status.observed` and its wake predicate
go: the subtree existed only to give a predicate something to diff, and nothing
read its contents. See
[`pkg/provisioners/managers/server`](../../provisioners/managers/server/README.md)
for what the pass does with the read, and
[`pkg/providers/internal/openstack`](../../providers/internal/openstack/README.md)
for the projection itself.

A parked server is the exception: a terminal disposition has no requeue, by
design, so polling does not revive it. It waits for a spec edit, a replacement,
or a controller restart — the restart works because a polling controller never
stamps its processed generation.

The "pre-launch" test is the shared `ProviderCreateFailure` predicate exported by
[`pkg/provisioners/managers/server`](../../provisioners/managers/server/README.md),
reused here verbatim so the watch trigger and the provisioner action are decided
by the same code. It blocks the rebuild for any server that has ever been
provisioned — authoritatively via the write-once `status.provisionedAt` latch,
with `launchedAt` and the `Active` condition as backstops — so a healthy, data-bearing server that
later errors never re-arms delete-and-retry.
