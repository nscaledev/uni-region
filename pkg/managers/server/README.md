# Server

This package is the controller factory for `Server` reconciliation.

It is structurally standard, but it fronts the richest provisioner in the tree:
[`pkg/provisioners/managers/server`](../../provisioners/managers/server/README.md),
which maintains explicit resource-reference edges and SSH CA cloud-init
augmentation.

The watch is slightly broader than the other resource managers: besides server
spec generation changes, it also wakes the controller when the monitor first
observes a pre-launch provider server in `Healthy/Errored`. That status edge is
the trigger for bounded delete-and-retry handling in the server provisioner.

The rebuild feature (a third watch predicate waking the controller from a
monitor-recorded terminal rebuild observation) is excised pending
re-implementation from the machine-checked spec at
[`docs/superpowers/specs/2026-07-31-server-rebuild-protocol-design.md`](../../../docs/superpowers/specs/2026-07-31-server-rebuild-protocol-design.md).

The "pre-launch" test is the shared `ProviderCreateFailure` predicate exported by
[`pkg/provisioners/managers/server`](../../provisioners/managers/server/README.md),
reused here verbatim so the watch trigger and the provisioner action are decided
by the same code. It blocks the rebuild for any server that has ever been
provisioned — authoritatively via the write-once `status.provisionedAt` latch,
with `launchedAt` and the `Active` condition as backstops — so a healthy, data-bearing server that
later errors never re-arms delete-and-retry.
