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
A third predicate, the level-based `RebuildSettled` (also exported by the
provisioner package), wakes the controller whenever the monitor's terminal
rebuild observation (`Status.Rebuild.State` `Succeeded`/`Failed`) awaits its
settlement pass.

A fourth, `serverObservedUpdate`, wakes the controller whenever the monitor's
`status.observed` region moves. It is the wake half of the reader/writer partition
described in
[`pkg/apis/unikorn/v1alpha1`](../../apis/unikorn/v1alpha1/README.md): the
reconciler sleeps until a provider fact actually changed instead of requeueing to
re-read one. It supersedes `RebuildSettled`, which is retained only until rebuild
actuation moves onto the region.

Unlike its siblings it compares the whole subtree instead of detecting a
field-specific edge. A predicate sees only the old and new objects, never the patch
that produced them, so an arm without a comparison would return true for every
update — the reconciler's own status writes included. Comparing makes it inert for
the writes that carry the region back unchanged, and a monitor write that races one
loses on `resourceVersion` rather than reverting it. The whole-subtree form means
facts added to the region later wake the reconciler with no edit here. What makes
that safe is not a single writer — the reconciler's create-retry path reaches the
same projection through `UpdateServerState`, so it can move the region itself — but
that a self-wake converges: the next pass writes the same value and the arm falls
quiet. The sibling arms are narrow because they guard conditions, which both writers
share. The comparison uses
semantic rather than reflect equality because the region carries a `*metav1.Time`,
and two decodings of one instant must not read as a change.

The "pre-launch" test is the shared `ProviderCreateFailure` predicate exported by
[`pkg/provisioners/managers/server`](../../provisioners/managers/server/README.md),
reused here verbatim so the watch trigger and the provisioner action are decided
by the same code. It blocks the rebuild for any server that has ever been
provisioned — authoritatively via the write-once `status.provisionedAt` latch,
with `launchedAt` and the `Active` condition as backstops — so a healthy, data-bearing server that
later errors never re-arms delete-and-retry.
