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

The "pre-launch" test is the shared `ProviderCreateFailure` predicate exported by
[`pkg/provisioners/managers/server`](../../provisioners/managers/server/README.md),
reused here verbatim so the watch trigger and the provisioner action are decided
by the same code. It blocks the delete-and-retry for any server that has ever been
provisioned — authoritatively via the write-once `status.provisionedAt` latch,
with `launchedAt` and the `Active` condition as backstops — so a healthy, data-bearing server that
later errors never re-arms delete-and-retry.

There is no third predicate for image rebuild. The watch here is otherwise
just `predicate.TypedGenerationChangedPredicate` — it fires only on a spec
edit (a `metadata.generation` bump), never on a status-only write. That is
deliberate for rebuild specifically: the provider's rebuild reconciliation
(see [`pkg/providers/internal/openstack/README.md`](../../providers/internal/openstack/README.md))
commits its acceptance record in a status write, on purpose, before it calls
the provider — and that write must **not** enqueue anything, or the ordering
it exists to protect would be moot. Liveness for an outstanding rebuild
attempt instead comes from the provisioner's own fixed-interval requeue
(`provisioners.ErrYield`), not from this watch. A parked attempt is the one
case with no requeue at all: its only exit is a new image selection, and a
new image selection is a spec edit, which this generation-changed predicate
already wakes the controller for — a second wake mechanism for the same
event would be redundant.
