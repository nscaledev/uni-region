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

A third, `serverObservedUpdate`, wakes the controller whenever the
`status.observed` region moves. It is the wake half of the reader/writer partition
described in
[`pkg/apis/unikorn/v1alpha1`](../../apis/unikorn/v1alpha1/README.md): the
reconciler sleeps until a provider fact actually changed instead of requeueing to
re-read one.

For every yielding state it is a latency optimisation, not a liveness dependency:
`ErrYield` requeues after `DefaultYieldTimeout`, so an in-flight rebuild is re-read
on a timer whether or not this arm ever fires; the arm only shortens the wait. For
a server parked by the provider's failed-rebuild row (a converged, quiesced
`ERROR` — see
[`pkg/providers/internal/openstack`](../../providers/internal/openstack/README.md)
— where no requeue exists), this arm *is* the liveness for observation-driven
recovery: a fault that clears at the provider un-parks the server only via this
wake, or via a spec edit's generation wake, which is monitor-independent.

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

On load: the arm fires on any observed-subtree delta, so a server flapping in and
out of `ERROR` drives one full reconcile per flip — and each woken pass also
mutates the provider, re-running port reconciliation (today an unconditional
Neutron `UpdatePort`, with a standing TODO in the openstack provider to make it
conditional) plus floating-IP reconciliation, so the deferral's cost is Neutron
write amplification, not just controller CPU. The unconditional `generation`
stamp guarantees one redundant wake per spec edit — the generation predicate
already woke the reconciler for that edit. If wake volume ever becomes a
problem, the knob is comparing only the fields a woken pass acts on (`image`,
`errored`); deferred until it is one.

The "pre-launch" test is the shared `ProviderCreateFailure` predicate exported by
[`pkg/provisioners/managers/server`](../../provisioners/managers/server/README.md),
reused here verbatim so the watch trigger and the provisioner action are decided
by the same code. It blocks the rebuild for any server that has ever been
provisioned — authoritatively via the write-once `status.provisionedAt` latch,
with `launchedAt` and the `Active` condition as backstops — so a healthy, data-bearing server that
later errors never re-arms delete-and-retry.
