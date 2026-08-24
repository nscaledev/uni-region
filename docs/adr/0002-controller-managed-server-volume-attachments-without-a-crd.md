---
status: proposed
---

# Reconcile server-volume attachments without a relationship CRD

Keep a dedicated controller, but do not create `ServerVolumeAttachment`.
`Server.spec.volumes` is desired attachment intent, `Volume.spec.claimRef` is
the single selected claim, and `Server.status.volumes` is the user-visible
projection. The controller reconciles each Volume directly from existing
Servers and Volumes; Cinder remains provider truth.

Before a provider mutation, the selected claim and a controller finalizer on
both Server and Volume must be persisted. The controller retains both
finalizers until Cinder confirms detachment. First successful optimistic claim
acquisition wins; a competing Server reports an errored status row and is
re-evaluated when the claim changes. Provider drift or an orphaned attachment
is recovered by correcting provider state and changing existing Server intent;
there is no attachment object, queue, fairness timestamp, force-reconcile
field, or separate monitor checker.

## Considered Options

`ServerVolumeAttachment` would preserve independent request history and enable
oldest-request arbitration, but duplicates durable state already represented by
Server intent, Volume claim, endpoint finalizers, and Server status. Those
capabilities are unnecessary for the initial single-attach model. Add a
relationship CRD only for multiattach, queued/fair arbitration, or durable
operator-facing attachment history.
