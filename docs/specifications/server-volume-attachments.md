# Server-Volume Attachment Specification

Status: Proposed

Target: Region service v2

Decision record: [ADR 0002](../adr/0002-controller-managed-server-volume-attachments-without-a-crd.md)

## Purpose

This specification defines attachment of an existing `Volume` to a `Server`.
It supports one Server per Volume. It creates no attachment CRD.

The dedicated attachment controller reconciles existing Server and Volume
resources. All provider operations are asynchronous and idempotent.

## Model

| Fact | Authority | Derived representation |
|---|---|---|
| Attachment intent | `Server.spec.volumes` | `Server.status.volumes` |
| Selected Server | `Volume.spec.claimRef` | Attachment reconciliation |
| Provider relationship | Fresh Cinder observation | `Server.status.volumes` |
| Guest device | Fresh Cinder observation | `Server.status.volumes[].device` |

`Server.spec.volumes` is the complete desired Volume set. Each row names an
existing Volume ID. There are no imperative attach or detach endpoints.

`Volume.spec.claimRef` is the singleton reservation. Its supported kind is
`Server`. A nil claim permits claim acquisition. A claim permits provider
mutation but does not prove provider attachment.

`Server.status.volumes` is keyed by Volume ID. The attachment controller
exclusively owns these rows. Other Server status writers preserve the field.
Status never authorizes provider mutation, claim release, or finalizer removal.

## Controller

The attachment controller runs in its own binary, Deployment, service account,
and controller factory. Its work item is `(namespace, volumeID)`. The Volume ID
is the single-attach serialization key.

It watches:

- Servers whose `spec.volumes` contains the Volume ID.
- Volumes whose lifecycle, claim, pause, or deletion state changes.
- Its required requeues while Cinder reports a provider transition.

The controller filters its own `Server.status.volumes` writes. It does not
create an attachment object or use a separate attachment monitor checker.

## Attach

1. The existing Server handler validates and persists attachment intent. It
   does not claim the Volume or call a provider.
2. The controller lists every Server that expresses intent for the Volume.
   It validates endpoint existence, tenancy scope, deletion state, Flavor and
   VolumeClass compatibility, and current Server intent.
3. The controller retains a Volume finalizer while any valid Server expresses
   attachment intent. This prevents Volume deletion from passing unresolved
   attachment work.
4. If the Volume claim is nil, an eligible Server patches it with optimistic
   locking. The first successful patch wins.
5. A losing Server receives an `Errored` row with a safe claim-conflict
   message. It makes no provider call and waits for a claim or intent change.
6. Before a provider mutation, the controller persists and reads back the
   selected claim, the Volume finalizer, and a controller finalizer on the
   selected Server.
7. A new provider attach waits for `Volume Available=True` with reason
   `Provisioned`. It also waits while either endpoint is paused. Server attach
   eligibility comes from a fresh provider read, not from a Server condition.
8. The controller reads Cinder before it calls Nova. If Cinder already reports
   exactly one attachment to the selected Server, the controller projects
   `Provisioned` and the device to the Server status row.
9. Otherwise, the controller asks Nova to attach. It re-observes Cinder until
   the intended relationship is present. Nova acceptance is not convergence.

If Cinder reports a foreign attachment, multiple attachments, or an orphaned
attachment, the controller reports `Errored`. It retains the claim and
finalizers. It never attaches, detaches, force-detaches, or repairs that
relationship automatically.

## Detach and deletion

Removing a Volume from `Server.spec.volumes` is accepted immediately. Provider
cleanup is asynchronous. Server deletion also starts cleanup, but never deletes
the Volume.

1. The controller retains the selected claim and both endpoint finalizers.
2. It reads Cinder. If the intended relationship remains, it asks Nova to
   detach and reads Cinder again.
3. It retains all safeguards until Cinder reports no relationship for the
   selected Server.
4. After Cinder confirms absence, it clears the Server status row, releases the
   claim only when it still names the selected Server, and removes the Server
   finalizer.
5. It removes the Volume finalizer only when no Server expresses attachment
   intent for that Volume.

Cleanup ignores pause and Server readiness. A late attachment after intent
removal is detached before cleanup completes. If Cinder still reports an
attachment after its Server no longer exists, the controller reports an
orphaned attachment and requires operator recovery.

To recover a foreign or orphaned relationship, an operator corrects provider
state and changes Server attachment intent. No force-reconcile field,
annotation, or internal attachment CRUD exists.

## Conditions and status

The existing Volume controller owns `Volume.status.conditions`. The attachment
controller reads only `Available=True/Provisioned` as the attach-readiness
gate. It treats `Provisioning` as a wait state and a terminal Volume error as a
safe attachment error.

The attachment controller writes the corresponding `Server.status.volumes` row:

| State | `provisioningStatus` |
|---|---|
| Waiting for claim, endpoint, readiness, or provider convergence | `Provisioning` |
| Cinder confirms the selected relationship | `Provisioned` |
| Claim conflict, invalid intent, terminal endpoint error, foreign, multiple, or orphaned relationship | `Errored` |
| Intent removed or endpoint deleting while detach is incomplete | `Deprovisioning` |

Messages are safe and actionable. Raw provider details remain in structured
logs. The observed device is informational and never authorizes cleanup.

## Provider requirements

Cinder is the attachment authority. It reports attachment count and Server ID,
including after Nova no longer exposes a Server. Nova initiates attach and
detach and supplies Server eligibility.

The provider must re-observe Cinder after an accepted operation. It must not
issue a duplicate attach when Cinder already reports the intended relationship
or a transition. Independent Volumes use `delete_on_termination=false`.

## API behavior

The existing Server create and update handler preflights each Volume ID:

- The caller can read the Volume.
- The Volume exists and is not deleting.
- The Server and Volume share tenancy and provider scope.
- The VolumeClass supports the Server Flavor.
- A visible claim is nil or names the same Server.

The handler returns `404` for a missing or inaccessible Volume, `422` for
scope or Flavor incompatibility, and `409` for a conflicting claim or write
conflict. Controller validation remains authoritative because handler checks
can race and internal writers can bypass the handler.

## Verification

The minimum verification boundary is:

- Handler validation tests.
- Controller state-table and lifecycle tests.
- Provider idempotency tests for attach and detach.
- One integration lifecycle that attaches then detaches an existing Volume.

The initial release excludes multiattach, boot volumes, configurable
`delete_on_termination`, force detach, public attachment APIs, fair request
ordering, durable attachment history, automatic provider drift repair, and
atomic Volume moves between Servers.
