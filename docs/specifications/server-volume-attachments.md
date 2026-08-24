# Server–Volume Attachment Specification

Status: Proposed

Target: Region service v2

Decision record: [ADR 0001](../adr/0001-controller-managed-server-volume-attachments.md)

## 1. Purpose

This specification defines how Region attaches an existing `Volume` to a
`Server`. The design follows the Kubernetes separation between workload intent,
binding and provider attachment without introducing a separate claim resource:

- `Server.spec.volumes` is attachment intent.
- `Volume.spec.claimRef` is the exclusive selected binding.
- `ServerVolumeAttachment` is the controller-managed lifecycle relationship.
- Cinder is authoritative for the provider attachment.

The feature supports one Server per Volume. All operations are asynchronous and
idempotent.

## 2. Goals

- Attach and detach existing Region Volumes without adding attachment work to
  the Server or Volume lifecycle controllers.
- Prevent two Servers from attaching the same Volume.
- Preserve Volumes when Servers are deleted.
- Make crashes and duplicate reconcile events safe.
- Confirm provider convergence through fresh observation rather than recorded
  status or successful request submission.
- Expose attachment progress through the existing Server API.
- Detect provider drift through the existing Region monitor process.

## 3. Non-goals

The first release does not support:

- multiattach.
- boot volumes.
- inline Volume creation from a Server request.
- configurable `delete_on_termination`.
- force detach.
- public CRUD for attachment resources.
- atomic moves between Servers.
- attachment-specific metrics or Kubernetes Events.

## 4. Sources of truth

| Fact | Authority | Derived representation |
|---|---|---|
| Desired attachments | `Server.spec.volumes` | Materialized attachments |
| Selected Server | `Volume.spec.claimRef` | Attachment and Server status |
| Provider relationship | Fresh Cinder observation | `Attached`, `Available`, device and Server status |
| Server attach eligibility | Fresh provider observation | Condition message and requeue decision |
| Guest device | Fresh provider observation | Attachment status and `Server.status.volumes` |

Status must never authorize provider mutation, detach, claim release, reference
release or finalizer removal.

## 5. Resource model

### 5.1 Existing Server intent

`Server.spec.volumes` remains the complete desired set. Each entry contains an
existing Volume ID and is keyed by that ID. There are no imperative attach or
detach endpoints.

### 5.2 Existing Volume claim

`Volume.spec.claimRef` remains the singleton reservation. Its supported kind is
`Server`, and its ID is the selected Server ID. A nil claim means that the
Volume is available for arbitration. A claim reserves provider mutation. It is
not evidence that attachment has completed.

### 5.3 ServerVolumeAttachment

`ServerVolumeAttachment` is a namespaced, controller-managed Region CRD. It is
not exposed through the Region REST API.

Conceptual schema:

```yaml
apiVersion: region.unikorn-cloud.org/v1alpha1
kind: ServerVolumeAttachment
metadata:
  name: <deterministic UUIDv5>
  ownerReferences:
    - kind: Server
      name: <server ID>
      controller: true
spec:
  serverID: <server ID>
  volumeID: <volume ID>
status:
  observedGeneration: 1
  conditions:
    - type: Available
      status: "False"
      reason: Provisioning
      message: Waiting for the Volume to become attachable.
      observedGeneration: 1
    - type: Attached
      status: "False"
      reason: Detached
      message: Cinder reports no attachment.
      observedGeneration: 1
  device: /dev/vdb
```

`spec.serverID` and `spec.volumeID` are required and immutable. Status contains
only `observedGeneration`, conditions and the optional provider-observed
`device`. It contains no phase, provider attachment ID, duplicate Server ID or
selection boolean.

The name is generated with `GenerateDeterministicResourceID` using a dedicated
resource namespace UUID and an unambiguous `(serverID, volumeID)` invariant.
Recreating the same pair therefore produces the same name.

The controller does not write labels. Controller-runtime cache field indexes on
`spec.serverID` and `spec.volumeID`, plus an index on
`Server.spec.volumes[].id`, provide lookup. Tenancy is derived from the Server
and Volume and validated on every reconciliation pass.

### 5.4 Conditions

The attachment controller owns the lifecycle `Available` condition:

| State | Status | Reason |
|---|---|---|
| Waiting, claiming or attaching | `False` or `Unknown` | `Provisioning` |
| Cinder confirms the intended attachment | `True` | `Provisioned` |
| Invalid or operator-action-required state | `False` | `Errored` |
| Deleting or detaching | `False` | `Deprovisioning` |

Messages distinguish actionable details such as a conflicting claim, missing
endpoint, incompatible Flavor, foreign attachment, unexpected multiattach or
orphaned attachment. Messages must be safe for an authenticated user. Raw
provider errors remain in structured logs.

The dedicated attachment monitor checker owns the observational `Attached`
condition:

| Provider observation | Status | Reason |
|---|---|---|
| Exactly one attachment to the intended Server | `True` | `Attached` |
| No attachment | `False` | `Detached` |
| Provider operation still transitioning | `Unknown` | `Transitioning` |
| Attached to another Server | `False` | `ForeignAttachment` |
| More than one attachment | `False` | `UnexpectedMultiattach` |
| Server missing while an attachment remains | `False` | `OrphanedAttachment` |
| Provider observation error | `Unknown` | `ObservationFailed` |

`Attached` is a wake signal and status projection only. The attachment
controller must re-read Cinder before every provider mutation or destructive
decision.

The controller can populate `device` from the observation that first confirms
convergence. The monitor owns its ongoing refresh. It is cleared after confirmed
absence and preserved when observation fails. It is informational.

## 6. Resource graph and deletion ordering

The Server is the Kubernetes controller owner of the attachment. The Volume is not
an owner because Volume deletion must remain blocked while Server intent exists.

Before provider mutation, the attachment controller must durably establish and
read back:

1. The attachment object.
2. The attachment cleanup finalizer.
3. The selected Volume claim.
4. The canonical blocking reference of the attachment on the Server.
5. The same blocking reference on the Volume.

References use `GenerateResourceReference` and are placed and released only by
the attachment controller.

Server deletion initiates attachment deletion. The Server reference prevents
Nova deletion until Cinder confirms detach. Deleting a Server never deletes its
Volumes.

Explicit Volume deletion remains blocked while a Server still lists the Volume.
The caller must remove that intent first. Detach then completes, the claim and
references are released, and normal Volume deletion can continue.

Independent Volumes always use `delete_on_termination=false` when attached.

## 7. Public API behavior

### 7.1 Adding a Volume

The existing Server create or update handler validates every supplied Volume ID
before persisting intent:

- the caller can read the Volume.
- the Volume exists and is not deleting.
- the Volume and Server share organization, project, Region and provider
  identity scope.
- the selected VolumeClass supports the Server Flavor.
- any visible existing claim is nil or already names this Server.

Use existing Region error conventions:

- inaccessible or absent resource: `404`.
- co-location or Flavor incompatibility: `422`.
- incompatible existing claim or lifecycle/write conflict: `409`.

The handler performs no provider operation and writes no Volume claim,
attachment, reference or provider status. It persists only the complete Server
intent and returns asynchronously. Controller validation remains authoritative
because handler validation is subject to races and can be bypassed by internal
storage writers.

### 7.2 Removing a Volume

Removing a Volume from the desired set is always allowed after normal update
authorization and optimistic-lock checks. The handler does not require an
attach-eligible Server state and does not wait for Cinder. Cleanup is
asynchronous.

## 8. Controller architecture

The attachment controller has its own binary, deployment, service account and
factory. It is not part of the existing Server or Volume controller.

The work item of the controller is `(namespace, volumeID)`. The Volume ID is the
single-attach serialization key. The controller manages only
`ServerVolumeAttachment` relationships, although events from their endpoints
produce the work items.

### 8.1 Cache indexes

Register indexes for:

- Servers by each `spec.volumes[].id`.
- attachments by `spec.volumeID`.
- attachments by `spec.serverID`.

### 8.2 Watches

| Source | Enqueued Volume IDs |
|---|---|
| Server create | All desired Volume IDs |
| Server update | Union of old and new desired Volume IDs |
| Server deletion | All desired Volume IDs |
| Relevant Server readiness/lifecycle change | All desired Volume IDs |
| Volume create, generation, deletion, claim or availability change | Its ID |
| Attachment create, generation or deletion | `spec.volumeID` |
| Monitor-owned `Attached` change | `spec.volumeID` |

Filter attachment controller-owned status updates and
`Server.status.volumes` projections so they do not create self-triggered loops.
Informer startup add events reconstruct the complete work set after restart.

### 8.3 Work-item reconciliation

For one Volume ID, reconciliation performs these steps:

1. List all Servers that currently request the Volume.
2. List all existing attachments for the Volume.
3. Create each missing deterministic pair attachment, even if the Volume is
   currently missing or invalid. This preserves request age and durable error
   status.
4. Delete attachments that no longer match Server intent or whose Server is
   deleting.
5. Validate endpoint identity, scope, deletion state, Flavor compatibility,
   deterministic name and Server owner reference.
6. Repair a stale claim by reconstructing its deterministic attachment as a
   protected cleanup record when necessary.
7. Select or preserve the claim winner.
8. Reconcile the lifecycle and Server status projection of every pair.

A directly created attachment is adopted only when its immutable pair,
deterministic name, owner and current Server intent all match. Otherwise it is
deleted through normal cleanup and must never authorize provider attach.

## 9. Claim arbitration

An existing valid claim always wins. Otherwise, candidates must have existing,
same-scope and Flavor-compatible endpoints, but they need not yet be provider
ready. Choose the oldest attachment `creationTimestamp`. Use the attachment name as
the deterministic tie-breaker.

Patch `Volume.spec.claimRef` with optimistic locking. A conflict returns
`ErrYield`. The next pass re-reads all candidates. Controller replicas require
no distributed lock.

Only the attachment whose Server matches the persisted claim can mutate
provider state. Losing attachments remain durable and project an errored Server
volume row with a safe claim-conflict message. They do not poll. Claim and
attachment events wake them when selection can change.

`creationTimestamp` reflects materialization order rather than the exact Server
update time. No per-intent timestamp is added.

## 10. Provider contract

The provider interface retains idempotent `AttachVolume` and `DetachVolume` and
adds one read-only, provider-neutral observation operation used by the
controller and monitor. Its result must distinguish:

- detached.
- attached to the intended Server, with optional device.
- transitioning.
- attached to another Server.
- multiple attachments.
- an attachment remaining when the intended provider Server cannot be found.

Concrete Cinder attachment IDs and OpenStack SDK types must not escape the
OpenStack provider.

OpenStack owns Nova-specific eligibility. It maps provider state into the
existing provisioning error vocabulary:

- allowed: perform or continue attachment.
- temporarily blocked: `ErrYield`.
- action required: park with a safe error.
- unexpected provider failure: follow normal provisioning/deprovisioning error
  handling.

The generic controller must not encode Nova states. OpenStack can permit attach
for states such as `ACTIVE`, `SHUTOFF`, `PAUSED`, `SUSPENDED` and
`VERIFY_RESIZE`, while classifying transitional states separately from locked,
shelved or errored states.

### 10.1 Observation-before-action

Before every attach:

1. Observe Cinder.
2. If the intended relationship already exists, return it as converged.
3. If the Volume is transitioning, yield without another Nova call.
4. If no relationship exists and the Server is eligible, call Nova attach and
   yield.
5. On a later pass, return success only when Cinder confirms the relationship.

Before every detach:

1. Observe Cinder regardless of recorded status or endpoint readiness.
2. If no relationship exists, return success.
3. If the intended relationship exists, call Nova detach idempotently and
   yield.
4. Return success only when Cinder confirms absence.

Nova request acceptance is never convergence.

## 11. Provider-state safety matrix

| Intent | Fresh Cinder observation | Action |
|---|---|---|
| Present | Intended attachment | Mark lifecycle available and do not re-check attach gates |
| Present | Absent | Attach only when claim and all write-ahead guards are durable |
| Present | Transitioning | Yield at the fixed interval |
| Present | Foreign attachment | Error, retain claim/references and never detach |
| Present | Multiple attachments | Error, retain claim/references and never repair |
| Removed/deleting | Intended attachment | Detach and retain every safeguard |
| Removed/deleting | Absent | Complete ordered cleanup |
| Removed/deleting | Foreign or multiple | Error and retain safeguards for an operator |
| Any | Server absent and Cinder attachment remains | Report orphaned and never force detach |

If intent is removed while attach is in flight, deletion wins. A late attachment
is detached before cleanup completes. If intent is re-added while the old pair
is deleting, deletion completes and the deterministic pair is recreated.

Later Server lifecycle or Volume health changes do not detach a relationship
that Cinder still confirms. Only removed intent or endpoint deletion starts
cleanup.

## 12. Deprovisioning

Deletion checks provider truth unconditionally and ignores endpoint pause and
attach eligibility. The attachment finalizer remains until absence is
confirmed.

After confirmed absence, cleanup proceeds in this order:

1. Release `Volume.spec.claimRef` only if it still names this Server.
2. Remove the attachment reference from the Volume.
3. Remove the attachment reference from the Server.
4. Remove the corresponding `Server.status.volumes` row.
5. Remove the attachment finalizer.

Every step is idempotent and conflict-retried. The claim is never released
before provider absence is known.

If the claimed Server is absent but Cinder still reports an attachment, retain
all safeguards and require operator recovery. After correcting provider state,
the operator deletes the attachment. Its finalizer confirms absence. Remaining
Server intent recreates the pair if needed. There is no force-reconcile field.

## 13. Server status projection

The attachment controller exclusively owns `Server.status.volumes`. Other
Server status writers preserve it. Projection uses a fresh Server read and an
optimistic status patch.

| Attachment state | `Server.status.volumes[].provisioningStatus` |
|---|---|
| Waiting, claiming, attaching | `Provisioning` |
| `Available=True/Provisioned` | `Provisioned` |
| Attachment deleting | `Deprovisioning` |
| Invalid, conflicting, foreign, multiple or orphaned | `Errored` |

The row is keyed by Volume ID. It carries the optional observed device and a
safe message. Attachment state does not change the overall `Available`
condition.

## 14. Retry and recovery

- Expected transient states, provider transitions and optimistic conflicts use
  `ErrYield` and `constants.DefaultYieldTimeout` (10 seconds).
- An accepted provider operation is observed until Cinder reaches a known
  outcome. There is no overall timeout in v1.
- Existing core terminal and user-action-required dispositions park.
- Genuine deprovisioning failures use controller-runtime error backoff while
  retaining the finalizer and references.
- There are no blocking waits inside reconciliation.

Crash recovery relies on source-of-truth reads:

- crash after claim write: the persisted claim remains the winner.
- crash after Nova acceptance: the next Cinder observation discovers progress
  or convergence.
- lost status write: lifecycle is re-derived.
- missing attachment with a retained claim: reconstruct a cleanup record.
- duplicate event: idempotent reads and writes produce no duplicate provider
  operation.

## 15. Monitor

Add a dedicated attachment checker to the existing Region monitor process. Do
not add attachment polling to the Server health checker and do not create a new
deployment.

Each poll lists attachments, resolves their Region/provider context, performs
the read-only provider observation and patches only the monitor-owned
`Attached` condition and device. A failed observation records
`Attached=Unknown/ObservationFailed` without clearing the last known device.

An `Attached` change enqueues the Volume ID. The lifecycle controller re-reads
Cinder before deciding whether to attach, detach or report drift. The monitor
never mutates provider state, claims, references, `Available`, or Server status.

## 16. Packaging and RBAC

- Install the CRD from `charts/region/crds`.
- Add a dedicated controller binary, image, Deployment, service account, Role,
  ClusterRole and bindings using existing chart patterns.
- Give the controller permission to watch the endpoints.
- Give the controller permission to manage attachments and their status.
- Give the controller permission to patch Volume claims and references.
- Give the controller permission to patch Server references and
  `status.volumes`.
- Give the monitor read access to attachments/endpoints and patch access only
  to attachment status.
- Give the Region API no attachment permission unless compilation/runtime
  wiring proves a read permission is necessary.
- Ordinary users receive no Kubernetes RBAC for attachments. Cluster
  administrators retain normal operational access.

## 17. Observability

Use structured logs for every reconcile, provider observation, state
transition, reference operation and requeue decision. Include resource type,
attachment ID, Server ID, Volume ID and outcome as fields. Never log credentials
or expose raw upstream errors in conditions.

Use the standard reconcile duration, outcome and queue metrics of the controller framework.
Do not add attachment-specific Events or metrics in v1. Add product
metrics through the monitor only when an attachment SLO requires them.

## 18. Verification

### 18.1 Unit tests

Use standard Go tests for `pkg/` code. At minimum cover:

- deterministic pair naming and immutable schema.
- handler authorization, scope, Flavor, claim and detach validation.
- arbitration, tie-breaking and optimistic conflicts.
- every row of the provider-state safety matrix.
- write-ahead ordering before provider mutation.
- crash after claim write and after Nova acceptance.
- foreign, multiple and orphaned fail-closed behavior.
- deletion ordering and stale-claim reconstruction.
- status writer conflict recovery and self-watch filtering.
- OpenStack observation and attach/detach idempotency.
- monitor condition ownership and provider-observation failure.

### 18.2 Integration test

Add one `//go:build integration` Ginkgo lifecycle using the typed API client and
`test/api.Endpoints`:

1. Create an available Volume and Server.
2. Add the Volume to the Server desired set.
3. Assert the response body and eventual `Server.status.volumes` fields.
4. Remove the Volume.
5. Assert eventual row removal and Volume claim release.
6. Register cleanup immediately after every resource creation.

The KinD install must exercise the generated CRD, controller/monitor
Deployments, service accounts and RBAC under randomized release and namespace
names. Provider-specific OpenStack behavior remains covered by focused provider
tests unless the integration environment supplies OpenStack.

## 19. Acceptance criteria

The feature is complete when:

- Server intent deterministically materializes one attachment per pair.
- one and only one Server claim wins for a Volume.
- no provider attach occurs before claim, finalizer and both references are
  durable.
- attach and detach succeed only after Cinder confirms convergence.
- foreign, multiple and orphaned relationships never trigger destructive
  repair.
- Server deletion detaches but never deletes data Volumes.
- Volume deletion remains blocked by active Server intent.
- Server API status accurately projects lifecycle and device.
- monitor drift observations wake reconciliation but never authorize actions.
- controller restart and duplicate events are safe.
- the documented verification suite passes.
- all repository pre-commit and pre-push checks pass before merge.
