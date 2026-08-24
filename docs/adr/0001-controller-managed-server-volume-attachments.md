---
status: proposed
---

# Use controller-managed ServerVolumeAttachments

Server attachment intent remains in `Server.spec.volumes`, and `Volume.spec.claimRef`
remains the exclusive binding record. A controller-managed
`ServerVolumeAttachment` represents provider attachment lifecycle for each
Server–Volume pair and is not exposed through the public Region REST API. We do
not introduce a standalone `VolumeClaim`: the current workflow selects an
existing Volume directly, so another resource and binding controller would add
lifecycle and migration machinery without enabling a required capability.

This adopts the useful separation in Kubernetes PV, PVC, and VolumeAttachment
handling without copying the PVC resource model. The initial model permits one
Server per Volume; multiattach is explicitly deferred.

The Server HTTP handler performs preflight validation for immediate user
feedback, but it writes only Server intent. Two controllers divide the work:
the custom Volume-keyed attachment coordinator watches Server intent, Volumes
and attachments, materializes deterministic `ServerVolumeAttachment` objects,
and exclusively owns Volume claim acquisition and release. The generic
attachment-keyed lifecycle controller owns endpoint protection, provider attach
and detach, attachment finalizers and attachment status. Handler validation is
never authorization for a later provider mutation. The initial single-attach
constraint makes Volume the serialization key.

Each controller runs in its own binary and deployment. This is required because
the shared generic UNI reconciler keys status and finalizers to the object it
reconciles: a Volume-keyed generic controller would incorrectly publish
attachment lifecycle on `Volume`. The coordinator therefore uses a custom
reconcile loop, while the lifecycle controller can retain the generic pattern.
This operational cost keeps existing Server and Volume lifecycle controllers
unchanged and ensures attachment cleanup continues independently while endpoint
deletion is blocked by attachment references.

Packaging follows the existing Region Helm pattern: the CRD lives under
`charts/region/crds`, and component-specific service account, least-privilege
RBAC and controller Deployment templates ship in the same release. No staged
rollout mechanism is added.

`ServerVolumeAttachment` is internal in the same sense as other
controller-managed Region resources: it has no public Region REST endpoint and
only its controller receives mutation permissions. Kubernetes cluster
administrators can still inspect and operate on it.

Attachment observation follows UNI's conditions-first convention; provider
attachment identifiers are rediscovered rather than persisted. Each attachment
protects its Server from deletion until provider detachment is confirmed, so
the Server controller cannot delete Nova first. A requested Volume deletion is
similarly postponed while any Server still expresses attachment intent; the
user must remove that intent before the Volume controller detaches and resumes
Cinder deletion.

Provider convergence is observation-confirmed: acceptance of a Nova attach or
detach request is never success until fresh Cinder state shows the requested
relationship present or absent. Attach-time Server state gates apply only when
creating a missing relationship; an already-correct attachment succeeds before
those gates are considered. Cleanup always attempts idempotent detach without
requiring a ready Server and never removes an attachment observed on a different
Server.

Cinder is the attachment authority because it durably reports the number of
storage relationships and the Server ID for each one, including after Nova no
longer exposes a Server. Nova initiates attach and detach and supplies Server
eligibility, but acceptance of a Nova request is not convergence. Cinder may be
eventually consistent, so accepted operations are re-observed until the desired
relationship is confirmed.

If Cinder reports the Volume attached to a different Server, the controller
reports `Available=False/Errored` with a safe foreign-attachment message. It
retains the claim and
all deletion safeguards, and performs neither attach nor detach. Automatically
disconnecting the foreign Server could interrupt a live workload or corrupt
data; adopting it would contradict declared Server intent. Recovery therefore
requires an operator to correct Region or provider state.

After correcting a foreign or orphaned provider relationship, an operator
deletes the affected attachment. Its finalizer verifies provider absence before
cleanup completes; if Server intent still exists, materialization recreates the
relationship. The API adds no force-reconcile field or annotation.

Before every Nova attach request, the provider first observes Cinder. It does
not issue a duplicate request when the desired relationship already exists or
the Volume is still transitioning. This makes reconciliation safe after a crash
between Nova acceptance and status persistence without storing provider
operation identifiers.

If Cinder reports multiple relationships for a Volume, the single-attach
controller reports `UnexpectedMultiattach` and performs no automatic repair.
If Server intent is removed while Nova is still processing attach, deletion
takes precedence: the finalizer remains and any relationship that subsequently
appears is detached before cleanup completes.

If the same Volume is re-added while its deterministic attachment is already
deleting, cleanup still completes before materialization recreates it.
Kubernetes deletion cannot be cancelled safely, and retaining an attachment
through object replacement would create a protection gap.

Once Cinder confirms the intended relationship, later Server lifecycle changes
such as stop, pause, resize or shelve do not trigger detach. Attach eligibility
is evaluated only when creating a missing provider relationship; declared
intent or endpoint deletion controls cleanup.

Likewise, endpoint health degradation does not authorize detach while Cinder
still confirms the intended relationship. The controller preserves the
attachment; only removed intent or endpoint deletion initiates cleanup.

OpenStack-specific Server eligibility remains inside the OpenStack provider.
The attachment controller consumes only a provider-neutral result: allowed,
temporarily blocked or action-required. It does not encode Nova states such as
`ACTIVE`, `SHUTOFF`, locked or shelved.

Independent Region Volumes always use `delete_on_termination=false`. Explicit
detach-before-Server-delete remains the primary data-safety mechanism, with the
Nova flag as defence in depth.

Reconciliation scheduling is classified by recovery trigger. Converged and
event-recoverable states do not requeue; accepted asynchronous provider work
uses the shared 10-second `constants.DefaultYieldTimeout`; transient Kubernetes
or provider conditions and write conflicts return `ErrYield` at that fixed
interval; existing core terminal and user-action-required dispositions park;
only genuine deprovisioning failures use controller-runtime error backoff. An
accepted provider operation continues to be observed until Cinder reaches a
known outcome because it may complete after an arbitrary delay. The initial
implementation adds no overall provider timeout or `ProviderTimeout` condition.

A dedicated attachment checker runs inside the existing Region monitor process,
reusing its provider cache, poll scheduling, telemetry and lifecycle. It owns an
observational `Attached` condition and the ongoing device observation, and it
detects stable provider drift. The
attachment controller owns lifecycle `Available` and treats monitor changes only
as wake signals; it always re-reads Cinder before provider mutation. A separate
monitor process is deferred unless attachment polling later requires an
independent scaling or failure boundary.

`Server.spec.volumes` remains the sole source of attachment intent. A directly
created `ServerVolumeAttachment` may be adopted only when its deterministic
identity and immutable endpoints match current Server intent; otherwise it is
deleted through normal finalizer cleanup and must never authorize provider
attachment. RBAC prevents ordinary users from creating these controller-managed
resources, but controller safety does not depend on that restriction.

The controller materializes the deterministic attachment before validating its
endpoints. Handler validation is only point-in-time preflight: an endpoint may
disappear before reconciliation, internal writers may bypass the HTTP handler,
and restored or legacy objects may contain unresolved intent. The attachment
therefore preserves request age and exposes missing or invalid endpoints as
durable status.

Before acting on an attachment, the controller validates that both endpoints
exist, occupy the same Region tenancy scope, are not being deleted, and still
agree with `Server.spec.volumes`. It also validates VolumeClass compatibility
with the Server Flavor and the attachment's deterministic identity and Server
owner reference. Structural schema rules enforce field shape and immutability;
the controller owns cross-resource validation because admission cannot make
those observations durable.

New provider attachment waits while either endpoint is paused. Attachment
deletion and provider cleanup ignore pause so that pause cannot strand a
relationship or block endpoint deletion.

Reconciliation is driven by relevant changes to Server intent, endpoint
lifecycle/readiness, Volume claim and availability, and attachment generation
or deletion. Server events enqueue both removed and added Volume IDs. The
controller filters its own attachment status writes and Server volume-status
projections to prevent self-triggered reconciliation loops. Explicit bounded
requeues remain available while an accepted asynchronous provider operation is
being observed.

Attachment state projects only into the corresponding
`Server.status.volumes` row; it does not control the Server's overall
`Available` condition. Waiting, claim acquisition and attachment project as
`Provisioning`; confirmed attachment as `Provisioned`; cleanup as
`Deprovisioning`; and invalid, conflicting, terminal or orphaned relationships
as `Errored`. Public messages are safe and actionable, while raw provider
details remain in controller logs.

The attachment lifecycle controller exclusively owns `Server.status.volumes`.
Other Server status writers preserve that field. Projection uses a fresh Server
object and an optimistic status patch; normal conflict retries reconcile
concurrent writes.

When multiple Servers concurrently desire an unclaimed Volume, attachment does
not fail closed. An existing valid claim always wins; otherwise the oldest
attachment request wins, with attachment name as the deterministic tie-breaker.
The Volume-keyed coordinator acquires the singleton claim with optimistic
locking and reports a safe claim-conflict message on losing relationships. It
never changes the winner while that Server continues to desire the Volume.

Request age is the attachment's Kubernetes `creationTimestamp`, which reflects
materialization order rather than the exact instant a Server spec changed.
Server volume entries carry no timestamp, and adding one solely for stronger
fairness is not justified. The choice is stable after materialization.

Claim acquisition is serialized logically by the coordinator's Volume
reconciliation key and persisted with an optimistic patch to
`Volume.spec.claimRef`. Kubernetes conflict retry resolves races between
controller replicas; no distributed lock is introduced.

Every Server–Volume request receives a deterministic pair-named
`ServerVolumeAttachment`. This retains the request's identity, creation time and
status even when it loses arbitration. `Volume.spec.claimRef` remains the
authoritative selected binding: only the attachment whose Server matches the
claim may mutate provider state. Pair identity deliberately prepares the
relationship model for possible future multiattach without enabling it now.

The pair name is a stable UUIDv5 derived from `(serverID, volumeID)`. The
coordinator maps Server and attachment events back to the Volume key; it may
use field indexes later if list-based reconciliation becomes a measured
bottleneck. Tenancy is derived from and validated against the endpoints. The
Server is the attachment's controller owner, while the Volume is deliberately
not an owner because Volume deletion must remain blocked while Server intent
exists. Before any provider mutation, the attachment, its cleanup finalizer,
the selected Volume claim and blocking references on both endpoints must all be
persisted and read back.

Attachment observation follows the generic UNI `Available` condition convention
and includes `observedGeneration`; an optional provider-observed device may be
stored solely for projection into `Server.status.volumes`. Provider attachment
identifiers are not persisted.

The attachment spec contains only immutable `serverID` and `volumeID` fields;
tenancy is derived from its endpoints. Status contains only `observedGeneration`,
UNI conditions and the optional observed device. It has no
phase, provider attachment identifier or duplicate endpoint state.

`Available=True` with canonical reason `Provisioned` means a fresh Cinder
observation confirms that the Volume is attached to the intended Server.
Progress, failure and deletion use the canonical `Provisioning`, `Errored` and
`Deprovisioning` reasons. Safe condition messages distinguish pending endpoints,
a conflicting claim, foreign or multiple attachments and an orphaned
relationship. A transient inability to determine provider truth uses
`Available=Unknown` with `Provisioning`. There is no phase or `Selected`
boolean.

The monitor-owned `Attached` condition uses domain-specific reasons for
`Attached`, `Detached`, `Transitioning`, `ForeignAttachment`,
`UnexpectedMultiattach`, `OrphanedAttachment` and `ObservationFailed`. This
condition is observational and never authorizes provider mutation or cleanup.

The optional device is populated only from fresh provider observation, cleared
after confirmed detachment and used solely as informational projection into
`Server.status.volumes`. It never determines whether cleanup is required.

The HTTP handler returns a conflict when an existing incompatible claim is
visible during preflight. A request that loses a concurrent race remains
durably represented but reports `Available=False/Errored` with a safe
claim-conflict message,
which projects to an errored Server volume row. It performs no provider action
and does not poll; Volume claim and selected-attachment events wake it when
arbitration can change.

Adding a Volume through the existing Server update API performs handler
preflight, persists the complete desired Volume set and returns without waiting
for provider attachment. Removing a Volume is also accepted immediately and
never requires an attach-eligible Server state; provider cleanup is
asynchronous. No imperative attach or detach endpoints are added.

Attachment requests are materialized immediately. The oldest eligible request
acquires the Volume claim before provider readiness, reserving the Volume while
the Server or Volume converges. Provider attachment begins only after both
endpoints are ready and all write-ahead safeguards have been read back. This
keeps request ordering durable and treats the claim as reservation rather than
proof of provider attachment.

Deletion never trusts attachment status as authorization. A deleting
attachment asks the provider to ensure absence and retains its finalizer, claim
and endpoint references until Cinder confirms that absence. Its row remains in
`Server.status.volumes` as `Deprovisioning` until cleanup completes. If Nova no
longer exposes the Server while Cinder still reports its attachment, automatic
force-detach is forbidden: the relationship reports `OrphanedAttachment` and
retains every safeguard for explicit operator recovery.

After Cinder confirms absence, cleanup releases the claim only if it still
matches this Server, removes endpoint-blocking references, removes the projected
Server status row and finally removes the attachment finalizer. The claim is
never released before provider absence is known.

Deleting a Server deletes its attachment relationships and detaches its Volumes,
but never deletes those Volumes. An explicit Volume deletion remains blocked
while a Server still requests it; removing that attachment intent allows
cleanup to detach, release the claim and preserve normal Volume deletion
semantics. Independent Volumes continue to use
`delete_on_termination=false`.

If a Volume claim names a Server but its deterministic attachment is missing,
the controller reconstructs that attachment as a protected cleanup record
before inspecting or changing provider state. It clears the claim only after
confirmed provider absence. A missing claimed Server combined with an observed
Cinder attachment becomes `OrphanedAttachment` and requires operator recovery.

The minimum verification boundary comprises focused handler validation tests,
controller state-table and lifecycle tests, OpenStack provider idempotency
tests, and one integration lifecycle covering attach followed by detach.

The initial controller relies on durable conditions and structured logs, which
is the repository's normal reconciliation observability pattern. It does not
emit attachment-specific Kubernetes Events. It exposes only the standard
controller metrics; product-level custom metrics remain the responsibility of
the monitoring layer and are added only when an attachment SLO requires them.

The initial release explicitly excludes multiattach, boot volumes, configurable
`delete_on_termination`, force detach, public attachment APIs, automatic provider
drift repair and atomic Volume moves between Servers.
