# Getting `status.observed` into region

**Date**: 2026-07-31 (revised same day: dual-write migration replaced by
excise-and-reimplement after the zero-callers finding, §0.1)
**Status**: Draft
**Branch**: `status-observed-spec`
**Protocol reference**: [the machine-checked rebuild protocol spec](2026-07-31-server-rebuild-protocol-design.md)
and its normative model [`tla/ServerRebuild.tla`](tla/ServerRebuild.tla).

## 0. Scope and inputs

The protocol spec defines *what* must be true of the rebuild protocol under a
by-owner status partition; TLC checked it. This document is the other half:
what region's code actually does today, and the staged path from here to
there. Decisions already made and honored here:

- **The monitor stays.** Consolidating it into a timer-driven reconciler is a
  future exercise; the level wake predicates therefore remain load-bearing
  and are re-specified, not deleted.
- **The rebuild marker is two fields** (`targetImageID`, `accepted`) — the
  fence and four-state machine are certified hygiene by the model matrix;
  `preArmImageRef` is *not added* until the async-accept model extension
  decides whether the accepted-but-not-started window needs it.
- **The existing rebuild implementation is excised, not migrated** (§0.1).

### 0.1 Why excise: the rebuild protocol has zero callers

Verified across the estate, not assumed:

- uni-compute (the sole consumer, per region's own README claims) handles
  image drift by **delete and recreate**: `needsRebuild` in
  `pkg/provisioners/managers/instance/provisioner.go` treats an image or
  flavor change as grounds to `deleteServer` — it never PUTs an image change
  to region.
- nscale-cli and uni-ui contain no non-generated callers of
  `PUT /api/v2/servers/{serverID}` at all.
- The only prospective caller is the **unmerged** uni-compute branch
  `inst-920` (`0397c31`, "rebuild instances in place on image-only drift"),
  which renames `needsRebuild`→`needsRecreate`, narrows it to flavor/CA
  drift, and routes image-only drift through the update path.

So the in-place rebuild plumbing — the marker, the four-state machine, the
monitor advancement, the `DO NOT CHANGE` constraints — is dark-launched code
nothing can reach in production. Migrating it under dual-write would preserve
continuity nobody consumes. Instead: hold `inst-920`, delete the plumbing, do
the (now small) split, re-implement rebuild from the protocol spec on the
clean partition, and land `inst-920` as the first caller of the
implementation that was built against the checked model rather than
reverse-engineered into one.

Ticket realignment this implies: INST-1216 ("bin the plumbing") becomes
stage 1 and moves *first*; INST-1198 (the split) is stage 2; the rebuild
re-implementation is a new ticket that absorbs INST-1235b (the Ironic
convergence consult is designed in as a second evidence channel, not patched
onto the old truth table); INST-1235a (the empty CRASHED branch) stays
independent and can land anytime.

## 1. What region has today

### 1.1 Ownership by field

The real writer sets, from the code (not the doc comments):

| Field | Writers today | Readers today | Target |
|---|---|---|---|
| `conditions[Available]` | reconciler (core `handleReconcileCondition`; park via `Terminal`/`UserActionRequired`) | kubectl print column, `serverParked` (provisioner.go:302) | reconciler (unchanged) |
| `conditions[Healthy]` | **monitor** (provider.go:2193) **and reconciler** (`markServerRebuildAccepted`, provider.go:2671) | `logStateTransition` (check.go:146) | `observed.health` |
| `conditions[Active]` | **monitor** (provider.go:2289), **reconciler** (provider.go:2671, provisioner.go:348, provider.go:3010), **and handler** (client.go:140, :272, :304) | v1 `serverPowerState`, v2 `powerState`, `onPhaseTransition`, `ProviderCreateFailure` | **blocked on INST-1213** (power model) |
| `privateIP` / `publicIP` | reconciler (provider.go:2447/2460, 2470–2506); cleared by retry reset (provisioner.go:350–351) | v1/v2 API | reconciler (unchanged) |
| `macAddress` | monitor only (provider.go:2250) | v2 API (client_v2.go:274) | `observed.macAddress` |
| `launchedAt` / `scheduledAt` | monitor (provider.go:2305/2310); **cleared by reconciler** retry reset (provisioner.go:354–355) | poll histograms (check.go:136,139) | `observed.*` (crossing removed, §4 stage 2) |
| `provisionedAt` | monitor, write-once (provider.go:2320) | `ProviderCreateFailure` (provisioner.go:275) | `observed.provisionedAt` (stays write-once) |
| `providerCreateFailures` / `Retrying` | reconciler (provisioner.go:400–428, :368/:383) | `providerCreateFailureUpdate` predicate (manager.go:65) | reconciler (unchanged) |
| `rebuild.targetImageID` | reconciler | v2 `deriveProvisioningStatus` via `RebuildPending()` | **excised**, returns in the re-implementation |
| `rebuild.state` | **both**: reconciler (arm `Initiated`, park `Failed`, advance) and monitor (`advanceServerRebuildState`, provider.go:2605) | `RebuildSettled` (provisioner.go:326) | **excised** — the re-implementation uses `accepted` + the verdict function |
| `volumes` | none | none | **dead** — delete (candidate cleanup, §7) |

Three facts this table surfaces that the prose lore under-counts:

1. **There are three writers of `Active`, not two.** The API handler stamps
   `Pending` on create and `Stopping` on a user stop. Any ownership story
   for `Active` is a power-model question (INST-1213) and is explicitly out
   of this change's scope: `Active` and the handler keep their current
   behavior until that decision lands.
2. **The monitor reads rebuild intent today** (`advanceServerRebuildState`
   reads `Status.Rebuild` and derives acceptance from its rank). The
   protocol's obligation 7 (monitor knows nothing about rebuilds) is a
   *change*, not a formalization of the status quo — delivered here by
   deleting the reader outright (stage 1).
3. **The reconciler clears monitor-written timestamps** on create-retry
   (`resetProviderCreateRuntimeStatus`) — a sanctioned ownership crossing
   that the split must remove, with a replacement story (§4, stage 2).

### 1.2 Write mechanics

- **Monitor**: exactly one status write per poll — an optimistic-locked JSON
  merge patch against the pre-check object (check.go:237), poll period 1
  minute (monitor.go:50). The four mutators that decide the patch content
  live provider-side (provider.go:3279).
- **Reconciler**: a whole-object `Status().Update` at the end of every
  reconcile (core `reconcile.go:385` — core is a module dep, not vendored),
  carrying the resourceVersion from the reconcile-start read. A concurrent
  monitor patch produces a 409, and core requeues after a fixed yield —
  this is the model's `RequeueOn409 = TRUE`, proven independently sufficient
  for settlement liveness (matrix row `_edge`). The write-back covers
  *every* status field the reconciler holds in memory, including
  monitor-owned ones it never meant to touch — harmless only because the
  optimistic lock turns interleavings into 409s. That fragility is the
  problem statement.
- **RBAC already half-enforces the split**: the monitor's cluster role
  grants `servers/status` **patch only** (no update); the controller gets
  both. The partition strengthens what this RBAC boundary means but needs
  no RBAC change.

### 1.3 The couplings that dissolve by deletion

- **Single-patch atomicity** (check.go:230–236 and the `DO NOT CHANGE` on
  `RebuildSettled`, provisioner.go:311–325): today, marker advance and
  health must ride one patch so that every park-conflicting write is itself
  a settlement wake. Under the migration plan this had to be carefully
  dissolved; under excise-and-reimplement both sides of the coupling are
  simply deleted, and the re-implementation is born on the model's level
  predicate (§3).
- **The shared indeterminate-health message** (provider.go:2160 /
  provider.go:2671): the reconciler writes monitor-shaped `Active`/`Healthy`
  values at rebuild-accept so the two writers agree instead of churning.
  Deleted with `markServerRebuildAccepted` in stage 1.

Also load-bearing context: `conditions` has **no `listType: map`** in the
CRD (only the volume lists do), so a merge patch replaces the whole
conditions array — one more reason the observed subtree uses plain typed
fields, not conditions (§2).

## 2. Target shape

```go
// ServerObservedStatus is the monitor's exclusive write region. Nothing
// else may write any field under it; the monitor may write nothing outside
// it (Active excepted until INST-1213 — see §4 stage 2). No reconcile
// decision may read it: observations stimulate, they do not authorize.
type ServerObservedStatus struct {
	// ServerGeneration is metadata.generation at the provider snapshot —
	// the subtree's own freshness stamp (the observedGeneration idiom,
	// scoped to the monitor). It is not rebuild plumbing and no decision
	// reads it: it exists so the observation carries its own provenance
	// and a reader can tell whether the mirror postdates their edit.
	ServerGeneration int64 `json:"serverGeneration"`
	// Image is nil when the provider reported no server — looked-and-absent
	// is a positive observation, not a skip.
	Image *ServerObservedImage `json:"image,omitempty"`
	// Health mirrors today's Healthy condition content.
	Health *ServerObservedHealth `json:"health,omitempty"`
	MACAddress *string      `json:"macAddress,omitempty"`
	LaunchedAt  *metav1.Time `json:"launchedAt,omitempty"`
	ScheduledAt *metav1.Time `json:"scheduledAt,omitempty"`
	// ProvisionedAt keeps its write-once latch semantics.
	ProvisionedAt *metav1.Time `json:"provisionedAt,omitempty"`
}

type ServerObservedImage struct {
	Ref string `json:"ref"`
	// +kubebuilder:validation:Enum=Rebuilding;Converged;Error
	Disposition ServerImageDisposition `json:"disposition"`
}
```

`Observed *ServerObservedStatus` hangs off `ServerStatus`; a nil pointer is
the model's `populated = FALSE` (the monitor has never looked).

`serverGeneration` is deliberately kept while every rebuild-specific
generation artifact (`armingGeneration`, the fence) is dropped: it is a fact
about the observation, not about any intent. The deep-equal skip includes
it, and since generation only moves on spec edits, the cost is exactly one
patch per edit — the first poll afterward — which doubles as the "the mirror
now postdates your edit" signal. Thereafter polls are empty again.

**Plain fields, not `metav1.Condition`** — resolving the protocol spec's
open encoding question: CRD conditions are atomic arrays under merge patch
(§1.3), which is exactly the class of cross-writer hazard this change
removes; plain fields make the monitor's patch trivially narrow and the
mutation-diff test (§5) trivially precise.

**The rebuild marker** arrives fresh in the re-implementation (stage 3) —
no shrink migration, no enum compatibility:

```go
type ServerRebuildStatus struct {
	TargetImageID regionids.ImageID `json:"targetImageID"`
	// Accepted is the write-ahead acceptance marker: stamped in the same
	// pass that submits the provider rebuild. It is what makes resubmission
	// impossible (AcceptOnce) and settlement legible (the verdict).
	Accepted bool `json:"accepted,omitempty"`
}
```

The necessity of these two fields is itself machine-checked: the
`_stateless` model variant (decision from spec vs fresh read alone, no
marker) violates `AcceptBudget` — a provider error that leaves the reported
ref at the old image makes the divergence check resubmit the destructive
rebuild with no new user intent. `_stateless_refupdate` shows the invariant
survives without the marker only if Nova's accept-time ref bookkeeping is
trusted across every error path — the exact trust INST-1235 invalidates.

`RebuildPending()` (`Status.Rebuild != nil`) and v2's
provisioned→provisioning rewrite are excised with the marker and return with
it in stage 3. Whether a park needs an error-attribution field beyond the
Available condition's reason/message is decided during stage 3 — the park
latch itself stays the Available condition.

**The verdict** is a pure function beside the types (unit-testable with
zero mocks), exactly the model's, minus the deleted guards:

```
verdict(intent, observed) =
    Pending    if intent == nil ∨ observed == nil
    Succeeded  if observed.image.ref == intent.targetImageID ∧ disposition == Converged
    Failed     if disposition == Error ∨ (intent.accepted ∧ observed.image.ref ≠ intent.targetImageID)
    Pending    otherwise
```

(No fence: `_nofence` proved it hygiene. No preArm in the *verdict*; whether
the *decision*'s supersession park needs pre-arm evidence is settled by the
async-accept model extension before stage 3 commits to a park guard.)

## 3. The wake, specified for the re-implementation

The settlement wake is the model's checked form — **a level over the whole
object**, evaluated on every Server update event:

```
settled(server) = server.Status.Rebuild != nil
               ∧ server.Status.Rebuild.Accepted
               ∧ ¬serverParked(server)
               ∧ verdict(server.Status.Rebuild, server.Status.Observed) ∈ {Succeeded, Failed}
```

A pure level, no old/new comparison. Every landed monitor patch that leaves
the verdict terminal re-fires it; a park write lost to a 409 is re-covered
by the next poll's patch, and if the observation is unchanged (no write, no
event) core's 409-requeue independently recovers the dropped park — matrix
rows `_level_norequeue` and `_edge` each pass alone, so liveness is
double-covered by construction, not by patch anatomy. No `DO NOT CHANGE`
comment is needed where the constraint is a checked model property; the
predicate cites the model instead.

## 4. The path: excise, split, re-implement, land the caller

**Stage 0 — hold `inst-920`.** No action: it is unmerged. It becomes the
acceptance test for stage 4.

**Stage 1 — excise the rebuild plumbing** (INST-1216, reframed and moved
first). Delete, in one reviewable series:

- Types: `ServerRebuildStatus`, `ServerRebuildState` + constants,
  `RebuildPending()`; CRD regen drops `status.rebuild`;
  `TestServerRebuildSchema` goes with it.
- Reconciler path: the `reconcileServerImage` chain (P1–P7),
  `reconcileServerRebuildPark`, `reconcileServerImageConverged`,
  `reconcileServerImagePending`, `submitServerRebuild`,
  `markServerRebuildAccepted` and the shared message constant.
- Monitor path: `advanceServerRebuildState`, `advanceRebuildState`,
  `serverRebuildStateRank` and the truth table.
- Wiring: `RebuildSettled`, `serverRebuildSettledUpdate` (the manager
  predicate `Or` shrinks by one), v2 `deriveProvisioningStatus`'s
  provisioned→provisioning rewrite.
- **Add a temporary API guard**: reject image changes in
  `validateUpdatedImage` while no reconciler behavior exists for them, so
  `spec.image` cannot silently diverge from reality during the gap. Removed
  in stage 3. (Without the guard, a PUT with a new image would update spec
  and nothing would act — a lie at rest.)

Behavior-neutral by the zero-callers finding (§0.1); existing CRs carrying
`status.rebuild` in dev environments are pruned by the structural schema on
their next status write. The pre-commit checklist plus the e2e suite is the
safety net.

**Stage 2 — the split** (INST-1198). Small on a rebuild-free codebase:

1. Add `ServerObservedStatus` (§2), regen CRDs, extend `crd_schema_test.go`.
2. Monitor's provider-side mutators build the observed struct from the same
   Nova read and write it *alongside* the legacy fields — still one patch
   per poll. Skip the write entirely when nothing changed (obligation 3).
3. Flip readers one at a time, each its own reviewable change: v2
   `macAddress` → `observed.macAddress`; poll histograms →
   `observed.launchedAt/scheduledAt`; `logStateTransition` →
   `observed.health`.
4. `ProviderCreateFailure` → re-derived. Today it reads
   `provisionedAt`/`launchedAt`/`Active`, and the retry reset *clears* the
   timestamps to make the next attempt legible — the ownership crossing.
   Under the split the reconciler may not clear observed fields; the
   monitor's absence semantics do the work instead:
   `deleteFailedProviderServer` removes the provider server, the next poll
   observes absence (`observed.image = nil`, health gone), and the
   subsequent attempt's observations overwrite. The predicate re-derives
   from reconciler-owned counters (`providerCreateFailures`/`Retrying`)
   plus observed evidence. **This is the one seam that needs its own design
   attention and dedicated tests** — the stale-timestamp window between
   delete and next poll must not mis-fire the edge predicate.
5. Stop the legacy monitor writes (Healthy condition, top-level
   MAC/timestamps); narrow the patch construction to `status.observed`
   (+ `Active` until INST-1213) and land the mutation-diff test (§5).

One release of dual-write between steps 2 and 5 covers the window where
old CRs have legacy fields but no observed subtree. Rollback of any step is
safe until step 5.

**Stage 3 — re-implement rebuild from the protocol spec** (new ticket;
absorbs INST-1235b). Greenfield against the checked model, on the clean
partition:

- Marker `{targetImageID, accepted}` (§2), armed only from spec-vs-fresh-read
  divergence; the decision procedure is the protocol spec's §4 table.
- The verdict as a pure function; `settled()` (§3) as the manager predicate.
- **Ironic convergence as a second evidence channel** gating `clear` for
  baremetal — designed in, per INST-1235b, so a Nova that reports converged
  without writing the image cannot produce a false success. Extend the TLA+
  model first (the silent-failure `NovaLie` transition + honesty invariant)
  so the guard is checked, not argued.
- Run the async-accept model extension before committing the supersession
  park guard (the `preArmImageRef` question).
- Remove the stage-1 API guard; v2 image updates become live intent again.
- `RebuildPending()` and the v2 provisioned→provisioning rewrite return.

**Stage 4 — land `inst-920`** (completes INST-920). uni-compute flips
image-only drift from delete+recreate to the update path; region's rebuild
gains its first caller, e2e'd against the re-implementation before merge.

## 5. Obligations → enforcement

The protocol spec's §8 obligations, mapped to where each is enforced and
tested:

| # | Obligation | Enforced by | Test |
|---|---|---|---|
| 1 | same-image spec edit is a no-op | API handler update path (`validateUpdatedImage` already short-circuits same-image, client_v2.go:87) | unit: update with unchanged image must not bump generation — **verify before stage 3 leans on it** |
| 2 | monitor patch narrow + optimistic + drop-on-conflict | check.go patch call; stage-2 patch construction | mutation-diff test: run a poll against a fixture, assert the computed patch touches only `status.observed` (+ `Active` until INST-1213) |
| 3 | unchanged observation ⇒ no write, no event | deep-equal skip in `checkServer` | unit: identical snapshot ⇒ zero API writes |
| 4 | decisions from fresh provider reads, never `observed` | stage-3 rebuild logic stays provider-side on the reconcile path | review rule + unit: verdict/decision funcs take explicit args; nothing in the rebuild pass dereferences `Status.Observed` |
| 5 | reconciler 409 ⇒ requeue | core `reconcile.go` (unchanged dep) | covered by core; do not fork |
| 6 | restart ⇒ re-list | stock informers | nothing to do |
| 7 | monitor writes only observed, reads no intent | stage-1 deletion of `advanceServerRebuildState`; RBAC patch-only already in place | mutation-diff test (as #2); grep-level lint that `pkg/monitor` + `updateServerStateWithClients` never touch `Status.Rebuild` |
| 8 | settlement wake is a level on every update event | `settled()` predicate of §3, born correct in stage 3 | unit: predicate is true for a terminal-verdict object regardless of the old object; integration: dropped park recovers within one poll |

## 6. Tooling and docs checklist

- `types.go` edits rebuild CRDs via the **file-target** (`charts/region/crds`
  depends on `$(APISRC)`) — `make generate` alone does *not* regen CRDs or
  deepcopy; run the checklist (`make touch license validate lint generate`,
  clean tree, `make test-unit`).
- `crd_schema_test.go`: `TestServerRebuildSchema` deleted in stage 1;
  observed-subtree assertions added in stage 2; new marker assertions in
  stage 3.
- OpenAPI: no schema change required — `observed` is not served; v2's
  `macAddress` flip is a source change only. The stage-1 image-update guard
  is a validation change, not a schema change.
- READMEs asserting ownership to update in the same changes:
  `pkg/apis/unikorn/v1alpha1/`, `pkg/monitor/`, `pkg/monitor/health/server/`,
  `pkg/managers/server/`, `pkg/providers/internal/openstack/`,
  `pkg/provisioners/managers/server/`, `pkg/handler/server/`.

## 7. Out of scope, blocked, and flagged

- **INST-1213 (power model)** blocks any `Active` ownership change; the
  handler's `Pending`/`Stopping` writes and the monitor's `Active` write are
  untouched here.
- **INST-1235a** (empty CRASHED branch) is independent — land anytime.
- **Model extensions gate stage 3**: the silent-failure (`NovaLie`)
  extension checks the Ironic evidence guard; the async-accept extension
  settles the `preArmImageRef` question. Both are model work, cheap relative
  to what they de-risk.
- **The park latch is `Errored` + absence-of-retry, not a distinct state.**
  Core deliberately surfaces transient and terminal failures identically
  (`handleReconcileCondition`: "no observable distinction between a retrying
  and a terminal failure"), and `serverParked` reads
  `Available.reason == Errored` — so a transient API error momentarily reads
  as parked until the retry pass overwrites it. The TLA+ model's `parked` is
  a crisp boolean; reality's is not. Level triggering makes the ambiguity
  harmless for settlement, but stage 3 should consider a first-class park
  reason on Available (core already supports specialized reasons — the
  `Dependency*` block is precedent) so `serverParked` becomes exact.
- **`metav1.Condition.observedGeneration` is unstamped estate-wide** (zero
  writers in core v1.19.0 and in region). `observed.serverGeneration` is the
  same upstream idiom applied at subtree scope — one stamp for the one
  provider snapshot all observed facts share, rather than N per-condition
  copies. Stamping the condition field in core's helpers would give the
  *reconciler* axis the same answer ("has the reconciler processed my
  edit?" via `Available.observedGeneration`) — a cheap core-repo rider,
  not a dependency of this change. It does not rescue conditions as the
  observed encoding: JSON merge patch replaces arrays wholesale regardless
  of `listType` markers (those only affect SSA, which is rejected here).
- **`ServerStatus.Volumes` is dead** (zero readers, zero writers; only the
  declarations exist). Delete as a separate one-line cleanup PR, not here.
- **Server-side apply** was considered for the monitor's subtree and
  rejected for this change: nothing in-repo uses SSA, the field-manager
  story is new operational surface, and merge-patch + patch-only RBAC +
  the mutation-diff test already give the guarantee we need.
