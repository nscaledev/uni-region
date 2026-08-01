---------------------------- MODULE ServerRebuild ----------------------------
(***************************************************************************)
(* The uni-region Server rebuild protocol under the status.observed       *)
(* partition. This model is normative; docs/superpowers/specs/            *)
(* 2026-07-31-server-rebuild-protocol-design.md is its prose rendering.   *)
(*                                                                         *)
(* Processes:                                                              *)
(*   User       - edits spec.image (bounded number of flips)              *)
(*   Reconciler - two-phase: snapshot etcd, decide from a FRESH Nova      *)
(*                read, write back under optimistic lock (409 = requeue). *)
(*                May crash between decide and write (RAbort).            *)
(*   Monitor    - two-phase: snapshot Nova + Server generation, write     *)
(*                status.observed under optimistic lock (409 = drop until *)
(*                next poll). Empty patches make no write and NO event.   *)
(*   Nova       - progresses an accepted rebuild to converged or error.   *)
(*                                                                         *)
(* Toggleable guards (set in the .cfg) so TLC can check the designed      *)
(* system and the buggy variants:                                          *)
(*   LevelWake    - TRUE: settlement wake is a LEVEL (fires on any        *)
(*                  evidence write while verdict is terminal). FALSE:     *)
(*                  EDGE (fires only when the verdict value changes).     *)
(*   UseFence     - evidence correlation by serverGeneration >=           *)
(*                  armingGeneration.                                      *)
(*   UsePreArm    - supersession excludes the pre-arm image ref.          *)
(*   RequeueOn409 - TRUE: a conflicted reconciler status write requeues   *)
(*                  (core's fixed-interval retry, reconcile.go). FALSE:   *)
(*                  the write is silently dropped - isolates whether the  *)
(*                  level wake alone recovers it.                          *)
(*   UseMarker    - TRUE: the persisted rebuild intent gates the decision *)
(*                  (the designed system). FALSE: STATELESS - the pass    *)
(*                  acts from spec vs a fresh Nova read alone; the intent *)
(*                  variables become ghost state. Checks whether the      *)
(*                  two-field marker is actually load-bearing.            *)
(*   RefUpdatesAtAccept - TRUE: Nova's reported image ref flips to the   *)
(*                  target at ACCEPT time (API-database bookkeeping,      *)
(*                  written before any disk work). FALSE: the ref only   *)
(*                  converges on success (an error leaves it at the old   *)
(*                  image). Which holds in practice is per-driver and     *)
(*                  undocumented - the stateless variant's safety turns   *)
(*                  entirely on this switch, the marker's does not.       *)
(*                                                                         *)
(* A reconciler crash (RAbort) is always followed by a restart re-list    *)
(* (controller-runtime informers enqueue every object on start), modeled  *)
(* by relistP.                                                             *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS LevelWake, UseFence, UsePreArm, RequeueOn409, UseMarker, RefUpdatesAtAccept

Images == {"A", "B"}
MaxEdits == 2      \* image flips after the initial create (enough for A->B->A)
RvBound == 14      \* state constraint on resourceVersion churn

NoIntent == [pres |-> FALSE, tgt |-> "A", pre |-> "A", ag |-> 0, acc |-> FALSE]
NoObs    == [pop |-> FALSE, ref |-> "A", disp |-> "conv", sg |-> 0]
NoSnap   == [ok |-> FALSE]

VARIABLES
  \* Nova (provider truth)
  nImg, nOp, nTgt,          \* nOp \in {"idle","busy","err"}
  \* etcd Server object
  spec, gen, rv,
  intent,                   \* [pres, tgt, pre, ag, acc]
  parked,
  obs,                      \* status.observed: [pop, ref, disp, sg]
  \* scheduling
  wake,                     \* settlement wake pending
  relistP,                  \* restart re-list pending (set by a crash)
  lastG,                    \* last generation the reconciler started a pass for
  \* two-phase in-flight state
  msnap, rsnap,
  \* history (for invariants) and bounds
  edits, accCount,          \* accCount: Nova accepts for the CURRENT attempt
  accE,                     \* accE: TOTAL Nova accepts across the run
  parkJust,                 \* park was justified by a fresh Nova read
  aborts                    \* crashes so far (bounded: crashes are finite)

vars == <<nImg, nOp, nTgt, spec, gen, rv, intent, parked, obs, wake, relistP, lastG,
          msnap, rsnap, edits, accCount, accE, parkJust, aborts>>

-----------------------------------------------------------------------------
(* Verdict: the pure function from the spec, with guard toggles. *)

DispOf(op) == IF op = "busy" THEN "busy" ELSE IF op = "err" THEN "err" ELSE "conv"

Correlated(it, ob) == (~UseFence) \/ (ob.sg >= it.ag)

Superseded(it, ob) ==
  IF UsePreArm THEN ob.ref \notin {it.pre, it.tgt} ELSE ob.ref # it.tgt

Verdict(it, ob) ==
  IF ~it.pres \/ ~ob.pop \/ ~Correlated(it, ob) THEN "P"
  ELSE IF ob.ref = it.tgt /\ ob.disp = "conv" THEN "S"
  ELSE IF ob.disp = "err" \/ (it.acc /\ Superseded(it, ob)) THEN "F"
  ELSE "P"

\* Settlement wake predicate over a (intent, parked, obs) after-state.
WakePred(it, pk, ob) == it.pres /\ it.acc /\ ~pk /\ Verdict(it, ob) \in {"S", "F"}

-----------------------------------------------------------------------------
Init ==
  /\ nImg = "A" /\ nOp = "idle" /\ nTgt = "A"
  /\ spec = "A" /\ gen = 0 /\ rv = 0
  /\ intent = NoIntent /\ parked = FALSE /\ obs = NoObs
  /\ wake = FALSE /\ relistP = FALSE /\ lastG = 0
  /\ msnap = NoSnap /\ rsnap = NoSnap
  /\ edits = 0 /\ accCount = 0 /\ accE = 0 /\ parkJust = TRUE /\ aborts = 0

-----------------------------------------------------------------------------
(* User: flip the image. A same-image update is a spec no-op (enforced by  *)
(* the API), so every edit here bumps the generation - the OQ4 invariant.  *)

UserEdit ==
  /\ edits < MaxEdits
  /\ \E i \in Images \ {spec} :
       /\ spec' = i
       /\ gen' = gen + 1
       /\ edits' = edits + 1
  /\ UNCHANGED <<nImg, nOp, nTgt, rv, intent, parked, obs, wake, relistP, lastG,
                 msnap, rsnap, accCount, accE, parkJust, aborts>>

-----------------------------------------------------------------------------
(* Nova: an accepted rebuild eventually converges or errors. On error the *)
(* reported image ref stays where the ACCEPT semantics left it: at the    *)
(* old image (RefUpdatesAtAccept = FALSE) or already at the target        *)
(* (RefUpdatesAtAccept = TRUE, set in the submit action).                  *)

NovaOK ==
  /\ nOp = "busy"
  /\ nImg' = nTgt /\ nOp' = "idle"
  /\ UNCHANGED <<nTgt, spec, gen, rv, intent, parked, obs, wake, relistP, lastG,
                 msnap, rsnap, edits, accCount, accE, parkJust, aborts>>

NovaErr ==
  /\ nOp = "busy"
  /\ nOp' = "err"
  /\ UNCHANGED <<nImg, nTgt, spec, gen, rv, intent, parked, obs, wake, relistP, lastG,
                 msnap, rsnap, edits, accCount, accE, parkJust, aborts>>

-----------------------------------------------------------------------------
(* Monitor: poll (snapshot Nova + Server generation + rv), then patch.    *)
(* The monitor reads NO rebuild intent - it stamps only object-level      *)
(* facts. An unchanged observation is an empty patch: no write, no event. *)

MRead ==
  /\ msnap = NoSnap
  /\ msnap' = [ok |-> TRUE, img |-> nImg, op |-> nOp, g |-> gen, v |-> rv]
  /\ UNCHANGED <<nImg, nOp, nTgt, spec, gen, rv, intent, parked, obs, wake,
                 relistP, lastG, rsnap, edits, accCount, accE, parkJust, aborts>>

MWrite ==
  /\ msnap.ok
  /\ LET newObs == [pop |-> TRUE, ref |-> msnap.img,
                    disp |-> DispOf(msnap.op), sg |-> msnap.g]
     IN IF newObs = obs
        THEN \* empty patch: no API write, no watch event
          /\ msnap' = NoSnap
          /\ UNCHANGED <<nImg, nOp, nTgt, spec, gen, rv, intent, parked, obs,
                         wake, relistP, lastG, rsnap, edits, accCount, accE, parkJust, aborts>>
        ELSE IF rv # msnap.v
        THEN \* 409: optimistic lock lost; drop until next poll
          /\ msnap' = NoSnap
          /\ UNCHANGED <<nImg, nOp, nTgt, spec, gen, rv, intent, parked, obs,
                         wake, relistP, lastG, rsnap, edits, accCount, accE, parkJust, aborts>>
        ELSE \* patch lands; the watch sees the new object
          /\ obs' = newObs
          /\ rv' = rv + 1
          /\ msnap' = NoSnap
          /\ wake' = (wake \/ (IF LevelWake
                               THEN WakePred(intent, parked, newObs)
                               ELSE WakePred(intent, parked, newObs)
                                    /\ Verdict(intent, newObs) # Verdict(intent, obs)))
          /\ UNCHANGED <<nImg, nOp, nTgt, spec, gen, intent, parked, relistP,
                         lastG, rsnap, edits, accCount, accE, parkJust, aborts>>

-----------------------------------------------------------------------------
(* Reconciler: RStart snapshots etcd (and consumes its trigger); RFinish  *)
(* decides from the snapshot plus a FRESH Nova read and writes back under *)
(* the optimistic lock. A 409 requeues when RequeueOn409 (core's fixed-   *)
(* interval retry), else drops. RAbort models a crash between decide and  *)
(* write; the restart's informer re-list (relistP) re-enqueues.           *)
(*                                                                         *)
(* Stateless mode gets a standing divergence trigger: a landed monitor    *)
(* patch whose observed ref differs from spec is the update event a       *)
(* stateless controller would enqueue on.                                  *)

RTrigger == wake \/ relistP \/ (gen > lastG)
            \/ (intent.pres /\ ~intent.acc)
            \/ (~UseMarker /\ obs.pop /\ obs.ref # spec)

RStart ==
  /\ rsnap = NoSnap
  /\ RTrigger
  /\ rsnap' = [ok |-> TRUE, sp |-> spec, g |-> gen, v |-> rv,
               it |-> intent, pk |-> parked]
  /\ wake' = FALSE
  /\ relistP' = FALSE
  /\ lastG' = gen
  /\ UNCHANGED <<nImg, nOp, nTgt, spec, gen, rv, intent, parked, obs,
                 msnap, edits, accCount, accE, parkJust, aborts>>

\* Crash between decide and write; the restart's informer re-list recovers.
\* Bounded: an eternally crash-looping controller settles nothing and is not
\* a protocol bug.
RAbort ==
  /\ rsnap.ok
  /\ aborts < 1
  /\ aborts' = aborts + 1
  /\ rsnap' = NoSnap
  /\ relistP' = TRUE
  /\ UNCHANGED <<nImg, nOp, nTgt, spec, gen, rv, intent, parked, obs, wake,
                 lastG, msnap, edits, accCount, accE, parkJust>>

\* Marker-gated decision (the designed system): what the pass wants to
\* write, given snapshot s and fresh Nova state. One of: "arm", "accept",
\* "submit", "clear", "park", "unpark", "noop".
DecisionM(s) ==
  IF s.pk
  THEN IF s.sp # s.it.tgt THEN "unpark" ELSE "noop"
  ELSE IF ~s.it.pres
  THEN IF s.sp # nImg /\ nOp = "idle" THEN "arm" ELSE "noop"
  ELSE IF ~s.it.acc
  THEN IF nOp = "busy" /\ nTgt = s.it.tgt
       THEN "accept"                       \* lost acceptance write: re-stamp, never resubmit
       ELSE IF nImg = s.it.tgt /\ nOp = "idle"
       THEN "clear"                        \* converged before submit
       ELSE IF nOp \in {"idle", "err"}
       THEN "submit"
       ELSE "noop"
  ELSE \* accepted: settlement from the fresh read
       IF nImg = s.it.tgt /\ nOp = "idle" THEN "clear"
       ELSE IF nOp = "err" THEN "park"
       ELSE IF nOp = "idle" /\ nImg # s.it.pre /\ nImg # s.it.tgt THEN "park"
       ELSE "noop"

\* Stateless decision: spec vs the fresh read, nothing else. The submit
\* condition mirrors DecisionM's (acts from idle OR err) minus the marker
\* gate - the deleted gate is the experiment.
DecisionS(s) ==
  IF s.sp # nImg /\ nOp \in {"idle", "err"} THEN "submit" ELSE "noop"

Decision(s) == IF UseMarker THEN DecisionM(s) ELSE DecisionS(s)

RFinish ==
  /\ rsnap.ok
  /\ LET s == rsnap
         d == Decision(s)
     IN IF d = "noop"
        THEN /\ rsnap' = NoSnap
             /\ UNCHANGED <<nImg, nOp, nTgt, spec, gen, rv, intent, parked,
                            obs, wake, relistP, lastG, msnap, edits, accCount, accE, parkJust, aborts>>
        ELSE IF rv # s.v
        THEN \* 409 on the status write: core swallows and requeues (fixed
             \* interval) when RequeueOn409; otherwise the write just drops.
          /\ rsnap' = NoSnap
          /\ wake' = (wake \/ RequeueOn409)
          /\ UNCHANGED <<nImg, nOp, nTgt, spec, gen, rv, intent, parked, obs,
                         relistP, lastG, msnap, edits, accCount, accE, parkJust, aborts>>
        ELSE
          /\ rsnap' = NoSnap
          /\ rv' = rv + 1
          /\ CASE d = "arm" ->
                  /\ intent' = [pres |-> TRUE, tgt |-> s.sp, pre |-> nImg,
                                ag |-> s.g, acc |-> FALSE]
                  /\ accCount' = 0
                  /\ UNCHANGED <<nImg, nOp, nTgt, parked, parkJust, wake, accE>>
               [] d = "submit" ->
                  /\ nOp' = "busy"
                  /\ nTgt' = (IF UseMarker THEN s.it.tgt ELSE s.sp)
                  /\ nImg' = (IF RefUpdatesAtAccept
                              THEN (IF UseMarker THEN s.it.tgt ELSE s.sp)
                              ELSE nImg)
                  /\ intent' = (IF UseMarker THEN [s.it EXCEPT !.acc = TRUE] ELSE intent)
                  /\ accCount' = (IF UseMarker THEN accCount + 1 ELSE accCount)
                  /\ accE' = accE + 1
                  /\ UNCHANGED <<parked, parkJust, wake>>
               [] d = "accept" ->
                  /\ intent' = [s.it EXCEPT !.acc = TRUE]
                  /\ UNCHANGED <<nImg, nOp, nTgt, parked, parkJust, accCount, wake, accE>>
               [] d = "clear" ->
                  /\ intent' = NoIntent
                  /\ UNCHANGED <<nImg, nOp, nTgt, parked, parkJust, accCount, wake, accE>>
               [] d = "park" ->
                  /\ parked' = TRUE
                  /\ parkJust' = parkJust /\ (nOp = "err" \/ (nImg # s.it.pre /\ nImg # s.it.tgt))
                  /\ UNCHANGED <<nImg, nOp, nTgt, intent, accCount, wake, accE>>
               [] d = "unpark" ->
                  /\ parked' = FALSE /\ intent' = NoIntent
                  /\ UNCHANGED <<nImg, nOp, nTgt, parkJust, accCount, wake, accE>>
          /\ UNCHANGED <<spec, gen, relistP, lastG, msnap, edits, obs, aborts>>

-----------------------------------------------------------------------------
Next == UserEdit \/ NovaOK \/ NovaErr \/ MRead \/ MWrite
        \/ RStart \/ RAbort \/ RFinish

(* Fairness: the monitor keeps polling; the reconciler keeps running when  *)
(* triggered; Nova finishes what it accepted. RAbort and UserEdit are      *)
(* unfair (may happen finitely often / never).                             *)
Fairness ==
  /\ WF_vars(MRead) /\ WF_vars(MWrite)
  /\ WF_vars(RStart) /\ WF_vars(RFinish)
  /\ WF_vars(NovaOK \/ NovaErr)

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* Invariants *)

TypeOK ==
  /\ nImg \in Images /\ nTgt \in Images /\ nOp \in {"idle", "busy", "err"}
  /\ spec \in Images /\ gen \in Nat /\ rv \in Nat
  /\ parked \in BOOLEAN /\ wake \in BOOLEAN
  /\ edits \in 0..MaxEdits /\ accE \in Nat

\* One Nova accept per armed attempt (the submission gate).
AcceptOnce == accCount <= 1

\* The destructive-accept budget: every Nova accept was paid for by a user
\* edit - no automatic retry of a failed rebuild without new user intent.
\* This is the invariant the stateless variants exist to test.
AcceptBudget == accE <= edits

\* Every park was justified by a fresh provider read at park time.
ParkHonest == parkJust

\* State constraint to bound the run.
Constraint == rv <= RvBound

-----------------------------------------------------------------------------
(* Liveness: an accepted rebuild eventually settles - the marker clears   *)
(* or the server parks. Meaningful only when UseMarker (the antecedent is *)
(* vacuous in stateless mode).                                             *)

EventuallySettled == (intent.pres /\ intent.acc) ~> (~intent.pres \/ parked)

=============================================================================
