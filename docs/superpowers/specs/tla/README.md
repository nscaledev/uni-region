# TLA+ model: Server rebuild under the `status.observed` partition

`ServerRebuild.tla` is the normative definition of the rebuild protocol;
[the design spec](../2026-07-31-server-rebuild-protocol-design.md) is its
prose rendering. The model covers: user spec edits, a two-phase reconciler (snapshot etcd → decide from a fresh
Nova read → optimistic write), a two-phase monitor (poll → merge patch, empty
patches make no write and no watch event), Nova progressing an accepted
rebuild to converged or error, optimistic-lock 409s on both writers, and
level- vs edge-triggered settlement wakes. Reconciler crashes between decide
and write are modeled (`RAbort`, bounded) and are followed by a restart
re-list, as controller-runtime informers guarantee.

The design's guards are constants so TLC checks the designed system *and*
its buggy variants.

## Checked properties

- `AcceptOnce` (safety): at most one Nova accept per armed attempt — the
  submission gate.
- `ParkHonest` (safety): every park was justified by the fresh provider read
  taken by the parking pass.
- `EventuallySettled` (liveness): an accepted rebuild eventually clears or
  parks.

## Results

| Config | Marker | LevelWake | Fence | 409-requeue | Result |
|---|---|---|---|---|---|
| `ServerRebuild.cfg` (designed) | ✓ | ✓ | ✓ | ✓ | **all pass** (4,685 states) |
| `_level_norequeue` | ✓ | ✓ | ✓ | ✗ | **all pass** — the level wake *alone* recovers a conflict-dropped park, mechanically confirming the PR #523 claim |
| `_edge` | ✓ | ✗ | ✓ | ✓ | **all pass** — core's 409-requeue *alone* recovers it under edge triggering |
| `_edge_norequeue` | ✓ | ✗ | ✓ | ✗ | **liveness fails** — TLC produces the hung-rebuild trace the `DO NOT CHANGE` comments argued: wake consumed by a pass whose write is 409'd by a monitor patch, then unchanged-verdict polls are empty patches that never re-fire |
| `_nofence` | ✓ | ✓ | ✗ | ✓ | **all pass** — the generation fence is wake hygiene, not a safety or liveness mechanism; safety rests on fresh-read discipline |
| `_stateless` | ✗ | ✓ | ✓ | ✓ | **`AcceptBudget` fails** (8-state trace) — deciding from spec vs a fresh read alone, a provider error that leaves the reported ref at the old image makes the divergence check resubmit the destructive rebuild with no new user intent: the double-wipe loop |
| `_stateless_refupdate` | ✗ | ✓ | ✓ | ✓ | **all pass** — the stateless design is safe *iff* Nova's reported ref reliably flips at accept time, i.e. iff Nova's accept-time DB bookkeeping is the write-ahead marker. That is per-driver, undocumented behavior, and INST-1235 shows exactly this bookkeeping lying on baremetal |

Two independent mechanisms each suffice for settlement liveness: core's
requeue-on-conflict, and the level-triggered wake. The design keeps both;
the (LevelWake × RequeueOn409) matrix is complete — either alone survives
the park-conflict race, and only losing both hangs.

The stateless pair answers "why keep any marker at all": `AcceptBudget`
(every destructive accept is paid for by a user edit — `accE <= edits`) is
what the two-field marker buys. Without it, safety degenerates to a bet on
which Nova error paths update the reported image ref — the marker records
the same accept-time fact in the object *we* control, under our optimistic
lock, independent of provider bookkeeping.

## Fidelity notes (what the model does and doesn't capture)

- Nova accept is synchronous (submit ⇒ `busy`). The armed-but-not-started
  evidence window that `preArmImageRef` guards therefore cannot produce a
  wrong *action* here (parks are fresh-read-gated); demonstrating its
  display/wake value needs an async-accept extension. Foreign rebuilds
  (supersession) are likewise not modeled yet.
- One server, images {A, B}, at most 2 spec flips, at most 1 crash, rv ≤ 14
  (state constraint). Small but sufficient for every race in the spec's §8
  table that doesn't involve staleness *display* semantics.
- The monitor stamps only object-level facts — it reads no rebuild intent,
  matching the generation-fence design (no `forAttempt`).

## Running

```sh
java -cp tla2tools.jar tlc2.TLC -deadlock -workers 4 \
  -config ServerRebuild.cfg ServerRebuild.tla
```

(TLC ships in [tla2tools.jar](https://github.com/tlaplus/tlaplus/releases);
any JRE ≥ 11.)
