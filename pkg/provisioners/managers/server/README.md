# Server

`pkg/provisioners/managers/server` is the richest manager provisioner in the tree.

Distinctive behaviour:

- maintains explicit reference edges from a server to consumed networks,
  security groups, and optional SSH certificate authority
- blocks on identity readiness before provider create/delete
- preflight checks may still yield inside the provider, after other
  validation succeeds; those checks are transient and are not recorded
  as lifecycle transitions
- augments provider create options with managed cloud-init parts for SSH CA use
- retries provider-accepted create attempts that later land in provider error,
  deleting the failed provider server before a bounded re-attempt, but only for
  servers that have never been successfully provisioned; once the attempt cap is
  reached it aborts terminally rather than retrying further
- clears or updates consumed-resource references during reprovision and teardown

Create recovery and image rebuild recovery deliberately use different state:

| Initial create failure | Image rebuild failure |
|---|---|
| Server never launched | Server previously launched |
| Delete/recreate, bounded by the existing flag | One accepted attempt per target image |
| `ProviderCreateFailures` | `Status.Rebuild` |
| Exhaustion is operator-terminal | User selects another image or replaces the server |
| Edge wake: `ProviderCreateFailure` via `providerCreateFailureUpdate` | Level wake: `RebuildSettled` via `serverRebuildSettledUpdate` |

The rebuild state machine lives in the OpenStack provider's existing-server
reconciliation path. It leaves the create retry counter and predicate code
untouched. Intent is write-ahead: an arming pass records `Status.Rebuild` and
yields, so the marker is durable before a later pass submits to Nova (see the
provider README for the recovery semantics this buys). During a rebuild the
reconcile completes as soon as Nova accepts the action: it writes a fixed
accepted stamp (`Healthy` `False`/`Provisioning` and `Phase` `Building`, never
derived from the rebuild response body) — previously only the monitor's poll
wrote those for an existing server, so the create retry predicate's inputs can
now arrive a cycle earlier via the reconcile path as well — and then returns
rather than self-polling Nova until the rebuild converges.

Settlement is watch-predicate-driven for both recovery paths
(`pkg/managers/server`), each over a helper exported from this package:

- create failure rides `providerCreateFailureUpdate` over the
  `ProviderCreateFailure` helper — it wakes the reconciler to run the bounded
  delete-and-retry. This helper is genuinely shared: the provisioner makes the
  delete-and-retry decision through the same function the watch predicate
  fires on, so the trigger and the action cannot drift.
- rebuild settlement rides `serverRebuildSettledUpdate` over
  `RebuildSettled` — it wakes the reconciler for a settlement pass (marker
  clear on success, `UserActionRequired` park on failure) once the monitor
  stamps a terminal state (`Succeeded`/`Failed`) on `Status.Rebuild`. Unlike
  `ProviderCreateFailure`, the provisioner never consults `RebuildSettled`:
  the wake is stimulus only, and the settlement pass re-decides from its own
  fresh provider read. The helper lives beside the settlement logic so the
  wake condition and what it wakes are reviewed together.

`RebuildSettled` is a LEVEL test on the rebuild state, evaluated on the new
object at every non-empty status write rather than as a transition test: it
fires whenever `Status.Rebuild.State` is `Succeeded`, or `Failed` on a server
not yet parked (`serverParked`, which reads the core-owned `Available=Errored`
that a park writes). Its exact shape is load-bearing, and both halves matter.

It never fires for `Initiated` or `Rebuilding`. That is deliberate, not an
optimization: a wake over `Initiated` could re-drive a submission whose
acceptance write was lost and produce a second Nova accept, so the submission
gate must have no wake channel. Pre-acceptance progress is instead carried by
the arm/submit pass's own yield loop, and an in-flight `Rebuilding` has nothing
to settle.

It fires on *any* non-empty status write while a terminal marker stands, not
only on the write that changes the marker's state. This is what lets a dropped
write recover without leaning on re-assertion — an identical re-assertion is an
empty patch, produces no watch event, and could never re-fire a lost wake. The
settlement pass's own action removes the level: a `Succeeded` marker's converged
clear deletes the marker, and a `Failed` marker's park flips `Available` to
`Errored`, which `serverParked` then masks so a parked server's steady state
stays quiet (its marker is retained until the user selects another image). Each
of those settlement writes is confirmed by the pass's own yield loop, not by a
wake event: the clearing pass reads the marker back absent, and the pre-park
pass reads `Failed` back durable before it parks. The single write with no
read-back confirmation is the park's `Available=Errored` itself — and the
any-write level is exactly what covers it, because the very patch that conflicts
that write away lands while `Failed ∧ not-parked` still stands in etcd, so it is
itself a terminal-level wake and the woken pass re-parks. (This rests on the
monitor writing its marker advance and health in a single patch per poll; see
`pkg/monitor/health/server`.)

The reconciler still makes every decision from its own fresh provider read; the
monitor's stamp is stimulus, never authorization.

This is the clearest controller-side expression of the lifecycle DAG model:

- network/security-group/SSH-CA edges are explicit and blocking
- provider-side server lifecycle is delegated
- cloud-init augmentation translates higher-level SSH CA semantics into machine
  bootstrap material

## Caveats

- Reference maintenance here is easy to underappreciate, but it is central to
  keeping server deletion and dependent-resource blocking semantics correct.
- Provider create retry state is stored on `Server.status.providerCreateFailures`.
  Transient provider create failures return `ErrYield` (a fixed-interval requeue)
  until the configured attempt cap is reached. At the cap the provisioner returns
  the core `provisioners.Terminal` disposition, so the reconciler parks the server
  (writes `Errored`, stops requeuing) instead of looping forever on a failure that
  cannot self-heal — the bare error it used to return was requeued every yield
  interval indefinitely, starving the workqueue. The counter is tested against the
  prospective attempt and clamped to the cap, so it settles at the cap and cannot
  drift on re-reconcile or controller restart (an already-drifted counter heals
  back down on its next pass). Recovery is deliberately out of band: the terminal
  state is sticky until an operator resets `providerCreateFailures`, which re-arms
  the retry on the next reconcile. Changing retry behaviour must preserve these
  invariants.
- The delete-and-retry decision lives in the single `ProviderCreateFailure`
  predicate, shared with the controller watch predicate
  (`pkg/managers/server`) so the trigger and the action cannot drift. It fails
  closed: a rebuild destroys data, so any signal that the server has ever booted
  blocks it. In steady state the load-bearing guard is `launchedAt` (mirrored
  from Nova `launched_at`, which Nova sets at first boot and never clears).
  `Server.status.provisionedAt` is a durable, write-once copy of that same Nova
  signal that the retry reset never clears; it closes the one window `launchedAt`
  alone cannot — a launched server whose `launchedAt` is wiped by an in-flight
  retry reset, or a re-reconcile against a flaky provider. A reconciler-owned
  `Available`/Provisioned condition would be unsuitable for this: it is
  re-derived every reconcile and legitimately flips to `Errored`/`Provisioning`
  on a controller restart against a flaky provider — exactly when a rebuild would
  be catastrophic. The post-launch phases are retained as further defence in
  depth so losing any single status field cannot re-arm the rebuild path.
  Existing servers predating the latch backfill it on the next poll once booted
  and are covered by the `launchedAt` backstop until then.
- `Server.status.macAddress` is owned exclusively by the monitor (see
  `pkg/monitor/health/server`), not the reconciler. The reconciler no longer
  records it at port-create time — that value is the ephemeral Neutron MAC for
  baremetal, which Ironic later rebinds to the real NIC MAC — and the retry
  reset deliberately leaves it intact (like `provisionedAt`) so it never
  flickers to unset; a stale value self-heals on the next `ACTIVE` poll.
- Provider create retries also emit Kubernetes events and structured logs on
  retry start, retry readiness after delete, and retry exhaustion; avoid
  per-reconcile emissions while deletion is still converging.
- The provisioner currently trusts the API not to supply repeated network or
  security-group IDs, even though the code still carries explicit TODOs to
  reject duplicates.

## TODO

- Reject repeated network IDs in server specifications at the API boundary
  rather than relying on provisioner-side reference maintenance to behave
  sensibly.
- Reject repeated security-group IDs in server specifications for the same
  reason.
