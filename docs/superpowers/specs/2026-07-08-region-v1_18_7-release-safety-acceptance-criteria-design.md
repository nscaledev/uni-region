# Release-Safety Acceptance Criteria: Region `.7` (v1.18.7) → Production

**Date:** 2026-07-08
**Author:** Simon Murray (with Claude)
**Decision owner:** Instances squad
**Question:** Is staging-on-`.7` safe to promote to production, with no regressions vs `.6`?

## Context

Staging (UAT) was upgraded from `.6` to `.7`. The **API Tests** workflow
(`.github/workflows/test-api.yaml`) runs the Ginkgo integration suite
(`test/api/suites/`) against the **live deployed** environment, archives
`test-results.json` (ginkgo-json) + `junit.xml`, feeds a longitudinal
test-history service (`test-history-suite: uni-region-api`), auto-files Linear
issues for failures, and enriches failures with Grafana logs, Unikorn CR state,
and AI analysis in the Slack report.

Key facts established during scoping:

- **Baseline:** the last green `.6` UAT run is scheduled run `28926617426`
  (2026-07-08 07:51), staging **fully green**. This is what "no regression" is
  measured against.
- **Under test:** workflow_dispatch run `28950826755` (UAT-only; dev skipped) —
  the same suite against staging-on-`.7`. This is **attempt #1**.
- **No test/code skew:** the UAT job checks out the ref the version API resolves
  from the deployed service, so test code matches the deployed `.7`.
- **CI has no retry/flake handling:** CI runs `make test-api` (`ginkgo run -v`,
  **serial**, no `--flake-attempts`, no `--repeat`). Distinguishing "real
  regression" from "flaky" requires a retry procedure defined here.
- **Dev-only failures** (07-06, 07-08) are a **different version** (dev tracks
  main/nightly) and are out of scope, except as corroborating evidence (see AC2).

## Procedure (evidence collection)

Whole-suite retries, **conditional and early-stopping**, with **3 attempts as a
ceiling, not a target**. Retries cost time and live-environment compute, and the
squad still has the compute service to gate, so we do not spend runs we don't
need.

1. **Attempt #1** = the in-flight run `28950826755`. We pay for it regardless.
2. **If #1 is fully green → SAFE. Stop. Zero extra runs.**
3. **If #1 has failures → re-dispatch the whole UAT suite** (`run_uat=true`,
   `run_dev=false`), and stop as soon as the picture resolves:
   - A failing spec that **passes on any later attempt → flaky**, resolved; it
     needs no further retries (this is "green-within-N").
   - Re-dispatch again only while specs are **still failing**, up to attempt #3.
   - Consequence: an all-flaky failure set resolves in **2 runs**; only a
     genuinely-stuck spec consumes the **3rd**.
4. Staging must **stay on `.7`** across all attempts (the resolver re-checks the
   live version each dispatch; a version change mid-run invalidates aggregation).

Per spec, record the pass count `k/3` across the attempts actually run.

## Classification (per spec)

| Pass count | Class | Meaning |
|---|---|---|
| `3/3` (or `1/1` if #1 green) | **Stable pass** | Trusted. |
| `1–2/3` | **Flaky / intermittent** | Passed at least once → non-blocking, but tracked. |
| `0/3` | **Consistent failure** | Never passed → **blocks** (candidate regression). |

## The Gate — `.7` is SAFE to promote iff ALL of:

- **AC1 — Hard block on consistent failures.** Zero specs fail **all 3
  attempts** (`0/3`). Any spec that was green on the `.6` baseline and now fails
  every attempt is a **regression** and blocks release, unless discharged by AC2.

- **AC2 — Attribution escape hatch.** A `0/3` spec is reclassified as
  non-blocking **only** with documented evidence it is **not `.7`-caused** —
  i.e. environmental (staging data drift, quota exhaustion, external-network /
  OpenStack 5xx), test-data, or provably pre-existing. **Because `.6` was green,
  the default verdict for any `0/3` spec is "regression" until evidence proves
  otherwise.** Primary evidence: the report's Grafana log enrichment, Unikorn CR
  state, and AI analysis. Corroborating: if the **same** spec also fails on dev,
  the failure is likely not `.7`-specific (helps discharge; does not by itself
  prove environmental).

- **AC3 — Flakiness ceiling (soft-regression flag).** `1–2/3` specs do not
  block, but a spec that was **stable on the `.6` baseline and is now ≤`1/3`** is
  flagged for human review before promotion. A near-total-failure wearing a
  "flaky" label is a regression signal, not a free pass.

## Deliverables (the "firm handle on reliability")

- **Reliability report:** per-suite / per-spec `k/n` pass-rate table; suite-level
  flake rate = `#(1–2/3 specs) / total specs`.
- **Three lists:** consistent failures (`0/3`, blockers) · flaky (`1–2/3`,
  tracked) · stable.
- **`.6` → `.7` diff:** which specs changed class vs the green `.6` baseline —
  this is where genuine regressions surface.
- **Longitudinal reliability:** drawn from the existing `uni-region-api`
  test-history service rather than brute-forcing fresh statistics, so we
  characterise suite reliability without burning extra runs.
- **Verdict:** SAFE / NOT SAFE, with the blocking list and per-blocker
  attribution against AC1–AC3.

## Operational caveats

- Each run auto-files up to 5 Linear issues → multiple runs risk **duplicate
  issues**. The report dedups and flags rather than trusting the auto-filed set.
- Keep staging pinned to `.7` for the duration (see Procedure step 4).
- Retry runs are whole-suite by explicit choice: faithful to real CI ordering and
  catches order-dependent flakiness, at full per-run cost. This is accepted.

## Out of scope

- Compute service release gating (separate suite, separate decision).
- Dev environment failures except as AC2 corroboration.
- Changing the CI harness to add inline `--flake-attempts` (considered and
  rejected in favour of conditional whole-suite re-dispatch).
