# Excise Rebuild Plumbing (Stage 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete the in-place server rebuild implementation (the four-state marker, monitor advancement, reconciler rebuild pass, wake plumbing) and guard the API against image changes, per stage 1 of `docs/superpowers/specs/2026-07-31-status-observed-implementation-design.md`.

**Architecture:** Pure excision, justified by the verified zero-callers finding (spec §0.1): uni-compute delete+recreates on image drift; nothing calls the v2 image-update path. Order: guard the API first (so every later deletion is provably dead code), then delete consumers outward-in — wake plumbing, monitor advancement, reconciler pass — and the types last. Each task compiles and passes tests on its own.

**Tech Stack:** Go, controller-runtime, gomock (`make generate`), controller-gen CRDs (Makefile file-targets), Ginkgo integration suite (`//go:build integration`).

## Global Constraints

- Work in the worktree `/home/alex.emery/code/uni-brella/uni-region-status-observed`, branch `status-observed-spec`. Never commit to main.
- Pre-commit checklist must pass before the final commit of the plan: `make touch && make license && make validate && make lint && make generate`, then `[[ -z $(git status --porcelain) ]]`, then `make test-unit` (CLAUDE.md).
- `make generate` does NOT regenerate CRDs or deepcopy — those are Makefile *file targets* rebuilt when `pkg/apis/**` changes (Task 5 handles this explicitly).
- Comment style: comments state constraints code can't show; never narrate the diff. Deleted-feature references in comments are removed with the feature.
- `pkg/**/README.md` files are part of the implementation contract: each task updates the READMEs its deletions invalidate, in the same commit.
- Line numbers below are as of branch HEAD `be2472e` and drift as tasks land — anchor by symbol name, use line numbers as hints only.
- Do NOT touch `docs/superpowers/specs/` or `docs/superpowers/specs/tla/` — the model's `_stateless`/marker language describes the protocol, not this tree's current state.

---

### Task 1: API guard — reject image changes on the v2 update path

**Files:**
- Modify: `pkg/handler/server/client_v2.go` (`validateUpdatedImage`, ~:86-105)
- Test: `pkg/handler/server/client_v2_test.go` (replace `TestServerUpdateV2ValidatesChangedImage`, ~:989-1022)
- Modify: `pkg/handler/server/README.md`

**Interfaces:**
- Consumes: existing test harness helpers `testServerV2`, `testSrvNetworkWithProject`, `newSrvFakeClient`, `aclWithSrvUpdate`, `withPrincipal` (all already in `client_v2_test.go`).
- Produces: `validateUpdatedImage` keeps its exact signature `func (c *ClientV2) validateUpdatedImage(ctx context.Context, network *regionv1.Network, current *regionv1.Server, request *openapi.ServerV2Update) error` so its caller `validateUpdateV2Request` (~:154) is untouched. Error message the integration test (Task 6) greps: `"server image cannot be changed: in-place rebuild is not currently supported"`.

- [ ] **Step 1: Replace the changed-image validation test with a rejection test**

In `pkg/handler/server/client_v2_test.go`, delete `TestServerUpdateV2ValidatesChangedImage` (whole function, ~:989-1022, including its mock provider setup) and add in its place:

```go
func TestServerUpdateV2RejectsImageChange(t *testing.T) {
	t.Parallel()

	const newImageID = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"

	resource := testServerV2(srvServerID)
	network := testSrvNetworkWithProject(srvProjectID)
	c := server.NewClientV2(common.ClientArgs{
		Client:    newSrvFakeClient(t, network, resource).Build(),
		Namespace: srvNamespace,
	})
	ctx := withPrincipal(rbac.NewContext(t.Context(), aclWithSrvUpdate()))
	request := &openapi.ServerV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: resource.Name},
		Spec: openapi.ServerV2Spec{
			FlavorId: resource.Spec.FlavorID,
			ImageId:  idstest.MustParseImageID(newImageID),
		},
	}

	_, err := c.UpdateV2(ctx, idstest.MustParseServerID(resource.Name), request)
	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err))
}
```

(Mirrors `TestServerUpdateV2RejectsFlavorChange` at ~:967. If the deleted test was the only user of imports like `mocktypes`/`mockproviders`, remove the now-unused imports — the compiler will tell you.)

- [ ] **Step 2: Run the new test to verify it fails**

Run: `cd /home/alex.emery/code/uni-brella/uni-region-status-observed && go test ./pkg/handler/server/ -run TestServerUpdateV2RejectsImageChange -count=1 -v`
Expected: FAIL — the current code *validates* a changed image (mock provider missing → a different error than 422, or the test errors on the provider lookup). Either failure mode is fine; the point is it does not pass yet.

- [ ] **Step 3: Implement the guard**

In `pkg/handler/server/client_v2.go`, replace the entire body and doc comment of `validateUpdatedImage` with:

```go
// validateUpdatedImage rejects any image change on the update path. The
// in-place rebuild that acted on image drift has been excised; accepting a
// new image would update the spec with nothing to realize it — a lie at
// rest. Same-image PUTs (clients echoing current state) remain a no-op.
// TEMPORARY: removed when the rebuild re-implementation lands (spec
// 2026-07-31-status-observed-implementation-design.md, §4 stage 3).
func (c *ClientV2) validateUpdatedImage(_ context.Context, _ *regionv1.Network, current *regionv1.Server, request *openapi.ServerV2Update) error {
	if current.Spec.Image != nil && current.Spec.Image.ID == request.Spec.ImageId {
		return nil
	}

	return errors.HTTPUnprocessableContent("server image cannot be changed: in-place rebuild is not currently supported")
}
```

Then grep for `validateServerImageForUpdate` (`grep -rn validateServerImageForUpdate pkg/`) — if `validateUpdatedImage` was its only caller, delete `validateServerImageForUpdate` and any helper *it* alone used (compiler + `make lint` catch stragglers).

- [ ] **Step 4: Run the handler test package**

Run: `go test ./pkg/handler/server/ -count=1`
Expected: PASS — including `TestServerUpdateV2PreservesSSHCertificateAuthority`, which PUTs the *same* image and must still succeed (the same-image no-op is load-bearing: spec §5 obligation 1).

- [ ] **Step 5: Update the handler README**

In `pkg/handler/server/README.md`, find the update-path/image documentation and state the new contract: image is immutable via the API while the rebuild is excised (temporary, points at the spec). Remove or rewrite any sentence describing the update path triggering an in-place rebuild.

- [ ] **Step 6: Commit**

```bash
git add pkg/handler/server/
git commit -m "Reject v2 image changes while the in-place rebuild is excised

Nothing can act on image drift once the rebuild plumbing goes, so
accepting a new image would update the spec with nothing to realize
it. Same-image PUTs remain a no-op. Temporary guard, removed when the
rebuild re-implementation lands (spec 2026-07-31, stage 3)."
```

---

### Task 2: Excise the settlement wake plumbing

**Files:**
- Modify: `pkg/managers/server/manager.go` (delete `serverRebuildSettledUpdate` ~:72-78 and its `predicate.TypedFuncs` entry in `serverPredicate` ~:89-91)
- Modify: `pkg/provisioners/managers/server/provisioner.go` (delete `RebuildSettled` ~:311-341 with its DO-NOT-CHANGE comment; delete `serverParked` ~:298-309 IF it has no other callers)
- Delete: `pkg/provisioners/managers/server/provisioner_settled_test.go`
- Modify: `pkg/managers/server/manager_test.go` (delete `TestRebuildSettledUpdate` ~:112; keep `TestProviderCreateFailureUpdate`)
- Modify: `pkg/managers/server/README.md`, `pkg/provisioners/managers/server/README.md`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `serverPredicate` in `RegisterWatches` becomes a two-way `predicate.Or` (generation-changed + `providerCreateFailureUpdate`). Nothing later relies on rebuild symbols from these packages.

- [ ] **Step 1: Check `serverParked` callers**

Run: `grep -rn "serverParked" pkg/ --include="*.go"`
Expected: only its definition and the call inside `RebuildSettled`. If anything else calls it, keep it and note the caller in the commit message; otherwise it goes in step 2.

- [ ] **Step 2: Delete the plumbing**

- `pkg/managers/server/manager.go`: delete the `serverRebuildSettledUpdate` function and remove the third entry of the `predicate.Or(...)` in `RegisterWatches` so it reads:

```go
	serverPredicate := predicate.Or(
		predicate.TypedGenerationChangedPredicate[*unikornv1.Server]{},
		predicate.TypedFuncs[*unikornv1.Server]{
			UpdateFunc: providerCreateFailureUpdate,
		},
	)
```

- `pkg/provisioners/managers/server/provisioner.go`: delete `RebuildSettled` (function + full doc comment) and `serverParked` (per step 1).
- Delete `pkg/provisioners/managers/server/provisioner_settled_test.go` (its only test is `TestRebuildSettled`).
- `pkg/managers/server/manager_test.go`: delete `TestRebuildSettledUpdate` and any fixtures/imports only it used.

- [ ] **Step 3: Compile and test both packages**

Run: `go build ./... && go test ./pkg/managers/server/ ./pkg/provisioners/managers/server/ -count=1`
Expected: PASS. If `unikornv1core` or another import became unused in `provisioner.go`, remove it.

- [ ] **Step 4: Update the two READMEs**

Remove/rewrite the settlement-wake and `RebuildSettled` sections in `pkg/managers/server/README.md` and the rebuild-protocol sections in `pkg/provisioners/managers/server/README.md`. Where they described why the wake predicate is load-bearing, replace with one line: the rebuild feature is excised pending re-implementation from the machine-checked spec (link `docs/superpowers/specs/2026-07-31-server-rebuild-protocol-design.md`).

- [ ] **Step 5: Commit**

```bash
git add pkg/managers/server/ pkg/provisioners/managers/server/
git commit -m "Excise the rebuild settlement wake plumbing

Deletes RebuildSettled, its DO NOT CHANGE contract, and the watch
predicate arm. The properties those comments argued in prose are now
machine-checked in docs/superpowers/specs/tla; the re-implementation
builds its wake from the settled() level predicate in the spec."
```

---

### Task 3: Excise the monitor-side marker advancement

**Files:**
- Modify: `pkg/providers/internal/openstack/provider.go` (delete `serverRebuildStateRank` ~:2573, `advanceRebuildState` ~:2589, `advanceServerRebuildState` ~:2605-2644; remove the `advanceServerRebuildState(server, openstackServer)` call in `updateServerStateWithClients` ~:3293)
- Delete: `pkg/providers/internal/openstack/rebuild_state_test.go`
- Modify: `pkg/providers/internal/openstack/provisioning_status_test.go` (delete `TestUpdateServerStateWithClientsStampsSucceededForStoppedConvergedRebuild` ~:343-398)
- Modify: `pkg/monitor/health/server/README.md`, `pkg/providers/internal/openstack/README.md`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `updateServerStateWithClients` calls exactly three mutators: `setServerHealthStatus`, `setServerMACAddress`, and the Active/phase path (`setServerActive` via the phase logic). The monitor reads no rebuild state — spec §5 obligation 7's substance.

- [ ] **Step 1: Delete the advancement functions and call site**

In `provider.go`: delete the three functions (each with its doc comment and truth table) and the single call line in `updateServerStateWithClients`. Do NOT touch `setServerHealthStatus`/`convertServerHealthStatus` — the REBUILD→Unknown health mapping and `healthMessageIndeterminate` stay (a foreign/Nova-side rebuild is still an observable provider state).

- [ ] **Step 2: Delete the tests**

Delete `rebuild_state_test.go` entirely (`TestAdvanceServerRebuildState`, `TestAdvanceServerRebuildStateNilMarker`). In `provisioning_status_test.go` delete `TestUpdateServerStateWithClientsStampsSucceededForStoppedConvergedRebuild` and any fixtures only it used.

- [ ] **Step 3: Compile and test**

Run: `go test ./pkg/providers/internal/openstack/ -count=1`
Expected: PASS. (The remaining `TestUpdateServerStateWithClients*` tests cover MAC/phase/Ironic and must keep passing untouched.)

- [ ] **Step 4: Update READMEs**

`pkg/monitor/health/server/README.md`: remove the marker-advancement and single-patch-atomicity contract sections — the monitor now writes health/MAC/phase facts only. `pkg/providers/internal/openstack/README.md`: remove the monitor-advancement half of the rebuild documentation (reconciler half dies in Task 4).

- [ ] **Step 5: Commit**

```bash
git add pkg/providers/internal/openstack/ pkg/monitor/
git commit -m "Excise the monitor's rebuild marker advancement

The monitor no longer reads or writes any rebuild state - the
protocol spec's obligation 7 delivered by deletion. Health, MAC and
phase stamping are unchanged; REBUILD still maps to Unknown health."
```

---

### Task 4: Excise the reconciler-side rebuild pass

**Files:**
- Modify: `pkg/providers/internal/openstack/provider.go` (delete `serverRebuildTaskActive` ~:2646, `markServerRebuildAccepted` ~:2671, `reconcileServerRebuildPark` ~:2693, `submitServerRebuild` ~:2745, `reconcileServerImage` ~:2784, `reconcileServerImageConverged` ~:2844, `reconcileServerImagePending` ~:2887; rewrite the existing-server branch of `reconcileServer` ~:2951-2955; delete `openstackServerImageID` ~:2650 if unused after)
- Modify: `pkg/providers/internal/openstack/export_test.go` (delete the `ReconcileServerImage` wrapper ~:112-114)
- Delete: `pkg/providers/internal/openstack/reconcile_server_image_test.go` (23 tests)
- Modify: `pkg/providers/internal/openstack/provider_test.go` (`TestCreateServerCopyBackPreservesPortAndFloatingIPStatus` ~:1981-2030)
- Modify (maybe): the `ServerInterface` definition + `pkg/providers/internal/openstack/mock/interfaces.go` via `make generate` (step 5)
- Modify: `pkg/providers/internal/openstack/README.md`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `reconcileServer`'s existing-server branch returns the Nova server unchanged. `ServerInterface` may lose `RebuildServer` and the `ServerRebuildOptions` type (step 5's grep decides).

- [ ] **Step 1: Rewrite the existing-server branch, delete the pass**

In `reconcileServer`, replace:

```go
	openstackServer, err := client.GetServer(ctx, server)
	if err == nil {
		log.V(1).Info("server already exists")

		return reconcileServerImage(ctx, client, server, openstackServer)
	}
```

with:

```go
	openstackServer, err := client.GetServer(ctx, server)
	if err == nil {
		log.V(1).Info("server already exists")

		// Image drift is not acted on: the in-place rebuild is excised and the
		// API rejects image changes until the re-implementation lands (spec
		// 2026-07-31-status-observed-implementation-design.md, stage 3).
		return openstackServer, nil
	}
```

Then delete the seven functions listed above (each with its doc comment / P1–P7 pass-order comment). Run `grep -n "openstackServerImageID" pkg/providers/internal/openstack/*.go` — delete it too if the rebuild pass was its only caller.

- [ ] **Step 2: Delete the pass's tests and export**

Delete `reconcile_server_image_test.go` and the `ReconcileServerImage` wrapper in `export_test.go`. Before deleting, run `grep -n "novaRebuildServer\|rebuildOldImageID\|rebuildNewImageID\|requireRebuildAcceptedStamp" pkg/providers/internal/openstack/*_test.go` — any helper/const defined in the deleted file but used by `provider_test.go` (step 3 needs `novaRebuildServer` and the two image-ID consts) moves into `provider_test.go`.

- [ ] **Step 3: Fix the copy-back test**

In `TestCreateServerCopyBackPreservesPortAndFloatingIPStatus`:
- Delete the marker fixture lines:

```go
	// Intent already durable: this pass submits the rebuild.
	server.Status.Rebuild = &regionv1.ServerRebuildStatus{TargetImageID: idstest.MustParseImageID(rebuildNewImageID), State: regionv1.ServerRebuildStateInitiated}
```

- Delete the `compute.EXPECT().RebuildServer(...)` expectation (keep the `GetServer` expectation returning `novaRebuildServer("ACTIVE", rebuildOldImageID)` — an existing server whose image differs from spec now takes no action).
- Delete the part (b) assertions:

```go
	// (b) the rebuild status writes must propagate back to the caller.
	require.NotNil(t, server.Status.Rebuild)
	require.Equal(t, regionv1.ServerRebuildStateRebuilding, server.Status.Rebuild.State)
	requireRebuildAcceptedStamp(t, server)
```

- Trim the function's doc comment: it now documents only (a), the port/FIP copy-back preservation. Keep the (a) assertions exactly as they are.

- [ ] **Step 4: Compile and test**

Run: `go test ./pkg/providers/internal/openstack/ -count=1`
Expected: PASS.

- [ ] **Step 5: Delete `RebuildServer` from the client interface if dead**

Run: `grep -rn "RebuildServer\|ServerRebuildOptions" pkg/ --include="*.go" | grep -v "_test.go\|/mock/"`
If only the `ServerInterface` method declaration and `ServerRebuildOptions` type remain: delete both, then run `make generate` to regenerate `pkg/providers/internal/openstack/mock/interfaces.go`, then re-run step 4's test command. If a non-test caller remains, leave the interface alone and note it in the commit message.

- [ ] **Step 6: Update the README**

`pkg/providers/internal/openstack/README.md`: remove the rebuild pass-order (P1–P7), park, and submission documentation. One replacement line pointing at the protocol spec as the reference for the future re-implementation.

- [ ] **Step 7: Commit**

```bash
git add pkg/providers/internal/openstack/
git commit -m "Excise the reconciler's rebuild pass

Deletes the P1-P7 image reconciliation chain, park, submission and
acceptance stamping. An existing server now reconciles to itself;
image drift is unreachable behind the API guard. The re-implementation
builds from the machine-checked protocol spec's decision table."
```

---

### Task 5: Excise the types, helper, and read-path rewrite; regenerate

**Files:**
- Modify: `pkg/apis/unikorn/v1alpha1/types.go` (delete the `Rebuild` field ~:1195-1203 with its comment; delete `ServerRebuildState`, its four constants, and `ServerRebuildStatus` ~:1213-1246)
- Modify: `pkg/apis/unikorn/v1alpha1/helpers.go` (delete `RebuildPending` with its doc comment, ~:352-366)
- Modify: `pkg/apis/unikorn/v1alpha1/crd_schema_test.go` (delete `TestServerRebuildSchema` ~:62)
- Modify: `pkg/handler/server/client_v2.go` (delete `deriveProvisioningStatus` ~:230-242 and its call `metadata.ProvisioningStatus = deriveProvisioningStatus(in, metadata.ProvisioningStatus)` ~:255)
- Modify: `pkg/handler/server/client_v2_test.go` (delete `TestServerGetV2RebuildPendingReportsProvisioning` ~:2250, `TestServerGetV2RebuildPendingErroredStaysError` ~:2305, `TestServerGetV2RebuildIntentNotAcceptedReportsProvisioning` ~:2335, `TestServerListV2RebuildPendingReportsProvisioning` ~:2363; rename+simplify `TestServerGetV2NoRebuildReportsProvisioned` ~:2277)
- Regenerate: `pkg/apis/unikorn/v1alpha1/zz_generated.deepcopy.go`, `charts/region/crds/region.unikorn-cloud.org_servers.yaml`
- Modify: `pkg/apis/unikorn/v1alpha1/README.md`, `pkg/handler/server/README.md`

**Interfaces:**
- Consumes: Tasks 2–4 must be complete (they delete every code consumer of these types; this task fails to compile otherwise — that failure IS the ordering check).
- Produces: `ServerStatus` without `Rebuild`; v2 `metadata.ProvisioningStatus` served exactly as core's conversion produced it, no rewrite.

- [ ] **Step 1: Delete types, helper, read-path rewrite**

Make the five modifications listed above. For the kept v2 test, rename `TestServerGetV2NoRebuildReportsProvisioned` → `TestServerGetV2ReportsProvisioned` and remove any rebuild-marker setup from its fixture (the body should just create a provisioned server and assert `metadata.provisioningStatus == provisioned`).

- [ ] **Step 2: Compile — expect clean, catch stragglers**

Run: `go build ./... && grep -rn "ServerRebuild\|RebuildPending\|Status.Rebuild" pkg/ --include="*.go"`
Expected: clean build, zero grep hits. Any hit is a consumer Tasks 2–4 missed — delete it the same way before continuing.

- [ ] **Step 3: Regenerate deepcopy and CRDs**

Run: `grep -nE '^\$\(GENDIR\)|^\$\(CRDDIR\)|^generated|^charts/region/crds' Makefile` to confirm the file-target names, then run `make` (the default target rebuilds file targets stale against `pkg/apis/**`). Verify with `git status --short`: expect modified `zz_generated.deepcopy.go` and `charts/region/crds/region.unikorn-cloud.org_servers.yaml` (the `status.rebuild` subtree gone from the chart).

- [ ] **Step 4: Test the touched packages**

Run: `go test ./pkg/apis/... ./pkg/handler/server/ -count=1`
Expected: PASS — `crd_schema_test.go`'s remaining tests validate the regenerated chart; the v2 handler tests pass without the rewrite.

- [ ] **Step 5: Update READMEs**

`pkg/apis/unikorn/v1alpha1/README.md`: remove the rebuild marker/state-machine documentation. `pkg/handler/server/README.md`: rewrite the "provisioned means settled" passage — the uni-compute gate contract still holds, but the rebuild rewrite is gone; note the invariant is trivially true while image changes are rejected (Task 1's guard).

- [ ] **Step 6: Commit**

```bash
git add pkg/apis/ pkg/handler/server/ charts/region/crds/
git commit -m "Excise the rebuild marker types and the v2 provisioning rewrite

Removes ServerRebuildStatus, the four-state enum, RebuildPending and
deriveProvisioningStatus; regenerates deepcopy and the Server CRD
(status.rebuild subtree gone; stored CRs prune on their next status
write). provisioned-means-settled is trivially preserved while the
API rejects image changes."
```

---

### Task 6: Integration suite rework and final sweep

**Files:**
- Modify: `test/api/suites/servers_rebuild_test.go` (delete the two slow rebuild `Describe`s ~:160-263; keep the flavor-422 test and the Nova atomicity probe; add the image-422 test)
- Keep: `test/api/config.go` `ServerRebuildImageID` (the kept probe and the new test use rebuild-adjacent config; verify with grep, delete only if truly unused)
- Modify: `pkg/README.md` if it references the rebuild feature

**Interfaces:**
- Consumes: Task 1's guard error message `"image cannot be changed"`.
- Produces: a passing full pre-commit checklist on a tree with zero rebuild plumbing.

- [ ] **Step 1: Prune and extend the integration suite**

In `test/api/suites/servers_rebuild_test.go`:
- Delete `Describe("Given the server has settled as provisioned", ...)` (the in-place rebuild It, ~:160-205) and `Describe("Given the server has been stopped", ...)` (~:206-263).
- KEEP `Describe("Nova rebuild atomicity probe", ...)` (~:265+) — it probes Nova's accept-time ref semantics directly, which is the evidence base for the model's `RefUpdatesAtAccept` question and stage 3's design. Add a one-line comment above it saying exactly that.
- After the flavor-immutability `Describe` (~:149-159), add its image twin. First check the builder: `grep -n "WithImageID\|WithFlavorID" test/api/*.go test/api/**/*.go`. If `WithImageID` exists:

```go
		Describe("Given the server image is immutable while rebuild is excised", func() {
			It("rejects an image change with an actionable 422", func() {
				update := api.ServerUpdateFromRead(server).WithImageID(uuid.NewString()).Build()

				apiError, err := regionClient.UpdateServerExpectError(ctx, server.Metadata.Id, update, http.StatusUnprocessableEntity)
				Expect(err).NotTo(HaveOccurred())
				Expect(apiError.Error).To(Equal(coreapi.UnprocessableContent))
				Expect(apiError.ErrorDescription).To(ContainSubstring("image cannot be changed"))
			})
		})
```

If `WithImageID` does not exist, build the update with `update := api.ServerUpdateFromRead(server).Build()` followed by `update.Spec.ImageId = regionids.ImageID(uuid.NewString())` (adjust to the actual field type the compiler reports), keeping the same three assertions.

- [ ] **Step 2: Compile the integration and e2e trees**

Run: `go vet -tags integration ./test/... && go vet -tags e2e ./test/...`
Expected: clean — proves the suites compile against the excised tree even though they don't run here.

- [ ] **Step 3: Repo-wide symbol sweep**

Run: `grep -rn "ServerRebuildState\|ServerRebuildStatus\|RebuildPending\|RebuildSettled\|advanceServerRebuildState\|markServerRebuildAccepted\|submitServerRebuild\|reconcileServerImage" --include="*.go" .`
Expected: zero hits. Any hit gets deleted the way its package's task prescribed.

- [ ] **Step 4: Full pre-commit checklist**

Run, in order, each must pass:

```bash
make touch
make license
make validate
make lint
make generate
[[ -z $(git status --porcelain) ]] && echo CLEAN
make test-unit
```

If `git status` is dirty after `make generate`, commit the regenerated files with the fix to whatever produced them — generated code must be checked in.

- [ ] **Step 5: Commit**

```bash
git add test/ pkg/README.md
git commit -m "Prune the rebuild integration suite to the guard and the Nova probe

The in-place rebuild journeys are gone with the feature. Keeps the
flavor-immutability test, adds its image twin against the temporary
guard, and keeps the Nova atomicity probe - it documents the
accept-time ref semantics the re-implementation's model extension
(RefUpdatesAtAccept) needs evidence for."
```

---

## Self-Review (completed)

1. **Spec coverage (stage 1 items)**: types+enum+`RebuildPending` → Task 5; `reconcileServerImage` chain/park/converged/pending/submit/`markServerRebuildAccepted` + shared-message coupling → Task 4 (the message constant survives only in its health-mapping role, per Task 3 step 1); monitor `advanceServerRebuildState`/rank/truth-table → Task 3; `RebuildSettled` + predicate → Task 2; `deriveProvisioningStatus` rewrite → Task 5; temporary API guard → Task 1; behavior-neutrality/CR pruning → Task 5 commit message; README contract → every task, step-level.
2. **Placeholder scan**: the two conditional instructions (Task 4 step 5, Task 6 step 1) branch on a grep the executor runs, with exact code for both branches — no TBDs.
3. **Type consistency**: guard error string in Task 1 == grep target in Task 6; `serverPredicate` shape in Task 2 matches `manager.go`'s actual imports; copy-back test keeps `novaRebuildServer("ACTIVE", rebuildOldImageID)` and Task 4 step 2 moves those helpers before their definition file is deleted.
