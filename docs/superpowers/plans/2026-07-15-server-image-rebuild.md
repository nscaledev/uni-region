# Server Image Rebuild Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a v2 server image change converge through one safe, in-place
Nova rebuild while preserving typed resource IDs, keeping initial-create retry
semantics separate, and giving the user an explicit way to retry an accepted
rebuild that later fails.

**Architecture:** Keep the existing controller and provider lifecycle. A v2
update writes the desired typed image ID to `Server.spec`; the existing
generation watch invokes the server provisioner; the OpenStack provider's
existing-server branch compares the desired image with Nova's observed image
and runs a small rebuild state machine. Nova is authoritative for live state.
`Server.status.rebuild` stores only the target and accepted-attempt bookkeeping
needed to distinguish a failed controller-issued rebuild from an unrelated
runtime `ERROR`. The initial automatic rebuild gets one accepted attempt.
Transient failures that prove Nova did not accept the request may requeue, but
an accepted rebuild that finishes in `ERROR` is parked as user-action-required.
A narrow v2 retry operation increments an internal spec generation, waking the
same state machine without introducing a second source for the desired image.

**Tech Stack:** Go, controller-runtime, Kubernetes CRDs/status, OpenAPI,
Gophercloud Nova v2, GoMock.

**Reference implementation:** Commit `bbd7515` on
`alexemery/inst-920-rebased`. Use it as a source for tests and state-machine
ideas only; do not cherry-pick it wholesale because current `main` uses typed
IDs and has moved ahead in server/provider code.

---

## Behavioural Contract

- Changing `imageId` recreates the server's root disk and may destroy all data
  on that disk.
- The Nova server UUID, attached ports, fixed/floating IP relationships,
  attached data volumes, flavor, and placement are retained by rebuild.
- Initial create recovery remains unchanged: a provider-accepted create that
  reaches `ERROR` before first launch is deleted and recreated up to the
  existing configured limit.
- Rebuild is only considered for a server that has previously launched.
- The controller automatically makes at most one Nova-accepted rebuild attempt
  for a `(target image, rebuild generation)` pair.
- A `409 Conflict` or another response proving Nova did not accept rebuild is
  transient and may requeue without consuming the accepted attempt.
- An ambiguous transport error is resolved by observing Nova before another
  request is issued.
- An accepted rebuild that later reaches `ERROR` is not automatically repeated.
  The user may choose another image, request one explicit retry, or delete and
  recreate the server.
- An unrelated `ERROR` must never authorize rebuild.

## File Structure

**Modify:**

- `pkg/apis/unikorn/v1alpha1/types.go` — typed rebuild status and internal
  rebuild-generation field.
- `pkg/apis/unikorn/v1alpha1/README.md` — document rebuild state ownership.
- `pkg/apis/unikorn/v1alpha1/zz_generated.deepcopy.go` — generated only.
- `charts/region/crds/region.unikorn-cloud.org_servers.yaml` — generated only.
- `pkg/handler/server/client_v2.go` — image-change validation, immutable flavor,
  preservation of the internal generation, and retry operation.
- `pkg/handler/server/client_v2_test.go` — client validation and retry tests.
- `pkg/handler/server/validation.go` — shared typed image/flavor validation.
- `pkg/handler/server/validation_test.go` — compatibility tests.
- `pkg/handler/server/README.md` — destructive update and retry contract.
- `pkg/handler/handler_v2_server.go` — retry HTTP handler.
- `pkg/handler/handler_v2_server_test.go` — retry endpoint tests.
- `pkg/openapi/server.spec.yaml` — destructive update documentation and retry
  route.
- `pkg/openapi/{types,schema,client,router}.go` — generated only.
- `pkg/providers/internal/openstack/interfaces.go` — rebuild compute method.
- `pkg/providers/internal/openstack/mock/interfaces.go` — generated only.
- `pkg/providers/internal/openstack/compute.go` — traced Nova rebuild action.
- `pkg/providers/internal/openstack/provider.go` — image state machine and
  `REBUILD` status mapping.
- `pkg/providers/internal/openstack/reconcile_server_image_test.go` — focused
  state-machine tests.
- `pkg/providers/internal/openstack/compute_test.go` — rebuild request test if
  the existing compute-client test seam supports it.
- `pkg/providers/internal/openstack/README.md` — observed-state and failure
  semantics.
- `pkg/provisioners/managers/server/README.md` — explicit distinction between
  create retry and rebuild.

**Do not modify:**

- `ProviderCreateFailures`, `ProviderCreateRetrying`, or
  `ProviderCreateFailure` semantics.
- The provider-neutral `types.Provider` interface solely to expose rebuild.
  Rebuild remains an OpenStack implementation detail of idempotent
  `CreateServer` reconciliation.
- Generated files by hand.

---

### Task 1: Add typed rebuild bookkeeping to the Server CRD

**Files:**

- Modify: `pkg/apis/unikorn/v1alpha1/types.go`
- Modify: `pkg/apis/unikorn/v1alpha1/crd_schema_test.go`
- Generate: `pkg/apis/unikorn/v1alpha1/zz_generated.deepcopy.go`
- Generate: `charts/region/crds/region.unikorn-cloud.org_servers.yaml`

**Rationale:** Rebuild retry safety needs durable intent, but live operation
state remains provider-owned. A nested status object keeps rebuild fields
cohesive. `RebuildGeneration` is an internal command generation used only to
re-arm the same desired image after an accepted failure; because it is in spec,
incrementing it triggers the existing generation watch.

- [ ] **Step 1: Add a failing CRD schema test**

Extend `crd_schema_test.go` to assert that:

- `spec.rebuildGeneration` is an integer with minimum `0`.
- `status.rebuild.targetImageID` is a UUID-formatted string.
- `status.rebuild.generation` and `status.rebuild.acceptedAttempts` are
  non-negative integers.

- [ ] **Step 2: Run the focused test and confirm it fails**

```bash
go test ./pkg/apis/unikorn/v1alpha1 -run 'Test.*CRD.*Schema'
```

Expected: failure because the rebuild fields are absent from the generated CRD.

- [ ] **Step 3: Add the typed API fields**

Add the equivalent of:

```go
type ServerRebuildStatus struct {
    TargetImageID   regionids.ImageID `json:"targetImageID"`
    Generation      int64             `json:"generation"`
    AcceptedAttempts int32            `json:"acceptedAttempts,omitempty"`
}
```

Add `RebuildGeneration int64` to `ServerSpec`, with a minimum-zero kubebuilder
validation marker and documentation stating that it is controlled by the Region
API retry operation rather than normal update generation.

Add `Rebuild *ServerRebuildStatus` to `ServerStatus`.

Use the repository formatter's preferred alignment; the snippet is structural,
not formatting-prescriptive.

- [ ] **Step 4: Generate API artifacts**

```bash
make generate
```

- [ ] **Step 5: Run the focused schema and package tests**

```bash
go test ./pkg/apis/unikorn/v1alpha1/...
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add pkg/apis/unikorn/v1alpha1/types.go \
  pkg/apis/unikorn/v1alpha1/crd_schema_test.go \
  pkg/apis/unikorn/v1alpha1/zz_generated.deepcopy.go \
  charts/region/crds/region.unikorn-cloud.org_servers.yaml
git commit -m "feat(server): add rebuild operation status"
```

---

### Task 2: Validate image changes and forbid silent flavor drift

**Files:**

- Create: `pkg/handler/server/validation.go`
- Create: `pkg/handler/server/validation_test.go`
- Modify: `pkg/handler/server/client_v2.go`
- Modify: `pkg/handler/server/client_v2_test.go`

**Rationale:** A destructive asynchronous operation should not start with an
image that is missing, unavailable, too large, or incompatible with the existing
flavor. Flavor changes are not part of this work and are currently persisted but
ignored, so reject them explicitly.

- [ ] **Step 1: Port failing compatibility unit tests**

Adapt the useful table tests from commit `bbd7515` to typed IDs. Cover:

- ready image and compatible flavor;
- missing or invisible image returns not found without becoming an existence
  oracle;
- non-ready image returns unprocessable content;
- explicit architecture mismatch;
- unknown architecture on either side remains compatible;
- image larger than flavor root disk;
- baremetal/virtualized mismatch;
- unknown virtualization remains compatible;
- missing flavor returns not found.

- [ ] **Step 2: Run the validation tests and confirm they fail to compile**

```bash
go test ./pkg/handler/server -run 'Test.*(Image|Architecture|Virtualization|Flavor).*Validation'
```

Expected: failure because the shared validation helpers do not exist.

- [ ] **Step 3: Implement typed shared validation**

Use:

```go
provider.GetImage(ctx, organizationID, imageID)
provider.Flavors(ctx)
```

Keep `identityids.OrganizationID`, `regionids.ImageID`, and
`regionids.FlavorID` typed through the helper boundary. Treat missing metadata
as unknown/compatible; reject only explicit incompatibility.

- [ ] **Step 4: Add failing v2 update tests**

Cover:

- unchanged image skips provider image validation;
- changed image performs full validation;
- nil legacy image gaining an image performs validation;
- changed flavor returns HTTP 422;
- normal updates preserve `Spec.RebuildGeneration`.

- [ ] **Step 5: Implement the update guards**

In `UpdateV2`:

1. Reject a requested flavor different from `current.Spec.FlavorID`.
2. Resolve the existing network/provider.
3. Validate only when the persisted image would change.
4. After `generateV2`, copy `current.Spec.RebuildGeneration` into the required
   and updated spec so an ordinary PUT cannot clear retry intent.

Apply the shared image validation on create as well so create and rebuild do not
have different compatibility contracts.

- [ ] **Step 6: Run focused tests**

```bash
go test ./pkg/handler/server/...
```

Expected: pass.

- [ ] **Step 7: Commit**

```bash
git add pkg/handler/server/validation.go \
  pkg/handler/server/validation_test.go \
  pkg/handler/server/client_v2.go \
  pkg/handler/server/client_v2_test.go
git commit -m "feat(server): validate rebuild image updates"
```

---

### Task 3: Add the traced Nova rebuild primitive

**Files:**

- Modify: `pkg/providers/internal/openstack/interfaces.go`
- Generate: `pkg/providers/internal/openstack/mock/interfaces.go`
- Modify: `pkg/providers/internal/openstack/compute.go`
- Modify: `pkg/providers/internal/openstack/compute_test.go` when supported by
  the existing test seam

**Rationale:** Keep the cloud operation small and testable. The state machine
belongs above this adapter; the adapter only submits Nova's rebuild action.

- [ ] **Step 1: Add a failing compute-client test**

Assert that rebuilding server `server-id` to a typed image produces:

```json
{"rebuild":{"imageRef":"<image UUID>"}}
```

and uses `POST /servers/server-id/action`.

If the current compute test seam cannot inspect requests without substantial
new infrastructure, omit this adapter test and rely on the state-machine mock
contract plus Gophercloud's request tests; record that choice in the commit.

- [ ] **Step 2: Extend `ServerInterface`**

Add:

```go
RebuildServer(ctx context.Context, serverID string, imageID regionids.ImageID) (*servers.Server, error)
```

- [ ] **Step 3: Implement `ComputeClient.RebuildServer`**

Use `servers.RebuildOpts{ImageRef: imageID.String()}` and the existing tracing
pattern. Include server ID, target image ID, and action `rebuild` as span
attributes.

- [ ] **Step 4: Regenerate mocks**

```bash
make generate
```

- [ ] **Step 5: Run focused tests**

```bash
go test ./pkg/providers/internal/openstack -run 'Test.*Rebuild'
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add pkg/providers/internal/openstack/interfaces.go \
  pkg/providers/internal/openstack/mock/interfaces.go \
  pkg/providers/internal/openstack/compute.go \
  pkg/providers/internal/openstack/compute_test.go
git commit -m "feat(openstack): add server rebuild action"
```

---

### Task 4: Implement the one-attempt image rebuild state machine

**Files:**

- Create: `pkg/providers/internal/openstack/reconcile_server_image_test.go`
- Modify: `pkg/providers/internal/openstack/provider.go`
- Modify: `pkg/providers/internal/openstack/provisioning_status_test.go`
- Modify: `pkg/providers/internal/openstack/healthstatus_test.go` if present on
  the implementation branch; otherwise keep health tests in the closest current
  provider test file

**Rationale:** This is the core behavior. Tests must pin every destructive
decision before implementation.

- [ ] **Step 1: Port the state-machine fixtures with typed IDs**

Adapt `reconcileserverimage_test.go` from `bbd7515`. Use the current
`idstest.MustParseImageID` helpers and current provider fixtures.

- [ ] **Step 2: Add failing tests for non-destructive paths**

Cover:

- no desired image: no action;
- Nova image equals desired and status is `ACTIVE`: no action and stale rebuild
  marker cleared;
- Nova image equals desired and status is `SHUTOFF`: same behavior while phase
  remains stopped;
- Nova reports `REBUILD`: no new action, health reports provisioning, phase is
  `Building`, and reconciliation yields;
- Nova reports unrelated `ERROR` without a matching marker: no rebuild;
- server has not previously launched: image mismatch does not enter rebuild and
  remains eligible for the existing create-failure machinery only.

- [ ] **Step 3: Add failing tests for initial rebuild submission**

Cover:

- observed image differs from desired on a previously launched server;
- `RebuildServer` is called exactly once with the typed target;
- status marker is written before returning;
- `AcceptedAttempts` becomes `1` only after Nova accepts the action;
- reconciliation returns `ErrYield` after acceptance.

- [ ] **Step 4: Add failing tests for request failures**

Cover:

- Nova `409 Conflict`: return `ErrYield`, retain target intent, do not increment
  `AcceptedAttempts`;
- definite validation/not-found rejection: surface an error without consuming
  an accepted attempt;
- ambiguous transport error: preserve target intent and yield; on the next
  observation, `REBUILD` or desired-image state prevents a duplicate call;
- if the next authoritative observation still shows the old image in a stable
  rebuild-eligible state, allow resubmission because Nova did not accept the
  first request.

- [ ] **Step 5: Add failing tests for accepted asynchronous failure**

Cover:

- Nova `ERROR`, desired image, matching marker, accepted attempt `1`: return
  `provisioners.UserActionRequired(...)`, retain marker, and do not call rebuild;
- Nova `ERROR`, old image, matching marker, accepted attempt `1`: same result;
- Nova `ERROR`, matching image but marker for another generation or target: no
  rebuild because the error is unrelated to current intent;
- a different desired image resets target bookkeeping and permits one fresh
  accepted attempt;
- the same target with a higher `Spec.RebuildGeneration` resets bookkeeping and
  permits one explicit retry.

- [ ] **Step 6: Run focused tests and confirm failure**

```bash
go test ./pkg/providers/internal/openstack -run 'TestReconcileServerImage|Test.*Rebuild.*Status'
```

Expected: failures because the state machine and `REBUILD` mapping are absent.

- [ ] **Step 7: Implement small helpers**

Keep the implementation decomposed around these responsibilities:

- extract Nova's current image ID safely;
- test whether the status marker matches `(desired image, rebuild generation)`;
- begin/reset intent for a new target or explicit generation;
- clear intent after observed success;
- issue one rebuild request;
- reconcile observed state.

Do not use `status.conditions` as proof that a rebuild was issued. Conditions are
derived and may be rewritten. The matching rebuild marker only authorizes
classification of a failed rebuild; if it is missing, fail closed.

- [ ] **Step 8: Wire the state machine into existing-server reconciliation**

In `reconcileServer`, replace the current immediate return after successful
`GetServer` with `reconcileServerImage`.

When `serverForCreate` is a deep copy due to managed user-data augmentation,
copy `Status.Rebuild` back to the caller's server before returning, including on
`ErrYield` or user-action-required. Otherwise the manager cannot persist the
marker.

- [ ] **Step 9: Map Nova `REBUILD` visibly**

Update health and phase conversion so:

- health reason is `Provisioning`, not generic `Degraded`;
- phase is `Building` even though Nova may still report running power state.

- [ ] **Step 10: Run focused provider tests**

```bash
go test ./pkg/providers/internal/openstack/...
```

Expected: pass, including existing provider-create retry tests.

- [ ] **Step 11: Run server provisioner regression tests**

```bash
go test ./pkg/provisioners/managers/server/...
```

Expected: existing initial-create delete/recreate behavior still passes
unchanged.

- [ ] **Step 12: Commit**

```bash
git add pkg/providers/internal/openstack/provider.go \
  pkg/providers/internal/openstack/reconcile_server_image_test.go \
  pkg/providers/internal/openstack/provisioning_status_test.go \
  pkg/providers/internal/openstack/healthstatus_test.go
git commit -m "feat(openstack): reconcile server image with one rebuild"
```

If `healthstatus_test.go` does not exist on the working branch, omit it from the
`git add` command.

---

### Task 5: Add an explicit retry operation for an accepted failed rebuild

**Files:**

- Modify: `pkg/openapi/server.spec.yaml`
- Generate: `pkg/openapi/types.go`
- Generate: `pkg/openapi/schema.go`
- Generate: `pkg/openapi/client.go`
- Generate: `pkg/openapi/router.go`
- Modify: `pkg/handler/handler_v2_server.go`
- Modify: `pkg/handler/handler_v2_server_test.go`
- Modify: `pkg/handler/server/client_v2.go`
- Modify: `pkg/handler/server/client_v2_test.go`

**Rationale:** After an accepted failure, the desired image has already been
persisted, so repeating an identical PUT does not bump Kubernetes generation.
The retry operation must re-arm the same state machine without taking another
image value.

- [ ] **Step 1: Add failing client tests for retry eligibility**

Add `RetryRebuildV2` tests covering:

- missing server: not found;
- no update permission: forbidden;
- deleting server: invalid request;
- no matching failed rebuild marker: conflict or unprocessable content;
- rebuild currently in progress: conflict;
- matching failed rebuild: atomically increment `Spec.RebuildGeneration` using
  optimistic-lock patch;
- retry does not alter desired image or any other spec field.

The client may use the persisted `Healthy=Errored` condition plus a non-nil
matching rebuild marker as the API-edge eligibility check. The provider still
revalidates authoritative Nova state during reconciliation.

- [ ] **Step 2: Implement `RetryRebuildV2`**

Follow the existing start/stop/reboot client structure for lookup and RBAC, but
patch the Kubernetes resource rather than calling Nova directly. Increment the
generation with overflow protection. Return after the patch; the existing
generation-change watch drives the provider operation.

- [ ] **Step 3: Add the OpenAPI route**

Add:

```text
POST /api/v2/servers/{serverID}/rebuild/retry
```

The route has no request body and returns `202`. Its description must say:

- it retries the server's existing desired `imageId`;
- it is only valid after a failed Region-issued rebuild;
- it recreates the root disk and is destructive;
- it does not recover a failed compute host.

- [ ] **Step 4: Generate OpenAPI artifacts**

```bash
make generate
```

- [ ] **Step 5: Add and implement handler tests**

Follow the existing start/stop/reboot handler pattern. Verify successful `202`
and provider/client error conversion.

- [ ] **Step 6: Run focused tests**

```bash
go test ./pkg/handler/server/... ./pkg/handler/... -run 'Test.*Rebuild.*Retry'
```

Expected: pass.

- [ ] **Step 7: Commit**

```bash
git add pkg/openapi/server.spec.yaml \
  pkg/openapi/types.go pkg/openapi/schema.go pkg/openapi/client.go pkg/openapi/router.go \
  pkg/handler/handler_v2_server.go pkg/handler/handler_v2_server_test.go \
  pkg/handler/server/client_v2.go pkg/handler/server/client_v2_test.go
git commit -m "feat(server): add failed rebuild retry operation"
```

---

### Task 6: Preserve effective create-time guest configuration

**Files:**

- Modify: `pkg/providers/internal/openstack/interfaces.go`
- Generate: `pkg/providers/internal/openstack/mock/interfaces.go`
- Modify: `pkg/providers/internal/openstack/compute.go`
- Modify: `pkg/providers/internal/openstack/provider.go`
- Modify: `pkg/providers/internal/openstack/reconcile_server_image_test.go`

**Rationale:** A rebuilt server must remain a valid Uni-managed server. Image
replacement must not accidentally drop managed cloud-init/SSH CA augmentation,
key selection, or system metadata.

- [ ] **Step 1: Add failing preservation tests**

Cover servers using:

- `identityKeypair` SSH injection;
- SSH CA managed cloud-init augmentation;
- `none` SSH injection;
- user-supplied user data without managed augmentation;
- system metadata and user tags.

Assert that rebuild retains or explicitly supplies the effective values that a
fresh create would use. Ports, floating IPs, and attached volumes are not
recreated by Region during rebuild.

- [ ] **Step 2: Select the Nova microversion contract explicitly**

Nova supports rebuild `user_data` from microversion 2.57. Inspect the existing
compute client microversion configuration. If it is already at least 2.57,
extend the local rebuild request type/adapter to send the effective user data
and key name. If not, do not silently raise the global microversion: document
the compatibility impact and add a focused client configuration change with
tests.

Gophercloud v2.10.0's base `servers.RebuildOpts` does not expose all newer
fields. Use a small local options type implementing `ToServerRebuildMap` when
needed; do not fork or patch generated dependency code.

- [ ] **Step 3: Implement preservation through explicit rebuild options**

Build options from the same effective `serverForCreate` input used by initial
create. Preserve system metadata ordering so user tags cannot overwrite
platform linkage keys.

- [ ] **Step 4: Regenerate mocks and run tests**

```bash
make generate
go test ./pkg/providers/internal/openstack/... ./pkg/provisioners/managers/server/...
```

Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add pkg/providers/internal/openstack/interfaces.go \
  pkg/providers/internal/openstack/mock/interfaces.go \
  pkg/providers/internal/openstack/compute.go \
  pkg/providers/internal/openstack/provider.go \
  pkg/providers/internal/openstack/reconcile_server_image_test.go
git commit -m "fix(server): preserve managed configuration on rebuild"
```

---

### Task 7: Document the lifecycle contract

**Files:**

- Modify: `pkg/apis/unikorn/v1alpha1/README.md`
- Modify: `pkg/handler/server/README.md`
- Modify: `pkg/providers/internal/openstack/README.md`
- Modify: `pkg/provisioners/managers/server/README.md`

- [ ] **Step 1: Document field ownership and authority**

State that:

- spec image and rebuild generation are desired/user intent;
- Nova image/status are authoritative live state;
- rebuild status is safety bookkeeping, not proof of provider reality;
- missing bookkeeping fails closed.

- [ ] **Step 2: Document destructive API semantics**

State prominently that image changes and explicit retry recreate the root disk.
List what Nova preserves and clarify that rebuild stays on the same compute host;
evacuation is a separate operator workflow.

- [ ] **Step 3: Document create versus rebuild recovery**

Include a compact table:

| Initial create failure | Image rebuild failure |
|---|---|
| Server never launched | Server previously launched |
| Delete/recreate, bounded by existing flag | One accepted attempt per target/generation |
| `ProviderCreateFailures` | `Status.Rebuild` |
| Exhaustion is operator-terminal | Failure requires user retry/new image or replacement |

- [ ] **Step 4: Check documentation links**

```bash
make validate
```

Expected: pass with no broken package documentation links.

- [ ] **Step 5: Commit**

```bash
git add pkg/apis/unikorn/v1alpha1/README.md \
  pkg/handler/server/README.md \
  pkg/providers/internal/openstack/README.md \
  pkg/provisioners/managers/server/README.md
git commit -m "docs(server): define image rebuild lifecycle"
```

---

### Task 8: Full validation and regression review

**Files:** None intentionally modified beyond formatter/generator output.

- [ ] **Step 1: Run the required repository gates**

```bash
make touch
make license
make validate
make lint
make generate
git status --porcelain
make test-unit
```

Expected:

- all commands pass;
- `make generate` produces no uncommitted generated drift after generated files
  have been committed;
- only the planned implementation and pre-existing local artifacts appear in
  `git status`.

- [ ] **Step 2: Run focused race-sensitive packages**

```bash
go test -race ./pkg/providers/internal/openstack ./pkg/provisioners/managers/server ./pkg/monitor/health/server
```

Expected: pass.

- [ ] **Step 3: Review safety invariants manually**

Confirm from the final diff that:

- no path reuses or resets `ProviderCreateFailures` for rebuild;
- no rebuild is issued solely because `Healthy=Errored`;
- no missing status field authorizes rebuild;
- `REBUILD` never causes another rebuild request;
- accepted asynchronous failure never automatically retries;
- a changed target or explicit generation is required to re-arm;
- user data/SSH access remains equivalent to create;
- generated files were not edited manually.

- [ ] **Step 4: Review the complete change**

```bash
git diff origin/main...HEAD --stat
git diff origin/main...HEAD
```

Expected: no unrelated volume, DevStack, or create-retry behavior changes.

---

## Integration Follow-up

Unit tests are the merge gate for this plan. Before production rollout, exercise
the following against DevStack using the repository's documented integration
workflow:

1. Create a server on image A and wait for Running.
2. Record Nova UUID, port ID, fixed IP, floating IP, host, and attached volume
   IDs.
3. Update to image B.
4. Observe API phase `Building` while Nova reports `REBUILD`.
5. Confirm Running on image B with the recorded infrastructure identity intact.
6. Confirm managed SSH access/cloud-init still works.
7. Induce a rebuild failure, confirm there is no automatic second accepted
   attempt, invoke `/rebuild/retry`, and confirm exactly one new attempt.
8. Put the compute host out of service and confirm retry does not masquerade as
   evacuation.

Do not automate destructive failure injection in the standard API suite unless
the DevStack fixture can isolate and clean it reliably.

## Self-Review

- The plan uses the current controller generation watch and provider
  reconciliation path rather than adding another controller.
- Typed IDs remain typed through CRD, handler, validation, and compute adapter
  boundaries.
- Initial-create delete/recreate behavior is explicitly unchanged and covered by
  regression tests.
- Accepted rebuild failure has a concrete user recovery path without silent
  automatic destructive retries.
- Provider observation, rather than derived Kubernetes conditions, controls
  destructive decisions.
- The only new command-like state is a monotonically increasing internal spec
  generation, used so retry participates in the existing Kubernetes watch and
  optimistic concurrency model.
- Documentation and generated artifacts are included in the same change.
- There are no placeholder steps such as "handle errors" or "add tests" without
  explicit cases and expected results.
