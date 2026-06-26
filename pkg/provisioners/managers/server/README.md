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
  servers that have never been successfully provisioned
- clears or updates consumed-resource references during reprovision and teardown

This is the clearest controller-side expression of the lifecycle DAG model:

- network/security-group/SSH-CA edges are explicit and blocking
- provider-side server lifecycle is delegated
- cloud-init augmentation translates higher-level SSH CA semantics into machine
  bootstrap material

## Caveats

- Reference maintenance here is easy to underappreciate, but it is central to
  keeping server deletion and dependent-resource blocking semantics correct.
- Provider create retry state is stored on `Server.status`; changing retry
  behaviour must preserve the invariant that transient provider create failures
  return `ErrYield` until the configured attempt limit is reached.
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
