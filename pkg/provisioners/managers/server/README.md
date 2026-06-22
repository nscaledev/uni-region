# Server

`pkg/provisioners/managers/server` is the richest manager provisioner in the tree.

Distinctive behaviour:

- maintains explicit reference edges from a server to consumed networks,
  security groups, and optional SSH certificate authority
- blocks on identity readiness before provider create/delete
- augments provider create options with managed cloud-init parts for SSH CA use
- retries provider-accepted create attempts that later land in provider error,
  deleting the failed provider server before a bounded re-attempt
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
