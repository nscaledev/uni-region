# Server

`pkg/provisioners/managers/server` is the richest manager provisioner in the tree.

Distinctive behaviour:

- maintains explicit reference edges from a server to consumed networks,
  security groups, and optional SSH certificate authority
- blocks on identity readiness before provider create/delete
- blocks provider create while any configured `providerCreateGates` remain
  unsatisfied
- augments provider create options with managed cloud-init parts for SSH CA use
- clears or updates consumed-resource references during reprovision and teardown

This is the clearest controller-side expression of the lifecycle DAG model:

- network/security-group/SSH-CA edges are explicit and blocking
- provider-create gates are pre-provider-create coordination points; they delay
  provider create but are not deletion blockers
- provider-side server lifecycle is delegated
- cloud-init augmentation translates higher-level SSH CA semantics into machine
  bootstrap material

## Caveats

- Reference maintenance here is easy to underappreciate, but it is central to
  keeping server deletion and dependent-resource blocking semantics correct.
- The provisioner currently trusts the API not to supply repeated network or
  security-group IDs, even though the code still carries explicit TODOs to
  reject duplicates.

## TODO

- Reject repeated network IDs in server specifications at the API boundary
  rather than relying on provisioner-side reference maintenance to behave
  sensibly.
- Reject repeated security-group IDs in server specifications for the same
  reason.
