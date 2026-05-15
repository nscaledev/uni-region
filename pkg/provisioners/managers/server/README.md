# Server

`pkg/provisioners/managers/server` is the richest manager provisioner in the tree.

Distinctive behaviour:

- maintains explicit reference edges from a server to consumed networks,
  security groups, and optional SSH certificate authority
- blocks on identity readiness before provider create/delete
- augments provider create options with managed cloud-init parts for SSH CA use
- clears or updates consumed-resource references during reprovision and teardown

This is the clearest controller-side expression of the lifecycle DAG model:

- network, security-group, and SSH-CA references are held while the Server's
  current desired spec consumes them; the optional SSH-CA reference is released
  during Deprovision so deletion of an in-use CA remains blocked
- when a Server is updated to a replacement SSH CA, the provisioner adds the
  new reference and removes the same Server reference from stale CAs in the
  project so the previous CA can be deleted once unused
- provider-side server lifecycle is delegated
- cloud-init augmentation translates higher-level SSH CA semantics into machine
  bootstrap material

## Caveats

- Reference maintenance here is easy to underappreciate, but it is central to
  keeping server deletion and dependent-resource blocking semantics correct.
- SSH CA deletion is blocked while any Server still references it; once unused,
  deleting the CA removes the control-plane record for future use but does not
  revoke trust already written into guests by cloud-init.
- The provisioner currently trusts the API not to supply repeated network or
  security-group IDs, even though the code still carries explicit TODOs to
  reject duplicates.

## TODO

- Reject repeated network IDs in server specifications at the API boundary
  rather than relying on provisioner-side reference maintenance to behave
  sensibly.
- Reject repeated security-group IDs in server specifications for the same
  reason.
