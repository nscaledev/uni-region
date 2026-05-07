# Security Group

`pkg/provisioners/managers/security-group` is the straightforward security-group
provisioner.

Distinctive behaviour:

- waits for identity readiness
- delegates create/delete to the provider

Compared with siblings, it has very little controller-side policy of its own.
That is the expected shape for a well-scoped provisioner whose interesting
semantics already live in the handler/resource graph.
