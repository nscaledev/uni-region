# `cmd/unikorn-region-project-consumer`

## Purpose

This command is a cross-service lifecycle-edge bridge.

It watches `Project` lifecycle events from identity and propagates project
deletion into region root resources that are scoped to that project by label.

Right now it registers cascading-delete consumers for:

- `Identity`
- `FileStorage`
- `SSHCertificateAuthority`

So this command does not implement a new deletion model by itself. It adds one
specific edge type to the platform lifecycle DAG by stitching together two
existing local models:

- identity's project lifecycle and deletion semantics
- region's own root-resource cascade semantics

Without this bridge, those two systems would be locally correct but globally
disconnected.

## What It Adds

Identity already knows when a project is being deleted.

Region handlers and controllers already know how to cascade deletion once a
region root resource is told to die.

This command adds the missing cross-repo propagation edge:

1. observe project deletion in identity
2. discover region root resources labeled with that project
3. delete those roots in the shared region namespace
4. let region's owner refs, finalizers, and controllers take over from there

That preserves the platform-level invariant that deleting a project should
retire its region-owned project roots too, even though they live in a different
service and are not isolated by per-project namespaces.

## Invariants And Guard Rails

- Identity remains the source of truth for project lifecycle.
- This command is label-driven: it only finds region roots that are correctly
  labeled with `coreconstants.ProjectLabel`.
- It should only target true region root resources. Descendant cleanup is
  expected to happen through region's own ownership and reconciliation logic
  after the root is deleted.
- The command operates in the shared region namespace, which is why label-based
  discovery is necessary in the first place.

## Caveats

- Correctness depends on the root set being complete. If a project-scoped root
  resource is not registered here, project deletion in identity will not
  automatically trigger its teardown in region.
- Correctness also depends on downstream region root deletion working properly.
  This command initiates teardown; it does not replace region's own cascading
  semantics.
- Because it is simple, it would be easy to undersell. Architecturally it is
  one of the explicit pieces that makes cross-service tenancy deletion behave
  like one platform rather than adjacent services.

## TODO

- Keep the list of consumed region project-root resource kinds in sync with the
  real set of project-scoped roots in region.
- Revisit whether any additional region root resources should participate in the
  project-deletion bridge as the API evolves.

## Cross-Package Context

- [../../pkg/handler/README.md](../../pkg/handler/README.md) documents the
  region-side deletion and ownership semantics this command relies on after it
  deletes a root
- [`../../../identity/pkg/handler/README.md`](../../../identity/pkg/handler/README.md)
  documents the identity-side project lifecycle this command listens to
