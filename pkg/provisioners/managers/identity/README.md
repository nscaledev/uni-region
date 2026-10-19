# Identity

`pkg/provisioners/managers/identity` provisions and deprovisions cloud-side
identity/project scaffolding for region `Identity` resources.

Distinctive behaviour:

- adds and removes the identity-side project reference edge via
  `identity/pkg/client`
- delegates actual cloud identity creation/deletion to the provider
- propagates provider deletion yield/errors before removing the identity-service
  project reference; only provider success releases that reference

This is one of the clearest controller-side lifecycle bridges:

- identity service project lifecycle
- region identity root
- provider-side project/user/application-credential state

OpenStack deletion takes a fresh unfiltered Nova project inventory before any
credential removal. Any surviving server, including `ERROR` or one without a
Region CR, keeps identity deletion pending. Inventory failures retain cleanup
ownership. This protects credentials while Nova finishes networking cleanup;
it relies on the [provider qualification and recovery contract](../../../providers/internal/openstack/README.md#teardown-qualification-and-recovery).
The reconciler retains the Identity's own finalizer until deprovision succeeds.

## Caveats

- This is still tied to the deprecated handler/API identity surface, even though
  the underlying service-principal concept remains important.
