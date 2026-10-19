# Identity

`pkg/provisioners/managers/identity` provisions and deprovisions cloud-side
identity/project scaffolding for region `Identity` resources.

Distinctive behaviour:

- adds and removes the identity-side project reference edge via
  `identity/pkg/client`
- delegates actual cloud identity creation/deletion to the provider
- propagates provider deletion yields/errors without releasing the identity-service
  project reference; the reconciler retains its finalizer until success.
  See the [OpenStack teardown requirements](../../../providers/internal/openstack/README.md#teardown-qualification-and-recovery).

This is one of the clearest controller-side lifecycle bridges:

- identity service project lifecycle
- region identity root
- provider-side project/user/application-credential state

## Caveats

- This is still tied to the deprecated handler/API identity surface, even though
  the underlying service-principal concept remains important.
