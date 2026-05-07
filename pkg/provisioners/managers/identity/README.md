# Identity

`pkg/provisioners/managers/identity` provisions and deprovisions cloud-side
identity/project scaffolding for region `Identity` resources.

Distinctive behaviour:

- adds and removes the identity-side project reference edge via
  `identity/pkg/client`
- delegates actual cloud identity creation/deletion to the provider

This is one of the clearest controller-side lifecycle bridges:

- identity service project lifecycle
- region identity root
- provider-side project/user/application-credential state

## Caveats

- This is still tied to the deprecated handler/API identity surface, even though
  the underlying service-principal concept remains important.
