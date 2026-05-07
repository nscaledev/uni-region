# Identity

This package is the controller factory for `Identity` reconciliation.

It is structurally standard:

- embeds shared provider initialization
- exposes controller options for the identity provisioner
- watches `Identity` generation changes
- builds the reconciler around
  [`pkg/provisioners/managers/identity`](../../provisioners/managers/identity/README.md)

The resource-specific behaviour lives in the provisioner, not here.
