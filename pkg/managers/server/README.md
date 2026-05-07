# Server

This package is the controller factory for `Server` reconciliation.

It is structurally standard, but it fronts the richest provisioner in the tree:
[`pkg/provisioners/managers/server`](../../provisioners/managers/server/README.md),
which maintains explicit resource-reference edges and SSH CA cloud-init
augmentation.
