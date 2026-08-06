# Volume

This package is the controller factory for `Volume` reconciliation.

It registers a watch for Region `Volume` generation changes and deletion
timestamp transitions, loads the Region scheme and provider registry, and delegates lifecycle behavior to
[`pkg/provisioners/managers/volume`](../../provisioners/managers/volume/README.md).
The shared core reconciler owns finalizer and lifecycle-condition handling.
