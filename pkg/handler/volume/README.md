# Volume

`pkg/handler/volume` implements the public v2 Volume lifecycle API.

Volume creation validates the selected Network and VolumeClass, derives Region,
Identity, organization, and project scope from that Network, and persists a
controller-finalized `Volume` CRD owned by the Network with deletion blocking.
Requested size is stored as a binary quantity while the API remains whole-GiB.
Quota admission is not part of this package. A later slice adds create-time
quota admission.

List and get expose project-scoped metadata, immutable Network/class/size, the
standard lifecycle and health projection, and observed size when it is present
in CRD status. Attachment-derived fields are not projected by this package.

Updates replace mutable metadata and tags with optimistic locking while
preserving Network, VolumeClass, size, claims, controller state, and any
future allocation annotation. Delete is idempotent once started and rejects a
Volume with an active attachment claim or resource reference until it is
manually detached.
