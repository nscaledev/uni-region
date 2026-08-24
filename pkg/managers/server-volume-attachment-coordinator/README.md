# `server-volume-attachment-coordinator`

This custom controller reconciles a Volume key. It materializes the stable
`ServerVolumeAttachment` for every desired `Server.spec.volumes` entry and
arbitrates the singleton `Volume.spec.claimRef`.

It performs no provider calls and owns no attachment status or endpoint
references. Those belong to the attachment lifecycle controller. Keeping the
claim decision at the Volume key prevents two Servers from winning the same
single-attach Volume.
