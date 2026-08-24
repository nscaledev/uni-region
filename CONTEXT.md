# Region

The Region context manages provider-neutral infrastructure resources and their
relationships within a cloud region.

## Block storage

**Volume**:
A persistent block-storage resource whose lifecycle is independent of the Server that uses it.

**Volume claim**:
An exclusive reservation that binds a Volume to the resource permitted to use it.
_Avoid_: Attachment, provider attachment

**Attachment intent**:
A Server's request to connect an existing Volume.
_Avoid_: Volume claim

**ServerVolumeAttachment**:
The lifecycle relationship connecting one Volume to one Server.
_Avoid_: VolumeAttachment, attachment guard

**Selected attachment**:
The ServerVolumeAttachment whose Server holds the Volume claim and is therefore permitted to affect provider state.
_Avoid_: Winning attachment, active claim

**Orphaned attachment**:
A provider attachment whose Volume remains attached after its Server can no longer be found through the provider.
_Avoid_: Detached volume, stale status

**Attachment observation**:
The latest provider-reported relationship between a Volume and its intended Server. It is evidence used for status and reconciliation, not attachment intent or a Volume claim.
_Avoid_: Attachment intent, selected attachment
