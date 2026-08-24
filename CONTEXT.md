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

**Attachment reconciliation**:
The controller-managed process that realizes one Server's attachment intent for
one Volume. It has no separate persisted relationship resource.
_Avoid_: ServerVolumeAttachment, attachment object

**Selected claim**:
The Volume claim whose Server is permitted to affect provider attachment state.
_Avoid_: Selected attachment, winning attachment, active claim

**Orphaned attachment**:
A provider attachment whose Volume remains attached after its Server can no longer be found through the provider.
_Avoid_: Detached volume, stale status

**Attachment observation**:
The latest provider-reported relationship between a Volume and its intended Server. It is evidence used for status and reconciliation, not attachment intent or a Volume claim.
_Avoid_: Attachment intent, selected attachment
