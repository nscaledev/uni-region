# Server teardown qualification

This is the release evidence checklist for
[ORC-553](https://linear.app/nscale-workspace/issue/ORC-553/deleting-a-vpc-during-placement-teardown-leaves-neutron-ports-orphaned).
The [provider contract](./README.md#teardown-qualification-and-recovery) defines
the supported boundary. Deployment qualification is **pending**; automated HTTP
fixtures do not establish Nova/Ironic timing or Kubernetes GC ordering.

## Automated evidence

- Server deletion yields after accepted Nova DELETE, while subsequent reads
  still find the server, and across provider reconstruction. Existing BUILD/
  spawning and REBUILD/rebuild_spawning holds remain covered.
- Lookup rejects UNKNOWN/minimal rows, ambiguous exact names, missing/null
  collections, bodyless HTTP 204, empty pages with continuation and explicit
  next links without a usable target. Provider errors retain cleanup.
- After Nova absence, floating-IP deletion precedes port deletion. Repeated
  cleanup and concurrent-delete 404s are tolerated; 401/403/409/5xx retain cleanup.
- Identity teardown reads unfiltered `limit=250` pages before destructive effects.
  ACTIVE, ERROR, deleting and UNKNOWN servers block, including unrelated names
  with no Region CR. Failed/invalid/cancelled inventory and later-page errors
  retain credentials. Reconstructed providers proceed only after empty inventory.
- Public-provider deprovisioning retains references until Nova and Neutron
  cleanup succeed. Provisioner tests preserve retry counts, runtime state and
  create gates during pending deletes across persistence and reconstruction.

## Deployment evidence required before rollout

Use a disposable placement/VPC in an isolated real OpenStack environment and
supported fault injection. Do not interrupt shared production services or change
provider configuration without reviewing its impact.

- [ ] Record Region commit/release, OpenStack/Nova/Ironic/Neutron versions,
  relevant configuration on every replica, provider IDs and UTC timestamps.
  Retain redacted requests and logs; exclude tokens, passwords and secrets.
- [ ] Confirm compute microversion **2.90**,
  `[api] list_records_by_skipping_down_cells = False` on every Nova API replica,
  and `reclaim_instance_interval = 0` consistently on API/compute services.
- [ ] With a relevant cell unavailable, exercise Region's exact name-filtered
  `/servers/detail?name=...` lookup and unfiltered
  `/servers/detail?limit=250` inventory, following every pagination link. Both
  must error or expose an unknown record that prevents cleanup. Successful
  empty/truncated results fail qualification, even with the required settings.
- [ ] Verify normal Nova deletion stays discoverable until its Neutron teardown
  finishes. Soft deletion or early disappearance fails qualification.
- [ ] Capture the unpatched ordering: placement deletion → Ironic `available` →
  delayed Nova networking cleanup → VPC deletion → revoked credentials/401.
- [ ] Repeat with the patch while holding Nova network cleanup. Request VPC
  deletion; verify Server/finalizers and owning Network/Identity remain pending
  and tenant user/project still authenticate. VPC API refusal due to references
  also provides valid protection.
- [ ] Release the delay; observe Nova teardown, floating-IP/port cleanup,
  dependent finalizer removal, then identity cleanup. Verify a replacement
  placement succeeds and Nova emits no credential-related 401.
- [ ] Repeat with a controller restart during pending deletion, transient
  Nova/Neutron errors and the qualified down-cell case. Verify recovery without
  force-removing finalizers.
- [ ] Strand a Nova ERROR server with its Region CR absent. Identity deletion
  must block and identify the remaining provider resources. After separately
  authorized operator cleanup, reconciliation must finish.
- [ ] Link the redacted deployment report here and in ORC-553. Roll out only to
  configurations that pass; keep rollout and ticket closure blocked on failure
  and design the missing authoritative provider check.

Nova documents [down-cell omissions under filters and pagination](https://docs.openstack.org/api-guide/compute/down_cells.html)
and [soft deletion](https://docs.openstack.org/nova/2026.2/admin/soft-delete-shadow-tables.html).
Check the deployed release's [configuration reference](https://docs.openstack.org/nova/2026.1/configuration/config.html)
as well as actual responses; pagination alone does not prove completeness.

## Accepted limits

[INST-1414](https://linear.app/nscale-workspace/issue/INST-1414/verify-region-cleanup-and-late-create-guarantees-for-member-drain)
remains open for remote quiescence, late/timed-out creates and rebuilds, durable
incarnation correlation and workloads represented only in Ironic. Inventory is
a point-in-time read, not a create fence. INST-1419/Reservation and Fleet must
not infer Drained or release holds from Region 404, Ironic `available`, or a
missing-Nova annotation. No Reservation/Fleet changes are included.

Existing orphans require separate recovery. A crash after Keystone user deletion
but before project/CR deletion is pre-existing liveness debt: tenant
reauthentication can fail on retry. Track restart-safe identity teardown
separately; the pending-delete restart tests do not cover that later phase.
