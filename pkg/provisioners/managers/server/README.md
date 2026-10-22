# Server

`pkg/provisioners/managers/server` is the richest manager provisioner in the tree.

Distinctive behaviour:

- maintains explicit reference edges from a server to consumed networks,
  security groups, and optional SSH certificate authority
- blocks on identity readiness before provider create; delegates delete
  unconditionally so the provider can handle unrealized identities idempotently
- blocks provider create while any configured `providerCreateGates` remain
  unsatisfied. The wait is a typed `provisioners.Yield` naming the outstanding
  gates on the `Available` condition: gates are satisfied by a separate service,
  so this wait can legitimately be long, and a bare sentinel would make it
  indistinguishable from every other wait on the create path
- preflight checks may still yield inside the provider, after other
  validation succeeds; those checks are transient and are not recorded
  as lifecycle transitions
- augments provider create options with managed cloud-init parts for SSH CA use
- retries provider-accepted create attempts that later land in provider error,
  deleting the failed provider server before a bounded re-attempt, but only for
  servers that have never been successfully provisioned; once the attempt cap is
  reached it aborts terminally rather than retrying further
- clears or updates consumed-resource references during reprovision and teardown

Create recovery and image rebuild recovery deliberately use different state:

| Initial create failure | Image rebuild failure |
|---|---|
| Server never launched | Server previously launched |
| Delete/recreate, bounded by the existing flag | Nothing to recover |
| `ProviderCreateFailures` | No persisted state |
| Exhaustion is operator-terminal | The failure surfaces on the monitor's lifecycle axis |
| Edge wake: `ProviderCreateFailure` via `providerCreateFailureUpdate` | No wake needed: `ErrYield` requeues on a timer |

The image reconcile lives in the OpenStack provider's existing-server path and
leaves the create retry counter and predicate code untouched. It decides only from
the fresh provider read; see the provider README for the row-by-row pass order.

Settlement for the create path is watch-predicate-driven (`pkg/managers/server`)
over a helper exported from this package: `providerCreateFailureUpdate` over
`ProviderCreateFailure` wakes the reconciler to run the bounded delete-and-retry.
That helper is genuinely shared — the provisioner makes the delete-and-retry
decision through the same function the watch predicate fires on, so the trigger and
the action cannot drift.

This is the clearest controller-side expression of the lifecycle DAG model:

- network/security-group/SSH-CA edges are explicit and blocking
- provider-create gates are pre-provider-create coordination points; they delay
  provider create but are not deletion blockers
- provider-side server lifecycle is delegated
- cloud-init augmentation translates higher-level SSH CA semantics into machine
  bootstrap material

Deprovisioning retains consumed-resource references and the Server's finalizer
until provider deletion succeeds. During failed-create retry, deletion yields
also preserve `ProviderCreateRetrying`, attempt count, runtime state and satisfied
create gates across restart, without emitting readiness events. Cleanup success
resumes the existing absence check/reset before gates can admit another attempt.

## Managed cloud-init augmentation

A server with an SSH certificate authority gets one managed part appended to
its user-data in a MIME multipart, even when it has no user-data of its own:
a `text/x-shellscript` named
`00-unikorn-ssh-certificate-authority` that writes the CA key and an
`sshd_config.d` drop-in, then reloads sshd.

Why a shell script, not cloud-config:

- cloud-config parts are merged, and cloud-init's default merge replaces
  lists, so a cloud-config part wiped the customer's `runcmd` and
  `write_files` (INST-1542). A `merge_how` rule does not save it: with
  `dict(no_replace)`, a customer key left empty (`runcmd:`) keeps its null and
  drops ours.
- Scripts are never merged. cloud-init runs them once per instance through
  `scripts_user`, the same module and time as `runcmd`. A reboot does not
  re-run it, so operators may remove the CA or edit sshd and it stays that way.
  A rebuild from a fresh image runs it again; so does a new instance-id
  (e.g. a new server made from a snapshot). A rebuild from a snapshot of the
  same server keeps the instance-id and cloud-init's record, so it does not.
- Its name sorts before the customer's `scripts_user` scripts (`runcmd`,
  `part-NNN`), so it runs first among them. cloud-init marks `scripts_user`
  as done before running any script, so if a customer script that ran first
  rebooted, ours would never run. Customer per-boot, per-instance and
  per-once scripts run in earlier modules whatever their name: one that
  reboots once delays ours by a boot; one that reboots every boot or never
  ends stops ours, as it stops the rest of their boot.
- Cost: it runs in cloud-init's final stage, after sshd has started (the old
  `write_files` ran before), so CA logins work only once first boot finishes.
  A boothook would run earlier, but from inside cloud-init's init stage, which
  systemd orders before sshd: restarting sshd from there can deadlock boot.

Customer user-data must reach cloud-init exactly as sent:

- A single payload is labelled `text/x-not-multipart`, so cloud-init detects
  its type itself. We never choose a type for the customer. It is
  quoted-printable in binary mode, so every byte, line endings included,
  survives: unencoded, cloud-init reads it as Latin-1 and corrupts any
  non-ASCII text, losing the whole cloud-config. Mostly-ASCII text grows a
  little (base64 would add a third), which matters near the provider's
  user-data size limit.
- MIME user-data is split into its top-level parts, copied raw
  (`NextRawPart`); a MIME message that is not multipart is one part. Decoding
  quoted-printable and writing it back changed the bytes and could break all
  user-data. Like cloud-init, we treat user-data as MIME only if
  `mime-version:` is in its first 4096 bytes and, as Python's email parser
  requires, its first line is a header. If the first line is blank instead,
  the parser drops it, and so do we.
- Stored MIME user-data that Go cannot parse (the API rejects it now) is
  wrapped whole rather than failing, so the server still reconciles.

Validation at the API (`ValidateUserData`, `ValidateManagedUserData`) accepts
what cloud-init's own detection accepts (longest prefix first, case
insensitive, leading whitespace ignored), and rejects `#part-handler`
(unstable in cloud-init) where used openly: as the payload or as a top-level
part. A part's type is read as cloud-init reads it: the declared type, sniffed
from the body only for `text/plain`, `text/x-not-multipart` and
`text/x-shellscript` (a missing or broken header counts as `text/plain`).
Multipart without `MIME-Version` is rejected, since cloud-init ignores it, and
so is user-data that is not UTF-8, which cloud-init's handlers cannot use.
Rejection is at the API only; the provisioner passes stored user-data
through so existing servers still reconcile.

Known gaps:

- A part-handler buried in gzip, a transfer encoding, a nested multipart, an
  archive or an `#include` is not rejected. It can only harm the customer's
  own server, e.g. by taking over our part.
- A customer part named `00-unikorn-ssh-certificate-authority` is overwritten
  by ours, and one named to sort before it runs first.
- Stored multipart without `MIME-Version` on a CA server (accepted before)
  is now wrapped whole, so on a rebuild or recreate cloud-init ignores it, as
  it always did without a CA.
- Go's multipart reader takes the line ending of the first boundary for all
  of them; Python accepts any. Mixed CRLF and LF boundaries split differently.
- We always send `multipart/mixed`. A customer `multipart/digest` whose parts
  have no `Content-Type` is read differently with a CA.
- A customer may set their own `TrustedUserCAKeys` (sshd takes the first value
  it reads) or drop `scripts_user` from cloud-init's module lists; both are
  their call.

## Cloud-init tests

`make test-cloud-init` runs the tests tagged `cloudinit` against real
cloud-init in an image built from `testdata/cloudinit` (Ubuntu 24.04 amd64, exact
package versions installed from a dated archive snapshot, so the build does not
break when the live archive moves on; bumping means moving the snapshot and the
versions together). They check what cloud-init does with our output, never its
shape:

- Boot tests run cloud-init's four stages in a container, once with the
  customer's user-data alone and once with ours added. Each input has a
  hard-coded expected outcome for the first boot, so two equally broken boots
  cannot pass; then markers, files across the filesystem, status, warnings and
  failed stages must match, and `sshd -T` must show the CA. A reboot clears
  `/run` as a real one does.
- Fast tests run cloud-init's Python on payloads: detection parity with
  cloud-init's own prefix table, part-handler rejection, and that every
  customer part reaches a cloud-init handler unchanged.

Limits: a container is not a VM (no systemd; `systemctl` and `service` are
shims that log calls), NoCloud stands in for OpenStack, and only one
cloud-init version is tested.

## Transition Emission

A pass reports what it observed changing by diffing the status it read against
the status it wrote. `Provision` snapshots the server before anything can write
to it and emits from a `defer`, so a parking or yielding pass reports its
transition too.

The snapshot must be a copy. Aliasing the server puts the provider's writes on
both sides of the diff, and every transition is silently swallowed — no error,
no log, just a stream that goes quiet.

This is why the emission could not wait for the monitor's deletion. The monitor
detects edges the same way, by diffing its own read against its own projection,
so whichever writer moves a field first owns the edge. Once the reconcile pass
projects, the monitor's diff comes up empty and its emission stops — and for the
duration histograms that loss is permanent per server, because they fire only on
the nil-to-set transition of a Nova timestamp and each server has exactly one.

One event, one record. Only an `Active` change is reported, to
`provisioninglog.StreamLifecycle`, which core documents as the lifecycle stream.

`Healthy` is deliberately not reported. Both conditions are derived from the same
provider read in the same pass, so a health line sat alongside the lifecycle one
saying the same thing: a server that stops produces `Active=Stopped` *and*
`Healthy=Degraded`, and the second carries no fact the first does not. The
monitor emitted both and this package briefly copied it; observed on a real
instance, the pair was pure duplication.

`Healthy` only makes sense for a cluster; a single server's state is the `Active`
condition. There is a `TODO: move this` on `setServerHealthStatus`.

The duration histograms record on the first arrival at `Running` from any earlier
state. The lifecycle path is Pending → Building → Running for VMs and Pending →
Queued → Building → Running for baremetal, so a strict Pending → Running
predicate would miss every observation. Each server contributes at most one
observation of each per persisted status, keyed off the nil-to-set transition of
the timestamp being measured rather than off the state change, so a stop/start
cycle does not double count.

It is not yet exactly-once. The emission runs inside `Provision`, before core
persists the status, so a pass whose status write does not land -- an optimistic
lock conflict, a missing RBAC verb, the process dying in between -- emits a
record and observes a duration that the next pass, reading the same unchanged
status, emits and observes again. core's own rule is to emit only once the change
is persisted, which needs a hook this package does not have. Until it does, a
lost status write costs a duplicate rather than a silence, which is the better
failure of the two. A timestamp predating the resource
(clock skew between the controller and Nova) is logged and dropped.

Metric label names — the region and flavour display names — are resolved from the
provider only when an observation is actually recorded, which is once in a
server's life. Resolving them per pass would put two provider reads on every
reconcile to label a metric that almost never fires.

There is no fleet gauge. Counting servers by state is an aggregate over every
server, which a per-resource reconcile cannot compute; the state is on the CR, so
that aggregation belongs to whatever scrapes them.

## Caveats

- Reference maintenance here is easy to underappreciate, but it is central to
  keeping server deletion and dependent-resource blocking semantics correct.
- Provider create retry state is stored on `Server.status.providerCreateFailures`.
  Transient provider create failures return `ErrYield` (a fixed-interval requeue)
  until the configured attempt cap is reached. At the cap the provisioner returns
  the core `provisioners.Terminal` disposition, so the reconciler parks the server
  (writes `Errored`, stops requeuing) instead of looping forever on a failure that
  cannot self-heal — the bare error it used to return was requeued every yield
  interval indefinitely, starving the workqueue. The counter is tested against the
  prospective attempt and clamped to the cap, so it settles at the cap and cannot
  drift on re-reconcile or controller restart (an already-drifted counter heals
  back down on its next pass). Recovery is deliberately out of band: the terminal
  state is sticky until an operator resets `providerCreateFailures`, which re-arms
  the retry on the next reconcile. Changing retry behaviour must preserve these
  invariants.
- The delete-and-retry decision lives in the single `ProviderCreateFailure`
  predicate, shared with the controller watch predicate
  (`pkg/managers/server`) so the trigger and the action cannot drift. It fails
  closed: a rebuild destroys data, so any signal that the server has ever booted
  blocks it. In steady state the load-bearing guard is `launchedAt` (mirrored
  from Nova `launched_at`, which Nova sets at first boot and never clears).
  `Server.status.provisionedAt` is a durable, write-once copy of that same Nova
  signal that the retry reset never clears; it closes the one window `launchedAt`
  alone cannot — a launched server whose `launchedAt` is wiped by an in-flight
  retry reset, or a re-reconcile against a flaky provider. A reconciler-owned
  `Available`/Provisioned condition would be unsuitable for this: it is
  re-derived every reconcile and legitimately flips to `Errored`/`Provisioning`
  on a controller restart against a flaky provider — exactly when a rebuild would
  be catastrophic. The post-launch phases are retained as further defence in
  depth so losing any single status field cannot re-arm the rebuild path.
  Existing servers predating the latch backfill it on the next poll once booted
  and are covered by the `launchedAt` backstop until then.
- `Server.status.macAddress` is projected from the provider read, once the
  server reaches `ACTIVE` — see
  [`pkg/providers/internal/openstack`](../../../providers/internal/openstack/README.md).
  It is not recorded at port-create time: that value is the ephemeral Neutron MAC
  for baremetal, which Ironic later rebinds to the real NIC MAC. The retry reset
  deliberately leaves it intact (like `provisionedAt`) so it never flickers to
  unset; a stale value self-heals on the next observation.
- Provider create retries also emit Kubernetes events and structured logs on
  retry start, retry readiness after delete, and retry exhaustion; avoid
  per-reconcile emissions while deletion is still converging.
- The provisioner currently trusts the API not to supply repeated network or
  security-group IDs, even though the code still carries explicit TODOs to
  reject duplicates.

## TODO

- Reject repeated network IDs in server specifications at the API boundary
  rather than relying on provisioner-side reference maintenance to behave
  sensibly.
- Reject repeated security-group IDs in server specifications for the same
  reason.
