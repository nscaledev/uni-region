# Packages

## Purpose

This tree contains the region service implementation.

At a high level it splits into six layers:

- API and storage model definition
- cloud-provider abstraction and concrete provider bindings
- request handling and server composition
- controller/provisioner lifecycle management
- polling-based status and telemetry projection
- a small amount of shared client and wiring glue

The useful way to read it is not as a directory tree, but as one system:

- handlers shape and validate the lifecycle graph
- provisioners and managers realize provider-side effects
- reconcile passes project observed provider truth back into status and telemetry
- providers bind the region model to real or simulated clouds
- `Volume` is a Region block storage model: a network-anchored,
  quota-carrying block storage resource. Its deployable controller now drives
  idempotent OpenStack create/delete lifecycle, keeps creation provisioning
  until Cinder reports the backing volume `available`, and releases an
  annotated Identity allocation only after Cinder confirms provider deletion.
  A Cinder error is surfaced through a safe typed provisioning condition. Its
  public v2 Volume lifecycle contract and core CRUD handlers are published;
  creation allocates requested capacity through Identity before persisting the
  Volume. Its persisted model reserves one Server attachment through the
  internal `spec.claimRef`, which the Server handler creates and compensates and
  the Volume controller releases after provider teardown. Before attachment,
  that controller places its canonical per-Volume reference on the Server; it
  removes the reference after teardown and before releasing the claim. Server
  deletion remains blocked while any such reference exists. Server status projects
  detailed attachment progress, while Volume status exposes when the current
  attachment was first confirmed. Its Volume
  provisioner reconciles the backing Volume and claimed Server attachment, then
  projects progress to Server status.
  Its provider capability exposes neutral backing discovery, observed
  size, and lifecycle state. The reconcile pass projects that truth into observed
  size and coarse health without taking over the controller-owned `Available`
  condition. `VolumeStatus.ProvisionedAt` records durable backing-storage
  creation, so provider loss degrades health without triggering replacement
  under the same Region Volume ID.
  OpenStack also supports server attachment behavior.
- `FileStorageSnapshot` is the installable storage contract for project-scoped
  customer Manual Snapshots, with [nested v2 creation, deletion](./handler/storage/README.md#manual-snapshot-lifecycle),
  and [reads](./handler/storage/README.md#manual-snapshot-reads) under their File
  Storage parent. Region records intent. File Storage deletion foreground-cascades
  to blocking snapshots before parent deprovisioning.
- `Server` now carries the internal attach-existing-only block volume intent
  and observed per-volume attachment rows. The provider boundary and OpenStack
  Nova attach/detach implementation exist; the Volume provisioner projects
  attachment progress while the Server handler remains the owner of intent.

## Recommended Reading Order

### API And Contract Model

- [constants](./constants/README.md)
- [apis/unikorn/v1alpha1](./apis/unikorn/v1alpha1/README.md)
- [ids](./ids/README.md)
- [openapi](./openapi/README.md)
- [userdata](./userdata/README.md)

These packages define the shared control vocabulary, the stored Kubernetes
resource model, the typed resource identifiers exposed at the API layer, the
HTTP wire contract, and the cross-service user-data validation contract.

The most important direction here is that `v2` is the intended API shape.
`v1` remains as deprecated compatibility surface and should be migrated away
from as quickly as practical.

### Provider Model

- [providers](./providers/README.md)
- [providers/types](./providers/types/README.md)
- [providers/internal/openstack](./providers/internal/openstack/README.md)
- [providers/internal/kubernetes](./providers/internal/kubernetes/README.md)
- [providers/internal/simulated](./providers/internal/simulated/README.md)

These packages define the mixed provider boundary:

- CRD-backed service resources are still passed through in native region shapes
- non-CRD provider concepts use intermediate provider-neutral types
- concrete providers preserve the linkage between region resources and real
  cloud resources

OpenStack is the real heavyweight implementation. Kubernetes and simulated are
alternative substrates shaped to fit the same broad service model.

### Handler And Server Layer

- [client](./client/README.md)
- [handler](./handler/README.md)
- [server](./server/README.md)

These packages define the application layer:

- direct lookup in a shared namespace rather than namespace indirection
- label- and relationship-derived scope
- `v2` selector-prefiltered listing and principal-context completion
- request-to-storage/provider translation
- platform-defined middleware and server composition

### Controller Lifecycle Layer

- [provisioners](./provisioners/README.md)
- [managers](./managers/README.md)

These packages define how desired state becomes provider-side effects.

Managers are thin controller factories. Provisioners hold the resource-specific
lifecycle logic: waiting for prerequisite identity readiness, maintaining
reference edges, calling providers, and cleaning up allocation/accounting
relationships.

Observation is not a separate layer. A resource whose provider moves underneath
it — `Server` and `Volume` — is reconciled by a polling controller, and each pass
projects the read it decided on into Kubernetes status, logs and telemetry. There
is no second process, and therefore one writer per resource. That is the
architectural admission this platform makes: not all lifecycle truth arrives
through controller watches, so some of it is polled — but it is polled by the
thing that already owns the resource.

## Important Cross-Cutting Themes

### `v2` First

The service is converging on flat `v2` APIs.

Compared with the older nested `v1` model, that means:

- direct resource addressing instead of deep path hierarchy
- org/project context recovered from request fields or dependent resources
- list working sets constrained before RBAC walks
- more handler responsibility for inferred scope and graph validation

`v1` is not an equal architectural citizen. It is deprecated compatibility
surface.

### Shared Namespace, Recovered Scope

Unlike identity, region does not primarily model user-visible scope by mapping
it onto separate Kubernetes namespaces.

Most resources live in one shared namespace. Scope is reconstructed through:

- labels
- owner relationships
- dependent-resource lookup
- RBAC checks over recovered organization/project bindings

That difference is one of the most important things to understand before
reading the handlers.

### Lifecycle DAG

The service behaves like a lifecycle DAG whose edges carry different blocking
and propagation semantics.

Common edge types include:

- owner references
- explicit blocking references
- quota/allocation consistency edges
- hidden service-principal roots
- cross-service propagation bridges

This is the abstraction that ties together handlers, provisioners,
and even command-level consumers outside `pkg`.

### OpenStack Project Scoping

OpenStack is not just a provider backend here. It strongly shapes the service
model.

The important pattern is:

- managed-domain authority provisions user/project scaffolding
- most real cloud resources are then created in the per-identity project
- the OpenStack project becomes the main lookup, isolation, and intended
  accounting boundary

That is why service principals, hidden identity roots, deterministic lookup,
and image/resource visibility rules matter so much throughout this tree.

### Best-Effort Consistency

Much of the service operates over Kubernetes objects plus external provider and
service APIs rather than a single transaction system.

The main consistency tools are:

- optimistic read/modify/write
- ownership and deletion blocking
- saga-based compensation for true multi-operation workflows
- polling where observed truth cannot be trusted to arrive through watches

This is especially visible in:

- [handler](./handler/README.md)
- [provisioners](./provisioners/README.md)

### Sizing The Polling Controllers

A polling controller's cost grows with the resources it polls, not with how
often users change them. These figures were measured with a scale harness that
ran the real controller and Kubernetes API against a fake cloud answering in
20ms a request, on a laptop, with a one-minute poll. Real cores and rows
differ, so treat them as a starting point and watch the pods.

Measured, per 10,000 servers and 10,000 volumes, steady state and in the
minutes after a restart:

| | CPU steady | CPU restart | working set | peak |
|---|---|---|---|---|
| server controller | 1.0 cores | 1.15 cores | 460MB | 700MB |
| volume controller | 0.75 cores | 1.0 cores | 470MB | 660-700MB |

Per 1,000 that is about 75-100m and 40MB a controller, plus about 25MB fixed.

Suggested per 10,000: the server controller requests 1.5 CPU and 768Mi, the
volume controller 1 CPU and 768Mi, both with a 1Gi limit. Set no CPU limit, or
at least 2. Set `GOMEMLIMIT` to about 90% of the memory limit: Go takes
GOMAXPROCS from the cgroup, but not the memory limit, and without it the heap
overshoots. At 2,000 servers a 100Mi limit was OOM-killed; with
`GOMEMLIMIT=85MiB` the same load ran with a peak of 88MB and no restarts, for
about the same CPU. At 100m CPU, 2,000 servers did not finish their first sweep
in 45 minutes: a controller needs about 145m steady and up to 170m after a
restart.

`--max-concurrency` is sized by the cloud's latency, not by CPU. Workers spend a
pass waiting on the cloud, so the number busy is the passes a second times the
pass time, and the pass time is the latency times the calls a pass makes in
series: two for a server and two for a volume. At 100ms and 2,000 servers that
is about 8 busy: 4 workers never caught up, 8 just did, 16 peaked at 12 busy in
steady state and all 16 after a restart. Set it to about twice the figure: about
90 per 10,000 servers at 100ms. The default is the node's core count, not the
pod's limit. More CPU does not reduce the workers needed; it buys headroom for
GC and restarts.

Most of the cost is decoding cloud lists. Reads are kept per project for up
to a minute (see the OpenStack provider's
[Kept Lists](./providers/internal/openstack/README.md#kept-lists) section);
without that the server controller cost six times as much at 500 servers.

## Caveats

- The package graph still contains transitional compatibility debt, especially
  around `v1`, provider-specific historical state, and version-label handling.
- Some of the most important lifecycle edges are not contained entirely within
  `pkg`; for example, cross-service project deletion propagation is implemented
  by [`cmd/unikorn-region-project-consumer`](../cmd/unikorn-region-project-consumer/README.md).
