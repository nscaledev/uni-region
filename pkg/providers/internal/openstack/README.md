# pkg/providers/internal/openstack

## Intention

`pkg/providers/internal/openstack` is the real cloud provider implementation
for OpenStack-backed regions.

It does not merely wrap the OpenStack SDK. It is the package that translates
the region service's storage model, tenancy model, metadata conventions, and
lifecycle rules into concrete OpenStack operations across identity, compute,
image, network, security group, load balancer, quota, and block storage
surfaces.

The most important philosophy in this package is the trust and scoping model:

- region-level `manager` authority is used only to provision and manage users
  and projects inside a managed Keystone domain
- once that scaffolding exists, most OpenStack operations deliberately context
  switch into the specific project provisioned for one Unikorn identity
- that OpenStack project then becomes the practical mapping, isolation, and
  accounting boundary between Unikorn resources and real cloud resources

That model is what makes it realistic for multiple regions or deployments to
share one underlying cloud while still limiting blast radius. It is also what
makes backchannel accounting and billing integration plausible, because the
project scope becomes the place where cloud resource usage can be tied back to a
specific Unikorn identity and its descendants.

The most important architectural rule is that this package prefers deterministic
lookup against OpenStack over maintaining broad mirrored OpenStack state in
Kubernetes. In older designs, dedicated `Openstack*` CRDs were used to persist
more provider-side state locally. That drifted from reality and introduced race
conditions. The current direction is:

- service-native CRDs remain the primary control objects
- OpenStack remains the source of truth for cloud-side resources where they can
  be re-found deterministically
- only the provider state that still cannot be reconstructed safely or
  sufficiently remains persisted locally, most notably `OpenstackIdentity`

This package therefore owns the mapping between:

- region-native CRDs and OpenStack resources
- service labels, tags, and metadata conventions
- per-identity delegated cloud credentials
- compensating local mechanisms where OpenStack is not sufficient on its own,
  such as image caching and provider-network VLAN allocation

## Links

- [../../../apis/unikorn/v1alpha1](../../../apis/unikorn/v1alpha1/README.md)
- [../../types](../../types/README.md)
- [../allocation/vlan](../allocation/vlan/README.md)
- [./ADMIN.md](./ADMIN.md)

`pkg/apis/unikorn/v1alpha1` defines the service-native resources and the
remaining persisted provider-state records this package consumes. `pkg/providers/types`
defines the provider-neutral contract this package implements. `pkg/providers/allocation/vlan`
covers the local VLAN allocator used when provider networks need segmentation IDs.
`ADMIN.md` keeps the human operator setup guidance for preparing an OpenStack
region.

## OpenStack Region Registration

An OpenStack-backed region should be registered with `hack/openstack/configure`
and `hack/openstack/register-region`, rather than by hand-creating the Keystone
domain, project, user, Kubernetes Secret, and `Region` manifest. That flow keeps
operator setup aligned with this package's scoping model: region-level provider
credentials are used to manage provider-domain scaffolding and discover region
inventory, while workload operations still context-switch into per-identity
OpenStack projects.

The full operator procedure lives in [./ADMIN.md](./ADMIN.md).

## Invariants And Guard Rails

- This package implements the full `types.Provider` contract for OpenStack
  regions.
- Provider construction has an explicit bootstrap/runtime split:
  - bootstrap uses uncached Kubernetes reads to assemble OpenStack service
    clients before controller-manager caches exist
  - runtime operation switches back to the normal Kubernetes client and refreshes
    derived OpenStack client state when region configuration or credentials
    change
- OpenStack access is intentionally scoped through different credential modes:
  - region-level service credentials bootstrap privileged service clients and
    managed-domain scaffolding
  - per-identity credentials are used for most project-scoped operations
  - some operations deliberately bind privileged credentials to a service
    principal's project when manager-level powers are required
- `OpenstackIdentity` is the remaining persisted provider-state anchor. It
  currently stores the secret-bearing user/project/application-credential and
  bootstrap state needed to operate on behalf of a region `Identity`.
- Identity deletion treats user-scoped compute cleanup as best effort when the
  recorded service principal cannot authenticate. The region-level identity
  cleanup still runs so identities that failed part-way through provisioning do
  not pin finalizers indefinitely.
- The package relies heavily on deterministic naming and metadata conventions to
  re-find cloud-side resources. This is a convention-heavy contract, not magic:
  - identity-scoped resources use fixed generated names
  - network lookups rely on deterministic names
  - server metadata is written deliberately as both a control-plane lookup aid
    and an in-guest linkage surface exposed through the metadata service
  - legacy camelCase server metadata keys remain frozen for backwards
    compatibility while newer namespaced keys provide the upgrade path
- Flavor export is a hybrid model: OpenStack discovers the flavor inventory, but
  region configuration can enrich or override user-facing flavor metadata such
  as architecture, baremetal status, and GPU semantics.
- Image handling is a first-class contract surface here:
  - OpenStack image properties are validated against a schema
  - public images can additionally be signature-verified
  - image properties are translated into provider-neutral OS, package, GPU,
    ownership, virtualization, and tag metadata
  - an optional refresh-ahead cache exists because raw image API latency is too
    expensive to expose directly to every caller
- Quota and role behaviour are not purely discovered from OpenStack defaults.
  The package assumes and applies a managed-role model, including default role
  names such as `manager`, `member`, and `load-balancer_member`, unless region
  configuration overrides parts of that behaviour.
- Network, security group, and server resources are re-found in OpenStack by
  deterministic lookup rather than relying on mirrored `OpenstackNetwork`,
  `OpenstackSecurityGroup`, or `OpenstackServer` CRDs as authoritative state.
- Some OpenStack list APIs are not safe to treat as exact lookup, notably
  server, network, and Octavia load-balancer `name` filters:
  - `name` filters behave like prefix or regular-expression matches rather than
    strict equality
  - this package therefore re-checks exact names after listing to avoid aliasing
    and false matches
- Provider networks that require VLAN segmentation use the local VLAN allocator
  because OpenStack does not allocate those IDs for us.

## Octavia Load Balancers

OpenStack load balancers are reconciled through Octavia in the service
principal's project. The region `LoadBalancer` CRD is still the desired-state
root, while Octavia remains the cloud-side source of truth for the realized
topology.

The provider reconciles the full topology:

- the Octavia load balancer and VIP
- listeners, pools, members, and optional health monitors
- the optional public floating IP attached to the Octavia-owned VIP port

Cloud-side lookup uses deterministic names:

- load balancer: `lb-{loadBalancer}`
- listener: `lb-{loadBalancer}-{listener}-listener`
- pool: `lb-{loadBalancer}-{listener}-pool`
- health monitor: `lb-{loadBalancer}-{listener}-monitor`

Those names are not just cosmetic. They are the linkage contract that lets the
provider re-find and converge existing Octavia resources without mirrored
provider-state CRDs. Octavia list filters are fuzzy in the same way as other
OpenStack name filters, so the client always post-filters returned resources by
exact name and treats duplicate exact matches as consistency errors.

Octavia provisioning status controls the reconcile outcome:

- `ACTIVE` allows the provider to continue reconciling the next part of the
  topology
- `PENDING_CREATE`, `PENDING_UPDATE`, and `PENDING_DELETE` yield the controller
  so the next pass can observe settled state
- any other state is treated as a consistency error because the provider cannot
  safely infer a valid next action

Mutable topology is converged in place where Octavia permits it:

- listener allowed CIDRs
- listener default-pool linkage
- TCP listener idle timeouts
- pool members
- health-monitor thresholds
- orphaned listeners, pools, and monitors whose deterministic names are no
  longer implied by the current spec

Other fields are intentionally blocked before they reach this provider. The
handler keeps existing listener protocol and port immutable, and it blocks
`proxyProtocolV2` drift for an existing listener name because that changes the
derived Octavia pool protocol, which Octavia does not allow to be updated in
place.

There are a few Octavia-specific constraints worth preserving:

- UDP listeners do not support idle timeouts or Proxy Protocol v2.
- UDP health checks use Octavia's UDP connect monitor type.
- TCP pools use Octavia `PROXYV2` only when `proxyProtocolV2` is enabled; the
  load-balancer client pins microversion `2.22` so that protocol is available.
- Floating IP cleanup runs before cascade-deleting the load balancer because the
  cascade removes the VIP port that otherwise anchors the floating IP lookup.
- Delete remains idempotent for resources that failed before Octavia state was
  recorded locally. Missing Octavia endpoints or incomplete service-principal
  state must not keep those never-realized `LoadBalancer` resources stuck on
  finalizers.

## Caveats

- This package is the convergence point of a large amount of platform policy,
  provider behaviour, and historical baggage. Its size reflects real behaviour,
  not just poor code hygiene.
- Deterministic lookup is the preferred direction, but the package still lives
  in a mixed world:
  - some cloud-side state is derived live from OpenStack
  - some transitional compatibility fields still exist in repo-native CRDs
  - `OpenstackIdentity` still persists state that the service would ideally stop
    owning over time
- Deterministic lookup is cleaner than mirrored CRDs, but it is still sensitive
  to convention drift. Renaming generated resources, changing metadata keys, or
  casually altering project-scoping assumptions can break the linkage between
  Unikorn resources, what OpenStack stores, and what users can see from inside
  provisioned servers.
- `OpenstackIdentity` should not be treated as permanently special. Its current
  survival is largely driven by implicit side effects and secret-bearing
  service-owned state that the architecture should work to remove:
  - ephemeral SSH key generation and download
  - implicit server-group creation
  - persisted service-principal/user/project/application-credential data
- Exposing application credentials to higher layers is current operational
  reality, not the desired end state. The package's scoping model helps contain
  blast radius today, while the wider platform works toward removing that
  exposure entirely.
- If the wider API moves toward explicit SSH certificate authority use, explicit
  server-group resources, and less implicit provider-side identity scaffolding,
  deleting `OpenstackIdentity` becomes more realistic.
- Image metadata translation is powerful but fragile. This package currently
  depends on OpenStack image properties carrying a large amount of semantic
  information correctly.
- Image query, get, create, delete, and snapshot flows are tightly coupled to
  the image cache path. When caching is disabled, large parts of the higher
  image contract are effectively unavailable rather than merely slower.
- The image query layer still contains its own comment admitting that some logic
  now operates on generic types and probably should not live here long term.
- Some older assumptions still leak through in status fields and helper paths,
  especially where compatibility with older API or storage shapes is still being
  carried.

## TODO

- Delete the remaining mirror-state OpenStack CRD usage paths entirely:
  `OpenstackNetwork`, `OpenstackSecurityGroup`, and `OpenstackServer` should not
  survive as authoritative provider-state patterns.
- Continue shrinking the reasons `OpenstackIdentity` must exist:
  - remove service-handled private SSH key material in favour of explicit SSH
    certificate trust
  - stop relying on implicit server-group provisioning
  - move toward explicit API shapes where reconstructable state does not need to
    be persisted here
- Revisit image-query and image-metadata logic that now operates on
  provider-neutral types but still lives in this package because of historical
  coupling.
- Remove remaining compatibility writes and reads that depend on transitional
  CRD status shapes as those fields disappear from the wider system.

## Cross-Package Context

- [../../types](../../types/README.md) defines the neutral provider contract and
  intermediate types this package must satisfy
- [../../../apis/unikorn/v1alpha1](../../../apis/unikorn/v1alpha1/README.md)
  defines the service-native control objects and the remaining persisted
  provider-state records this package consumes
- [../../../handler](../../../handler/README.md) and specific handler packages
  depend on this package to make region API operations real against OpenStack
- [../allocation/vlan](../allocation/vlan/README.md) exists because this
  package needs a compensating local allocator for provider-network VLAN IDs
